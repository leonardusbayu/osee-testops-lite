package auth

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"osee-testops-lite/internal/core"
	"strings"
	"testing"
	"time"
)

var participantTestPage = template.Must(template.New("login").Parse(`<h1>Styled participant sign-in</h1>{{.Error}}<form method="post" action="/auth/login"><input type="hidden" name="csrf" value="{{.CSRF}}"></form>{{if .Demo}}<form action="/auth/demo"></form>{{end}}`))

func TestParticipantNativeFormOriginPolicyDoesNotSuppressOrigin(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	styled, err := NewParticipantHandler(svc, "http://127.0.0.1:8090", participantTestPage, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := perform(styled, httpRequest("GET", "/auth/login", ""))
	if response.Header().Get("Referrer-Policy") != "same-origin" {
		t.Error("native browser form Origin is suppressed by document no-referrer policy")
	}
	plain, err := NewHandler(svc, "http://127.0.0.1:8090")
	if err != nil {
		t.Fatal(err)
	}
	if response = perform(plain, httpRequest("GET", "/auth/login", "")); response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("default API gateway privacy policy changed implicitly")
	}
}

func TestParticipantDemoValidStateUsesRealSessionAndLanding(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	_, code := testInvite(t, store, p, false)
	calls := 0
	handler, err := NewParticipantHandler(svc, "http://127.0.0.1:8090", participantTestPage, func(context.Context) (string, error) { calls++; return code, nil })
	if err != nil {
		t.Fatal(err)
	}
	page := perform(handler, httpRequest("GET", "/auth/login", ""))
	if !strings.Contains(page.Body.String(), "Styled participant sign-in") || !strings.Contains(page.Header().Get("Content-Security-Policy"), "style-src 'self'") {
		t.Error("styled local gateway/CSP not composed")
	}
	state, csrf := loginState(t, handler)
	req := httpRequest("POST", "/auth/demo", url.Values{"csrf": {csrf}}.Encode())
	req.AddCookie(state)
	response := perform(handler, req)
	if response.Code != 303 || response.Header().Get("Location") != "/portal" || calls != 1 {
		t.Fatal("expected real demo session and portal landing")
	}
	var session *http.Cookie
	for _, c := range response.Result().Cookies() {
		if c.Name == SessionCookieName {
			session = c
		}
	}
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatal("missing protected session cookie")
	}
	req = httpRequest("GET", "/auth/me", "")
	req.AddCookie(session)
	if response = perform(handler, req); response.Code != 200 || !strings.Contains(response.Body.String(), string(p.ParticipantID)) {
		t.Error("demo lost current own identity")
	}
	csrf, err = svc.RequestCSRF(req)
	if err != nil || csrf == "" {
		t.Fatal("participant view needs validated session CSRF")
	}
	req = httpRequest("POST", "/auth/signout", url.Values{"csrf": {csrf}}.Encode())
	req.AddCookie(session)
	if response = perform(handler, req); response.Code != 303 || response.Header().Get("Location") != "/auth/login?signedout=1" {
		t.Error("native signout did not revoke and return to sign-in")
	}
	req = httpRequest("GET", "/auth/me", "")
	req.AddCookie(session)
	if response = perform(handler, req); response.Code != 401 {
		t.Error("signout failed to revoke session")
	}
}
func TestParticipantDemoGuardsRunBeforeCallback(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	calls := 0
	handler, err := NewParticipantHandler(svc, "http://127.0.0.1:8090", participantTestPage, func(context.Context) (string, error) { calls++; return "", ErrUnavailable })
	if err != nil {
		t.Fatal(err)
	}
	state, csrf := loginState(t, handler)
	for _, problem := range []string{"foreign-origin", "missing-state", "duplicate-state", "invalid-csrf", "duplicate-csrf", "large-body", "duplicate-session", "unexpected-token"} {
		form := url.Values{"csrf": {csrf}}
		if problem == "invalid-csrf" {
			form.Set("csrf", "invalid")
		}
		if problem == "duplicate-csrf" {
			form["csrf"] = []string{csrf, csrf}
		}
		if problem == "large-body" {
			form.Set("extra", strings.Repeat("x", 3000))
		}
		if problem == "unexpected-token" {
			form.Set("token", "anything")
		}
		req := httpRequest("POST", "/auth/demo", form.Encode())
		if problem != "missing-state" {
			req.AddCookie(state)
		}
		if problem == "duplicate-state" {
			req.AddCookie(state)
		}
		if problem == "foreign-origin" {
			req.Header.Set("Origin", "https://example.invalid")
		}
		if problem == "duplicate-session" {
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "ambiguous"})
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "ambiguous"})
		}
		response := perform(handler, req)
		if response.Code != 403 && response.Code != 400 && response.Code != 413 {
			t.Errorf("expected bounded denial for %s, got %d", problem, response.Code)
		}
		if calls != 0 {
			t.Fatalf("unsafe %s request performed demo side effect", problem)
		}
	}
}
func TestParticipantDemoDisabledAndRateBounded(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	handler, err := NewParticipantHandler(svc, "http://127.0.0.1:8090", participantTestPage, nil)
	if err != nil {
		t.Fatal(err)
	}
	if page := perform(handler, httpRequest("GET", "/auth/login", "")); strings.Contains(page.Body.String(), `action="/auth/demo"`) {
		t.Error("disabled demo shown")
	}
	state, csrf := loginState(t, handler)
	req := httpRequest("POST", "/auth/demo", url.Values{"csrf": {csrf}}.Encode())
	req.AddCookie(state)
	if response := perform(handler, req); response.Code != 404 {
		t.Error("demo route enabled without callback")
	}
	calls := 0
	handler, err = NewParticipantHandler(svc, "http://127.0.0.1:8090", participantTestPage, func(context.Context) (string, error) { calls++; return "", ErrUnavailable })
	if err != nil {
		t.Fatal(err)
	}
	state, csrf = loginState(t, handler)
	for i := 0; i < 11; i++ {
		req = httpRequest("POST", "/auth/demo", url.Values{"csrf": {csrf}}.Encode())
		req.AddCookie(state)
		response := perform(handler, req)
		if i == 10 && (response.Code != 429 || response.Header().Get("Retry-After") == "") {
			t.Error("demo failed rate bound")
		}
	}
	if calls != 10 {
		t.Errorf("expected exactly ten permitted callbacks, got %d", calls)
	}
}
func TestParticipantStyledErrorsDoNotEchoSecretAndCSRFRequiresCurrentSession(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	handler, err := NewParticipantHandler(svc, "http://127.0.0.1:8090", participantTestPage, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, csrf := loginState(t, handler)
	req := httpRequest("POST", "/auth/login", url.Values{"csrf": {csrf}, "token": {"never-echo-this-code"}}.Encode())
	req.AddCookie(state)
	response := perform(handler, req)
	if response.Code != 401 || !strings.Contains(response.Body.String(), "Styled participant sign-in") || !strings.Contains(response.Body.String(), "invitation") || strings.Contains(response.Body.String(), "never-echo-this-code") {
		t.Error("invalid credential should remain on safe styled form with inline explanation")
	}
	p := testPrincipal(t, store, core.RoleParticipant)
	token, _ := testSession(t, store, p, time.Now().UTC().Add(10*time.Minute), nil)
	req = httpRequest("GET", "/portal", "")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	csrf, err = svc.RequestCSRF(req)
	if err != nil || csrf == "" {
		t.Fatal("valid current session has no form proof")
	}
	if err = svc.revoke(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if value, err := svc.RequestCSRF(req); err != ErrUnauthenticated || value != "" {
		t.Error("revoked request obtained CSRF proof")
	}
}
