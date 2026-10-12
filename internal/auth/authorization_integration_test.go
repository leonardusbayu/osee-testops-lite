package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"osee-testops-lite/internal/core"
)

const testOrigin = "http://127.0.0.1:8090"

func fixtureCSRF(s *Service, token string) string {
	h := hmac.New(sha256.New, s.csrfKey[:])
	h.Write([]byte("session-csrf:" + token))
	return hex.EncodeToString(h.Sum(nil))
}
func httpRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, testOrigin+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.10:43000"
	if method != http.MethodGet {
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return r
}
func perform(handler http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}
func gateway(t *testing.T, s *Service) http.Handler {
	t.Helper()
	h, err := NewHandler(s, testOrigin)
	if err != nil {
		t.Fatal("local gateway initialization failed")
	}
	return h
}
func loginState(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	w := perform(h, httpRequest(http.MethodGet, "/auth/login", ""))
	if w.Code != 200 {
		t.Fatalf("expected login page, got %d", w.Code)
	}
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("expected usable login CSRF form token")
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == loginStateCookieName {
			return cookie, match[1]
		}
	}
	t.Fatal("expected login state cookie")
	return nil, ""
}
func sessionCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge > 0 {
			return c
		}
	}
	t.Fatal("expected session cookie")
	return nil
}

// Dropping server-side role/MFA validation, trusting a client flag or losing CSRF breaks this endpoint.
func TestAdminRequiresMFA(t *testing.T) {
	store := testStore(t)
	s := NewService(store, nil)
	now := time.Now().UTC()
	stale := now.Add(-6 * time.Minute)
	future := now.Add(time.Minute)
	mutated := 0
	endpoint := s.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mutated++; w.WriteHeader(204) }))
	cases := []struct {
		role core.Role
		mfa  *time.Time
		want int
	}{
		{core.RoleParticipant, &now, 403}, {core.RolePartner, &now, 403}, {core.RoleAdmin, nil, 403},
		{core.RoleAdmin, &stale, 403}, {core.RoleAdmin, &future, 403}, {core.RoleAdmin, &now, 204}, {core.RoleOwner, &now, 204},
	}
	request := httpRequest(http.MethodPost, "/privileged", "role=owner&mfa=true")
	if w := perform(endpoint, request); w.Code != 401 {
		t.Errorf("expected unauthenticated denial, got %d", w.Code)
	}
	for _, tc := range cases {
		p := testPrincipal(t, store, tc.role)
		token, _ := testSession(t, store, p, now.Add(10*time.Minute), tc.mfa)
		currentService, currentEndpoint := s, endpoint
		if tc.want == 204 {
			genuine, session, _ := legacySyntheticStaff(t, tc.role)
			currentService = genuine.service
			token = session.Token
			currentEndpoint = currentService.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mutated++; w.WriteHeader(204) }))
		}
		request = httpRequest(http.MethodPost, "/privileged", "role=owner&mfa=true")
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		request.Header.Set("X-CSRF-Token", fixtureCSRF(currentService, token))
		request.Header.Set("X-Role", "owner")
		request.Header.Set("X-MFA", "true")
		if w := perform(currentEndpoint, request); w.Code != tc.want {
			t.Errorf("expected role/MFA gate %d for %s, got %d", tc.want, tc.role, w.Code)
		}
	}
	if mutated != 2 {
		t.Errorf("expected exactly two authorized mutations, got %d", mutated)
	}
}
func TestObjectOwnershipCannotBeForged(t *testing.T) {
	store := testStore(t)
	s := NewService(store, nil)
	a := testPrincipal(t, store, core.RoleParticipant)
	b := testPrincipal(t, store, core.RoleParticipant)
	token, _ := testSession(t, store, a, time.Now().Add(10*time.Minute), nil)
	for _, target := range []core.ID{a.ParticipantID, b.ParticipantID} {
		endpoint := s.RequireParticipant(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := s.AuthorizeParticipant(r.Context(), target); err != nil {
				w.WriteHeader(403)
				return
			}
			w.WriteHeader(204)
		}))
		request := httpRequest(http.MethodGet, "/private-result", "")
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		request.Header.Set("X-Participant-ID", string(target))
		request.Header.Set("X-Role", "owner")
		want := 403
		if target == a.ParticipantID {
			want = 204
		}
		if w := perform(endpoint, request); w.Code != want {
			t.Errorf("expected object gate %d, got %d", want, w.Code)
		}
	}
	if err := s.AuthorizeParticipant(context.Background(), a.ParticipantID); err == nil {
		t.Error("untrusted context accessed participant object")
	}
}
func TestCSRFAndSessionExpiry(t *testing.T) {
	genuine, session, p := legacySyntheticStaff(t, core.RoleAdmin)
	store, s := genuine.store, genuine.service
	now := time.Now().UTC()
	token := session.Token
	endpoint := s.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, valid := range []bool{false, true} {
		request := httpRequest(http.MethodPost, "/privileged", "")
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		want := 403
		if valid {
			request.Header.Set("X-CSRF-Token", fixtureCSRF(s, token))
			want = 204
		}
		if w := perform(endpoint, request); w.Code != want {
			t.Errorf("expected CSRF gate %d, got %d", want, w.Code)
		}
	}
	request := httpRequest(http.MethodPost, "/privileged", "")
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	request.Header.Set("X-CSRF-Token", fixtureCSRF(s, token))
	request.Header.Set("Origin", "https://foreign.example.invalid")
	if w := perform(endpoint, request); w.Code != 403 {
		t.Errorf("expected cross-origin denial, got %d", w.Code)
	}
	if err := s.revoke(context.Background(), token); err != nil {
		t.Fatal("fixture revoke failed")
	}
	if w := perform(endpoint, request); w.Code != 401 {
		t.Errorf("expected revoked session denial, got %d", w.Code)
	}
	expired, _ := testSession(t, store, p, now.Add(-time.Minute), nil)
	request = httpRequest(http.MethodGet, "/privileged", "")
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: expired})
	if w := perform(endpoint, request); w.Code != 401 {
		t.Errorf("expected server expiry denial, got %d", w.Code)
	}
}
func TestHTTPInviteLoginLogout(t *testing.T) {
	store := testStore(t)
	s := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	_, token := testInvite(t, store, p, false)
	h := gateway(t, s)
	state, csrf := loginState(t, h)
	values := url.Values{"token": {token}, "csrf": {csrf}, "role": {"owner"}, "mfa": {"true"}}
	request := httpRequest(http.MethodPost, "/auth/login", values.Encode())
	request.AddCookie(state)
	w := perform(h, request)
	if w.Code != 303 || w.Header().Get("Location") != "/auth/me" {
		t.Fatalf("expected successful sign-in redirect, got %d", w.Code)
	}
	cookie := sessionCookie(t, w)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Secure || cookie.Domain != "" {
		t.Error("local session cookie restrictions missing")
	}
	if strings.Contains(w.Body.String(), token) || strings.Contains(w.Header().Get("Location"), token) {
		t.Error("invitation credential leaked")
	}
	request = httpRequest(http.MethodGet, "/auth/me", "")
	request.AddCookie(cookie)
	w = perform(h, request)
	var body struct {
		Principal core.Principal
		CSRF      string
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Principal.UserID != p.UserID || body.Principal.ParticipantID != p.ParticipantID || body.Principal.Role != core.RoleParticipant || body.Principal.MFA || body.CSRF == "" {
		t.Fatal("expected own server-bound identity and logout proof")
	}
	if strings.Contains(w.Body.String(), cookie.Value) {
		t.Error("raw session credential leaked into body")
	}
	request = httpRequest(http.MethodPost, "/auth/logout", url.Values{"csrf": {body.CSRF}}.Encode())
	request.AddCookie(cookie)
	w = perform(h, request)
	if w.Code != 204 {
		t.Fatalf("expected logout, got %d", w.Code)
	}
	deleted := false
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge < 0 {
			deleted = true
		}
	}
	if !deleted {
		t.Error("logout did not delete cookie")
	}
	request = httpRequest(http.MethodGet, "/auth/me", "")
	request.AddCookie(cookie)
	if w := perform(h, request); w.Code != 401 {
		t.Errorf("expected revoked session after logout, got %d", w.Code)
	}
}
func TestLoginCSRFAndOriginFailClosed(t *testing.T) {
	store := testStore(t)
	s := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	_, token := testInvite(t, store, p, false)
	h := gateway(t, s)
	state, csrf := loginState(t, h)
	for _, tc := range []struct {
		origin, proof string
		cookie        bool
	}{
		{"https://foreign.example.invalid", csrf, true}, {testOrigin, "invalid", true}, {testOrigin, csrf, false}, {"", csrf, true},
	} {
		request := httpRequest(http.MethodPost, "/auth/login", url.Values{"token": {token}, "csrf": {tc.proof}}.Encode())
		request.Header.Set("Origin", tc.origin)
		if tc.cookie {
			request.AddCookie(state)
		}
		if w := perform(h, request); w.Code != 403 {
			t.Errorf("expected origin/state denial, got %d", w.Code)
		}
	}
	request := httpRequest(http.MethodGet, "/auth/login", "")
	request.Host = "foreign.example.invalid"
	if w := perform(h, request); w.Code != 403 {
		t.Errorf("expected host rebinding denial, got %d", w.Code)
	}
	request = httpRequest(http.MethodPost, "/auth/login", url.Values{"token": {token}, "csrf": {csrf}}.Encode())
	request.AddCookie(state)
	if w := perform(h, request); w.Code != 303 {
		t.Errorf("failed CSRF attempts consumed a valid invitation, got %d", w.Code)
	}
}
func TestLoginRateGateIgnoresForwardingHeaders(t *testing.T) {
	store := testStore(t)
	s := NewService(store, nil)
	h := gateway(t, s)
	state, csrf := loginState(t, h)
	for i := 0; i < 11; i++ {
		request := httpRequest(http.MethodPost, "/auth/login", url.Values{"token": {"STUDENT-1234"}, "csrf": {csrf}}.Encode())
		request.AddCookie(state)
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1))
		request.Header.Set("Forwarded", fmt.Sprintf("for=203.0.113.%d", i+1))
		want := 401
		if i == 10 {
			want = 429
		}
		if w := perform(h, request); w.Code != want {
			t.Errorf("expected bounded login attempt status %d, got %d", want, w.Code)
		}
	}
}
func TestLoginBodyBoundAndParseFailures(t *testing.T) {
	store := testStore(t)
	h := gateway(t, NewService(store, nil))
	state, csrf := loginState(t, h)
	request := httpRequest(http.MethodPost, "/auth/login", url.Values{"token": {strings.Repeat("x", 4096)}, "csrf": {csrf}}.Encode())
	request.AddCookie(state)
	if w := perform(h, request); w.Code != 413 {
		t.Errorf("expected oversized-body rejection, got %d", w.Code)
	}
	request = httpRequest(http.MethodPost, "/auth/login", "token=%ZZ&csrf="+csrf)
	request.AddCookie(state)
	if w := perform(h, request); w.Code != 400 {
		t.Errorf("expected malformed form rejection, got %d", w.Code)
	}
}
func TestLoginStateExpiresAndCannotBeForged(t *testing.T) {
	store := testStore(t)
	s := NewService(store, nil)
	h := gateway(t, s)
	state, csrf := loginState(t, h)
	fake := *state
	fake.Value = csrf[:len(csrf)-1] + "x"
	request := httpRequest(http.MethodPost, "/auth/login", url.Values{"token": {"STUDENT-1234"}, "csrf": {fake.Value}}.Encode())
	request.AddCookie(&fake)
	if w := perform(h, request); w.Code != 403 {
		t.Errorf("expected forged state denial, got %d", w.Code)
	}
	nonce, _ := testSecret(t)
	payload := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10) + "." + nonce
	mac := hmac.New(sha256.New, s.csrfKey[:])
	mac.Write([]byte("login-state:" + payload))
	expired := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	fake.Value = expired
	request = httpRequest(http.MethodPost, "/auth/login", url.Values{"token": {"STUDENT-1234"}, "csrf": {expired}}.Encode())
	request.AddCookie(&fake)
	if w := perform(h, request); w.Code != 403 {
		t.Errorf("expected server login-state expiry denial, got %d", w.Code)
	}
}
func TestHandlerRejectsNonlocalAndAmbiguousOrigins(t *testing.T) {
	s := NewService(testStore(t), nil)
	for _, origin := range []string{"https://production.example.invalid", "http://127.0.0.1:8090/path", "http://127.0.0.1:8090?x=1", "http://user@127.0.0.1:8090", "http://127.0.0.1:8090#fragment"} {
		if _, err := NewHandler(s, origin); err == nil {
			t.Error("nonlocal or ambiguous origin accepted")
		}
	}
}
func TestHTTPSLoopbackSetsSecureCookie(t *testing.T) {
	s := NewService(testStore(t), nil)
	h, err := NewHandler(s, "https://127.0.0.1:8090")
	if err != nil {
		t.Fatal("expected explicit HTTPS loopback support")
	}
	request := httptest.NewRequest(http.MethodGet, "https://127.0.0.1:8090/auth/login", nil)
	w := perform(h, request)
	if w.Code != 200 {
		t.Errorf("expected secure login page, got %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("expected secure restricted HTTPS state cookie")
	}
}
func TestRateLimiterBoundsStorageAndRecovers(t *testing.T) {
	limiter := newLoginLimiter(2)
	now := time.Now()
	if !limiter.allow("192.0.2.1", now) || !limiter.allow("192.0.2.2", now) {
		t.Fatal("expected initial rate slots")
	}
	if limiter.allow("192.0.2.3", now) {
		t.Error("capacity pressure must fail closed")
	}
	if !limiter.allow("192.0.2.3", now.Add(61*time.Second)) {
		t.Error("expired slots must be reclaimed")
	}
}
