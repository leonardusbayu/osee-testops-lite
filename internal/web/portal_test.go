package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/demo"
	"strings"
	"testing"
	"time"
)

func portalStore(t *testing.T) *db.Store {
	t.Helper()
	base := localTestStore(t)
	id, _ := core.NewID()
	schema := "test_portal_" + strings.ReplaceAll(string(id), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := base.Pool.Exec(context.Background(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	cfg := base.Pool.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := base.Pool.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("exact portal fixture schema cleanup failed")
		}
	})
	s := &db.Store{Pool: pool}
	if err = s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}
func portalIdentity(t *testing.T, s *db.Store, role string, email string) (core.ID, core.ID, *http.Cookie) {
	t.Helper()
	principal, _ := core.NewID()
	participant, _ := core.NewID()
	session, _ := core.NewID()
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes)
	hash := sha256.Sum256([]byte(token))
	ctx := context.Background()
	if role == "participant" {
		if _, err := s.Pool.Exec(ctx, "insert into participants(id,email) values($1,$2)", participant, email); err != nil {
			t.Fatal(err)
		}
	}
	var binding any
	if role == "participant" {
		binding = participant
	}
	if _, err := s.Pool.Exec(ctx, "insert into auth_principals(id,role,participant_id) values($1,$2,$3)", principal, role, binding); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, "insert into auth_sessions(id,principal_id,token_hash,expires_at) values($1,$2,$3,$4)", session, principal, hash[:], time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	return principal, participant, &http.Cookie{Name: auth.SessionCookieName, Value: token}
}
func portalRead(h http.Handler, path string, cookie *http.Cookie, hx bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", localOrigin+path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if hx {
		req.Header.Set("HX-Request", "true")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}
func TestParticipantWelcomeAndAssetsAreUsableAndSelfHosted(t *testing.T) {
	s := portalStore(t)
	h, err := LocalDemoRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	w := portalRead(h, "/", nil, false)
	for _, text := range []string{"Your test journey", `href="/auth/login"`, `href="/assets/app.css"`, `id="main-content"`, "Explore demo", "Synthetic demo"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Errorf("welcome missing usable %s", text)
		}
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "style-src 'self'") || strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
		t.Error("welcome CSS not backed by strict local CSP")
	}
	for _, path := range []string{"/assets/app.css", "/assets/app.js", "/assets/htmx.min.js"} {
		w = portalRead(h, path, nil, false)
		if w.Code != 200 || w.Body.Len() < 100 {
			t.Errorf("actual self-hosted asset unavailable: %s", path)
		}
	}
}
func TestParticipantPortalRedirectsMissingSessionAndDeniesOtherRoles(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	w := portalRead(h, "/portal", nil, false)
	if w.Code != 303 || w.Header().Get("Location") != "/auth/login?expired=1" {
		t.Error("native unauthenticated journey lost styled sign-in")
	}
	w = portalRead(h, "/portal", nil, true)
	if w.Code != 401 || w.Header().Get("HX-Redirect") != "/auth/login?expired=1" {
		t.Error("expired fragment must redirect, never swap private/login markup")
	}
	_, _, cookie := portalIdentity(t, s, "admin", "")
	w = portalRead(h, "/portal", cookie, false)
	if w.Code != 403 {
		t.Error("staff session entered participant portal")
	}
}
func TestParticipantPortalRendersOnlyOwnCurrentDatabaseRecords(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, own, cookie := portalIdentity(t, s, "participant", "own@example.invalid")
	_, foreign, _ := portalIdentity(t, s, "participant", "foreign@example.invalid")
	ownReg, _ := core.NewID()
	foreignReg, _ := core.NewID()
	for _, row := range []struct{ id, participant core.ID }{{ownReg, own}, {foreignReg, foreign}} {
		if _, err = s.Pool.Exec(context.Background(), "insert into registrations(id,participant_id) values($1,$2)", row.id, row.participant); err != nil {
			t.Fatal(err)
		}
	}
	w := portalRead(h, "/portal?view=attempts", cookie, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), string(ownReg)) || strings.Contains(w.Body.String(), string(foreignReg)) || strings.Contains(w.Body.String(), "foreign@example.invalid") {
		t.Error("portal did not scope actual data to own identity")
	}
	for _, path := range []string{"/portal?participant_id=" + string(foreign), "/portal?view=results&participant_id=" + string(foreign)} {
		w = portalRead(h, path, cookie, true)
		if w.Code != 403 || strings.Contains(w.Body.String(), string(foreignReg)) {
			t.Error("client identity selector was not denied")
		}
	}
	if _, err = s.Pool.Exec(context.Background(), "update registrations set registration_state='CANCELLED' where id=$1", ownReg); err != nil {
		t.Fatal(err)
	}
	w = portalRead(h, "/portal?view=attempts", cookie, true)
	if !strings.Contains(w.Body.String(), "Cancelled") {
		t.Error("fresh own status did not reflect committed DB change")
	}
}
func TestParticipantPortalEscapesContactAndNeverPersistsPrivateHistory(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, _, cookie := portalIdentity(t, s, "participant", "<script>alert(1)</script>@example.invalid")
	w := portalRead(h, "/portal", cookie, false)
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>alert(1)</script>") || !strings.Contains(w.Body.String(), "&lt;script&gt;") {
		t.Error("profile contact not HTML escaped")
	}
	for _, text := range []string{`hx-history="false"`, `id="portal-panel"`, `action="/auth/signout"`, `name="csrf"`, `aria-label="Participant navigation"`} {
		if !strings.Contains(w.Body.String(), text) {
			t.Errorf("portal lacks privacy/native semantics: %s", text)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Vary"), "HX-Request") {
		t.Error("private fragment cache boundary missing")
	}
}
func TestParticipantPortalViewsHaveNativeAndFragmentFallback(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, _, cookie := portalIdentity(t, s, "participant", "view@example.invalid")
	for view, title := range map[string]string{"overview": "Your overview", "attempts": "My attempts", "schedule": "Your schedule", "results": "Your results", "help": "Help & next steps"} {
		path := "/portal?view=" + view
		full := portalRead(h, path, cookie, false)
		partial := portalRead(h, path, cookie, true)
		if full.Code != 200 || !strings.Contains(full.Body.String(), "<!doctype html>") || !strings.Contains(html.UnescapeString(full.Body.String()), title) {
			t.Errorf("native %s view broken", view)
		}
		if partial.Code != 200 || strings.Contains(partial.Body.String(), "<!doctype html>") || !strings.Contains(html.UnescapeString(partial.Body.String()), title) {
			t.Errorf("HTMX %s fragment broken", view)
		}
	}
	if w := portalRead(h, "/portal?view=unknown", cookie, false); w.Code != 400 || strings.Contains(w.Body.String(), "unknown") {
		t.Error("unknown view not safely rejected")
	}
	if w := portalRead(h, "/portal?view=results&view=overview", cookie, false); w.Code != 400 {
		t.Error("ambiguous view accepted")
	}
}
func TestParticipantScheduleShowsActualWIBAndHostReadyGate(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, participant, cookie := portalIdentity(t, s, "participant", "schedule@example.invalid")
	session, _ := core.NewID()
	reg, _ := core.NewID()
	ctx := context.Background()
	if _, err = s.Pool.Exec(ctx, "insert into sessions(id,starts_at,cutoff_at,capacity) values($1,'2030-01-02T03:00:00Z','2030-01-02T02:00:00Z',1)", session); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(ctx, "insert into registrations(id,participant_id,session_id,registration_state) values($1,$2,$3,'CONFIRMED')", reg, participant, session); err != nil {
		t.Fatal(err)
	}
	w := portalRead(h, "/portal?view=schedule", cookie, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "10:00 WIB") || !strings.Contains(w.Body.String(), "Host not ready") || strings.Contains(w.Body.String(), "Check in now") {
		t.Error("schedule lost actual timezone/readiness boundary")
	}
	if _, err = s.Pool.Exec(ctx, "update sessions set host_ready=true where id=$1", session); err != nil {
		t.Fatal(err)
	}
	w = portalRead(h, "/portal?view=schedule", cookie, true)
	if !strings.Contains(w.Body.String(), "Host ready") || strings.Contains(w.Body.String(), "Check in now") {
		t.Error("readiness changed but unimplemented action was fabricated")
	}
}
func TestParticipantDemoUIIsExplicitAndDoesNotEnableInDefaultRouter(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if w := portalRead(h, "/auth/login", nil, false); strings.Contains(w.Body.String(), `action="/auth/demo"`) {
		t.Error("demo enabled implicitly")
	}
	if err = demo.Seed(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	h, err = LocalDemoRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	w := portalRead(h, "/auth/login", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Open demo portal") || !strings.Contains(w.Body.String(), "Synthetic demo") {
		t.Fatal("approved one-click flow unavailable")
	}
	var state *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "osee_completion_r1_login_state" {
			state = c
		}
	}
	if state == nil {
		t.Fatal("login state missing")
	}
	req := httptest.NewRequest("POST", localOrigin+"/auth/demo", strings.NewReader(url.Values{"csrf": {state.Value}}.Encode()))
	req.Header.Set("Origin", localOrigin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(state)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 303 || w.Header().Get("Location") != "/portal" {
		t.Fatal("demo did not create real session")
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("real cookie missing")
	}
	w = portalRead(h, "/portal", sessionCookie, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Demo participant") || !strings.Contains(w.Body.String(), "Synthetic demo") || !strings.Contains(w.Body.String(), "Confirmed") {
		t.Error("demo portal missing owned persisted dataset and explicit label")
	}
}
func TestParticipantPortalNativeSignoutHasUsableOriginPolicy(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, _, cookie := portalIdentity(t, s, "participant", "native@example.invalid")
	w := portalRead(h, "/portal", cookie, false)
	if w.Code != 200 || w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Error("native signout form needs non-opaque same-origin policy while forbidding off-origin referrers")
	}
}

func TestParticipantHealthProbeHostDoesNotOpenPrivateRoutes(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	for path, expected := range map[string]int{"/health/ready": 200, "/health/live": 200, "/": 403, "/auth/login": 403, "/portal": 403, "/assets/app.css": 403} {
		req := httptest.NewRequest("GET", "http://localhost"+path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != expected {
			t.Errorf("probe Host path %s: expected %d, got %d", path, expected, w.Code)
		}
	}
}

func TestParticipantUIOriginAndCurrentAuthorityRemainEnforced(t *testing.T) {
	s := portalStore(t)
	h, err := LocalRouter(s, localOrigin)
	if err != nil {
		t.Fatal(err)
	}
	principal, _, cookie := portalIdentity(t, s, "participant", "authority@example.invalid")
	req := httptest.NewRequest("GET", "http://example.invalid/portal", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Error("foreign Host reached portal")
	}
	if _, err = s.Pool.Exec(context.Background(), "update auth_principals set enabled=false where id=$1", principal); err != nil {
		t.Fatal(err)
	}
	w = portalRead(h, "/portal", cookie, true)
	if w.Code != 401 || strings.Contains(w.Body.String(), "authority@example.invalid") {
		t.Error("disabled current authority retained private HTML")
	}
}
