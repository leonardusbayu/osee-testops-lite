package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"osee-testops-lite/internal/core"
)

// Actual socket, CookieJar and response boundaries; no mocks or host-published port.
func TestHTTPNetworkSignInOwnIdentityAndLogout(t *testing.T) {
	store := testStore(t)
	s := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	_, code := testInvite(t, store, p, false)
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	handler, err := NewHandler(s, origin)
	if err != nil {
		t.Fatal("loopback transport setup failed")
	}
	server.Config.Handler = handler
	server.Start()
	t.Cleanup(server.Close)
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(origin + "/auth/login")
	if err != nil {
		t.Fatal("HTTP login page unavailable")
	}
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(raw)
	if response.StatusCode != 200 || len(match) != 2 {
		t.Fatal("expected network login state")
	}
	req, _ := http.NewRequest(http.MethodPost, origin+"/auth/login", strings.NewReader(url.Values{"token": {code}, "csrf": {string(match[1])}}.Encode()))
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = client.Do(req)
	if err != nil {
		t.Fatal("HTTP sign-in failed")
	}
	response.Body.Close()
	if response.StatusCode != 303 {
		t.Fatalf("expected network sign-in redirect, got %d", response.StatusCode)
	}
	response, err = client.Get(origin + "/auth/me")
	if err != nil {
		t.Fatal("HTTP own identity failed")
	}
	var identity struct {
		Principal core.Principal
		CSRF      string
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&identity)
	response.Body.Close()
	if response.StatusCode != 200 || err != nil || identity.Principal.UserID != p.UserID || identity.Principal.ParticipantID != p.ParticipantID || identity.CSRF == "" {
		t.Fatal("network response lost intended identity")
	}
	req, _ = http.NewRequest(http.MethodPost, origin+"/auth/logout", strings.NewReader(url.Values{"csrf": {identity.CSRF}}.Encode()))
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err = client.Do(req)
	if err != nil {
		t.Fatal("HTTP logout failed")
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatalf("expected network logout, got %d", response.StatusCode)
	}
	response, err = client.Get(origin + "/auth/me")
	if err != nil {
		t.Fatal("HTTP post-logout lookup failed")
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Error("network cookie survived logout")
	}
}
func TestStaffProofCannotRetainChangedRoleOrRevocation(t *testing.T) {
	store := testStore(t)
	queue := &testInviteQueue{}
	s := NewService(store, queue)
	owner := testPrincipal(t, store, core.RoleOwner)
	participant := testPrincipal(t, store, core.RoleParticipant)
	now := time.Now().UTC()
	token, hash := testSession(t, store, owner, now.Add(10*time.Minute), &now)
	var digest [32]byte
	copy(digest[:], hash)
	ctx := context.WithValue(context.Background(), proofContextKey{}, sessionProof{service: s, hash: digest})
	testExec(t, store, "update auth_principals set role='partner',partner_id=$2 where id=$1", owner.UserID, testID(t))
	if _, err := s.IssueInvite(ctx, participant.UserID); err != ErrForbidden {
		t.Error("old context retained privileged role")
	}
	testExec(t, store, "update auth_principals set role='owner',partner_id=null where id=$1", owner.UserID)
	if err := s.revoke(context.Background(), token); err != nil {
		t.Fatal("synthetic revoke failed")
	}
	if _, err := s.IssueInvite(ctx, participant.UserID); err != ErrUnauthenticated {
		t.Error("old context retained revoked session authority")
	}
	var count int
	if err := store.Pool.QueryRow(context.Background(), "select count(*) from auth_invites where principal_id=$1", participant.UserID).Scan(&count); err != nil || count != 0 {
		t.Error("changed/revoked authority created an invite")
	}
}
func TestLoginRejectsDuplicateStateAndDuplicateFormTokens(t *testing.T) {
	store := testStore(t)
	s := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	invite, code := testInvite(t, store, p, false)
	handler := gateway(t, s)
	state, csrf := loginState(t, handler)
	request := httpRequest(http.MethodPost, "/auth/login", url.Values{"csrf": {csrf}, "token": {code}}.Encode())
	request.AddCookie(state)
	request.AddCookie(state)
	if w := perform(handler, request); w.Code != 403 {
		t.Errorf("expected ambiguous state rejection, got %d", w.Code)
	}
	request = httpRequest(http.MethodPost, "/auth/login", url.Values{"csrf": {csrf}, "token": {code, code}}.Encode())
	request.AddCookie(state)
	if w := perform(handler, request); w.Code != 401 {
		t.Errorf("expected ambiguous token rejection, got %d", w.Code)
	}
	var unused bool
	if err := store.Pool.QueryRow(context.Background(), "select consumed_at is null from auth_invites where id=$1", invite).Scan(&unused); err != nil || !unused {
		t.Error("malformed request consumed valid invite")
	}
	request = httpRequest(http.MethodPost, "/auth/login", url.Values{"csrf": {csrf}, "token": {code}}.Encode())
	request.AddCookie(state)
	if w := perform(handler, request); w.Code != 303 {
		t.Errorf("expected valid login after malformed request, got %d", w.Code)
	}
	codeHash := sha256.Sum256([]byte(code))
	var persisted []byte
	if err := store.Pool.QueryRow(context.Background(), "select token_hash from auth_invites where id=$1", invite).Scan(&persisted); err != nil || string(persisted) != string(codeHash[:]) {
		t.Error("invite storage lost one-way binding")
	}
}
