package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"osee-testops-lite/internal/core"
)

type staffLoginTestFixture struct {
	staffIdentityTestFixture
	username, password string
	view               StaffEnrollmentView
	session            StaffSession
	at                 time.Time
}

func staffLoginFixture(t *testing.T) staffLoginTestFixture {
	t.Helper()
	f := staffIdentityFixture(t)
	at := time.Now().UTC()
	f.identity.now = func() time.Time { return at }
	username, password := "owner.login", staffCryptoPassword(t)
	pending := staffBeginOwner(t, f, username, password)
	view, err := f.identity.EnrollmentView(context.Background(), pending.Token)
	if err != nil {
		t.Fatal("synthetic new factor unavailable")
	}
	result, err := f.identity.ConfirmEnrollment(context.Background(), pending.Token, staffSyntheticCode(t, view, at))
	if err != nil {
		t.Fatal("synthetic genuine enrollment failed")
	}
	at = at.Add(30 * time.Second)
	return staffLoginTestFixture{f, username, password, view, result.Session, at}
}

func staffLoginContext(t *testing.T, f staffIdentityTestFixture, session StaffSession) context.Context {
	t.Helper()
	var result context.Context
	h := f.service.require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { result = r.Context() }), "session")
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8091/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session.Token})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || result == nil {
		t.Fatal("real middleware did not issue the opaque fixture proof")
	}
	return result
}

func TestStaffLoginPasswordThenTOTP(t *testing.T) {
	f := staffLoginFixture(t)
	ctx := context.Background()
	before := staffEnrollmentCounts(t, f.staffIdentityTestFixture)
	if pending, err := f.identity.BeginLogin(ctx, f.username, staffCryptoPassword(t), "198.51.100.7"); !errors.Is(err, ErrUnauthenticated) || pending.Token != "" {
		t.Fatal("wrong password started staff login")
	}
	pending, err := f.identity.BeginLogin(ctx, strings.ToUpper(f.username), f.password, "198.51.100.7")
	if err != nil || pending.Token == "" || !pending.ExpiresAt.Equal(f.at.Add(5*time.Minute)) {
		t.Fatal("correct password did not issue a five-minute challenge")
	}
	if staffEnrollmentCounts(t, f.staffIdentityTestFixture) != before {
		t.Fatal("password-only challenge granted session authority")
	}
	if _, err = f.identity.ConfirmLogin(ctx, pending.Token, staffSyntheticCode(t, f.view, f.at.Add(-30*time.Second)), ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("enrollment TOTP counter was reusable at login")
	}
	result, err := f.identity.ConfirmLogin(ctx, pending.Token, staffSyntheticCode(t, f.view, f.at), f.session.Token)
	if err != nil || result.Token == "" || result.Token == f.session.Token || !result.ExpiresAt.Equal(f.at.Add(30*time.Minute)) {
		t.Fatal("password and real TOTP did not produce a rotated thirty-minute staff session")
	}
	p, err := f.service.Resolve(ctx, staffCookieRequest(SessionCookieName, result.Token))
	if err != nil || p.Role != core.RoleOwner || !p.MFA {
		t.Fatal("genuine staff login did not resolve current authority")
	}
	if _, err = f.service.Resolve(ctx, staffCookieRequest(SessionCookieName, f.session.Token)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("previous same-principal cookie survived login rotation")
	}
	if _, err = f.identity.ConfirmLogin(ctx, pending.Token, staffSyntheticCode(t, f.view, f.at), ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("consumed staff challenge replay succeeded")
	}
	f.identity.now = func() time.Time { return f.at.Add(30 * time.Second) }
	second, err := f.identity.BeginLogin(ctx, f.username, f.password, "198.51.100.8")
	if err != nil {
		t.Fatal("second valid login challenge failed")
	}
	if _, err = f.identity.ConfirmLogin(ctx, second.Token, staffSyntheticCode(t, f.view, f.at.Add(30*time.Second)), ""); err != nil {
		t.Fatal("new independent TOTP counter was rejected")
	}
	if p, err = f.service.Resolve(ctx, staffCookieRequest(SessionCookieName, result.Token)); err != nil || !p.MFA {
		t.Fatal("later accepted TOTP invalidated an older still-current attestation")
	}
}

func staffCookieRequest(name, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8091/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: name, Value: token})
	return r
}

func TestStaffLoginConcurrentCounterSingleSession(t *testing.T) {
	f := staffLoginFixture(t)
	ctx := context.Background()
	first, err := f.identity.BeginLogin(ctx, f.username, f.password, "198.51.100.11")
	if err != nil {
		t.Fatal("first real login challenge failed")
	}
	second, err := f.identity.BeginLogin(ctx, f.username, f.password, "198.51.100.12")
	if err != nil {
		t.Fatal("second real login challenge failed")
	}
	code := staffSyntheticCode(t, f.view, f.at)
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, pending := range []StaffChallenge{first, second} {
		workers.Add(1)
		go func(p StaffChallenge) {
			defer workers.Done()
			<-start
			session, err := f.identity.ConfirmLogin(ctx, p.Token, code, "")
			if err == nil && session.Token == "" {
				err = ErrUnavailable
			}
			results <- err
		}(pending)
	}
	close(start)
	workers.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("concurrent confirmation failed outside the expected authority rejection")
		}
	}
	var consumed, sessions int
	if err = f.store.Pool.QueryRow(ctx, `select (select count(*) from auth_staff_challenges where kind='login' and consumed_at is not null),(select count(*) from auth_sessions)`).Scan(&consumed, &sessions); err != nil {
		t.Fatal("concurrent authority census failed")
	}
	if successes != 1 || consumed != 1 || sessions != 2 {
		t.Fatal("one factor counter created more than one new session")
	}
}

func TestStaffStepUpRotation(t *testing.T) {
	f := staffLoginFixture(t)
	ctx := context.Background()
	f.identity.now = func() time.Time { return f.at.Add(6 * time.Minute) }
	p, err := f.service.Resolve(ctx, staffCookieRequest(SessionCookieName, f.session.Token))
	if err != nil || p.MFA {
		t.Fatal("stale MFA must retain only its unenriched session identity")
	}
	proof := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	if _, err = f.identity.BeginStepUp(ctx, f.password); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("claimed or absent context began step-up")
	}
	pending, err := f.identity.BeginStepUp(proof, f.password)
	if err != nil || pending.Token == "" {
		t.Fatal("real stale session and password did not begin step-up")
	}
	if _, err = f.identity.ConfirmLogin(ctx, pending.Token, staffSyntheticCode(t, f.view, f.at.Add(6*time.Minute)), ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("step-up challenge was consumable by the login protocol")
	}
	fresh, err := f.identity.ConfirmStepUp(proof, pending.Token, staffSyntheticCode(t, f.view, f.at.Add(6*time.Minute)))
	if err != nil || fresh.Token == "" || fresh.Token == f.session.Token {
		t.Fatal("real step-up did not rotate session identity")
	}
	if _, err = f.service.Resolve(ctx, staffCookieRequest(SessionCookieName, f.session.Token)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("old token survived successful step-up")
	}
	freshProof := staffLoginContext(t, f.staffIdentityTestFixture, fresh)
	p, err = f.service.CurrentPrincipal(freshProof)
	if err != nil || !p.MFA || p.Role != core.RoleOwner {
		t.Fatal("current principal did not use the shared genuine proof")
	}
	other := NewService(f.store, nil)
	if _, err = other.CurrentPrincipal(freshProof); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("opaque proof crossed service instances")
	}
}
