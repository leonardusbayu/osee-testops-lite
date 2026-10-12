package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/internal/core"
)

func TestStaffTimestampOnlyWitnessRejected(t *testing.T) {
	for _, configured := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing_key", true: "genuine_service_no_credential"}[configured], func(t *testing.T) {
			f := staffIdentityFixture(t)
			svc := f.service
			if !configured {
				svc = NewService(f.store, nil)
			}
			principal := testPrincipal(t, f.store, core.RoleOwner)
			principal.MFA = true
			now := time.Now().UTC()
			token, hash := testSession(t, f.store, principal, now.Add(20*time.Minute), &now)
			committedEffects := 0
			read := svc.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
			mutation := svc.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := svc.WithStaffTx(r.Context(), principal, func(tx pgx.Tx, current core.Principal) error {
					_, err := tx.Exec(r.Context(), "insert into outbox(id,object_id,event_kind) values($1,$2,'synthetic-fake-authority')", testID(t), current.UserID)
					return err
				})
				if err != nil {
					errorResponse(w, err)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			r := staffCookieRequest(SessionCookieName, token)
			w := httptest.NewRecorder()
			read.ServeHTTP(w, r)
			readStatus := w.Code
			r = httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8091/synthetic/write", strings.NewReader(""))
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			r.Header.Set("Origin", "http://127.0.0.1:8091")
			r.Header.Set("X-CSRF-Token", svc.sessionCSRF(token))
			w = httptest.NewRecorder()
			mutation.ServeHTTP(w, r)
			mutationStatus := w.Code
			if err := f.store.Pool.QueryRow(context.Background(), "select count(*) from outbox where event_kind='synthetic-fake-authority'").Scan(&committedEffects); err != nil {
				t.Fatal("synthetic effect readback failed")
			}
			if readStatus != http.StatusForbidden || mutationStatus != http.StatusForbidden || committedEffects != 0 {
				t.Fatal("timestamp-only witness granted authority")
			}
			var digest [32]byte
			copy(digest[:], hash)
			proof := context.WithValue(context.Background(), proofContextKey{}, sessionProof{service: svc, hash: digest})
			if err := svc.WithStaffTx(proof, principal, func(pgx.Tx, core.Principal) error { t.Fatal("fake witness entered protected transaction"); return nil }); !errors.Is(err, ErrForbidden) {
				t.Fatal("timestamp-only witness was not rejected by the transactional gate")
			}
		})
	}
}

func TestStaffCookieNamespaceIsolation(t *testing.T) {
	f := staffLoginFixture(t)
	ctx := context.Background()
	if p, err := f.service.Resolve(ctx, staffCookieRequest("osee_completion_r1_session", f.session.Token)); err != nil || !p.MFA {
		t.Fatal("candidate cookie namespace cannot carry its real enrolled session")
	}
	for _, name := range []string{"osee_dev_session", "osee_completion_r1_login_state", "osee_completion_r1_challenge"} {
		if _, err := f.service.Resolve(ctx, staffCookieRequest(name, f.session.Token)); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("foreign or challenge cookie was treated as a candidate session")
		}
	}
	r := staffCookieRequest("osee_completion_r1_session", f.session.Token)
	r.AddCookie(&http.Cookie{Name: "osee_completion_r1_session", Value: f.session.Token})
	if _, err := f.service.Resolve(ctx, r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("duplicate session cookies were accepted")
	}
}

func TestStaffAuditTrustedActor(t *testing.T) {
	f := staffLoginFixture(t)
	ctx := context.Background()
	ownerProof := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	owner, err := f.service.CurrentPrincipal(ownerProof)
	if err != nil || !owner.MFA {
		t.Fatal("synthetic genuine owner could not resolve")
	}
	queue := &testInviteQueue{}
	f.service.queue = queue
	participant := testPrincipal(t, f.store, core.RoleParticipant)
	invite, err := f.service.IssueInvite(ownerProof, participant.UserID)
	if err != nil {
		t.Fatal("current owner failed to issue inert participant invitation")
	}
	login, err := f.service.consumeInvite(ctx, queue.token, "")
	if err != nil {
		t.Fatal("real participant invitation login failed")
	}
	if err = f.service.revoke(ctx, login.token); err != nil {
		t.Fatal("participant logout failed")
	}
	digest := sha256.Sum256([]byte(login.token))
	var session core.ID
	if err = f.store.Pool.QueryRow(ctx, "select id::text from auth_sessions where token_hash=$1", digest[:]).Scan(&session); err != nil {
		t.Fatal("real audited session lookup failed")
	}
	for _, item := range []struct {
		action        string
		object, actor core.ID
	}{{"auth_invite_issued", invite, owner.UserID}, {"auth_login", session, participant.UserID}, {"auth_logout", session, participant.UserID}} {
		var count int
		if err = f.store.Pool.QueryRow(ctx, "select count(*) from audit_events where action=$1 and object_id=$2 and actor_id=$3", item.action, item.object, item.actor).Scan(&count); err != nil || count != 1 {
			t.Fatal("auth transition omitted or fabricated its trusted actor")
		}
	}
	if _, err = f.identity.BeginLogin(ctx, f.username, staffCryptoPassword(t), "198.51.100.18"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("invalid password did not fail generically")
	}
	var denied int
	if err = f.store.Pool.QueryRow(ctx, "select count(*) from audit_events where action='staff_login_failed' and actor_id is null and object_id=$1", owner.UserID).Scan(&denied); err != nil || denied != 1 {
		t.Fatal("unauthenticated failure was not audited without an invented actor")
	}
}

func TestStaffCurrentAttestationVersionAndKeyRevocation(t *testing.T) {
	for _, change := range []string{"epoch", "factor_revoked", "principal_disabled", "timestamp", "wrong_key"} {
		t.Run(change, func(t *testing.T) {
			f := staffLoginFixture(t)
			proof := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
			svc := f.service
			switch change {
			case "epoch":
				testExec(t, f.store, "update auth_staff_credentials set credential_epoch=credential_epoch+1")
			case "factor_revoked":
				testExec(t, f.store, "update auth_staff_factors set revoked_at=$1", f.at)
			case "principal_disabled":
				testExec(t, f.store, "update auth_principals set enabled=false where role='owner'")
			case "timestamp":
				testExec(t, f.store, "update auth_sessions set mfa_verified_at=$1", f.at)
			case "wrong_key":
				svc = NewService(f.store, nil)
				key := append([]byte(nil), f.key...)
				key[0] ^= 1
				identity, err := NewStaffIdentity(svc, key, f.instance)
				if err != nil {
					t.Fatal("synthetic wrong-key observer setup failed")
				}
				identity.now = f.identity.now
			}
			w := httptest.NewRecorder()
			svc.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, staffCookieRequest(SessionCookieName, f.session.Token))
			if w.Code == http.StatusOK {
				t.Fatal("revoked or unauthenticated factor retained current staff authority")
			}
			if change != "wrong_key" {
				if _, err := svc.CurrentPrincipal(proof); err == nil {
					t.Fatal("old proof retained revoked authority")
				}
			}
		})
	}
}
