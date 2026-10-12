// Package testfixtures contains synthetic cryptographic protocols for private test schemas.
package testfixtures

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

type SyntheticStaff struct {
	Identity  *auth.StaffIdentity
	Instance  core.ID
	Authority *auth.Service
	Principal core.Principal
	Session   auth.StaffSession
}

func random(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal("synthetic private random material unavailable")
	}
	return value
}
func identifier(t *testing.T) core.ID {
	t.Helper()
	id, err := core.NewID()
	if err != nil {
		t.Fatal("synthetic identifier unavailable")
	}
	return id
}
func newCode(t *testing.T, view auth.StaffEnrollmentView) string {
	t.Helper()
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(view.Secret)
	if err != nil || len(seed) != 32 {
		t.Fatal("synthetic authenticator seed unavailable")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().UTC().Unix()/30))
	mac := hmac.New(sha1.New, seed)
	if _, err = mac.Write(counter[:]); err != nil {
		t.Fatal("synthetic authenticator unavailable")
	}
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
}
func enroll(t *testing.T, identity *auth.StaffIdentity, capability auth.StaffChallenge, username string) auth.StaffSession {
	t.Helper()
	ctx := context.Background()
	password := base64.RawURLEncoding.EncodeToString(random(t))
	pending, err := identity.BeginEnrollment(ctx, capability.Token, username, password)
	if err != nil {
		t.Fatal("synthetic credential protocol could not start")
	}
	view, err := identity.EnrollmentView(ctx, pending.Token)
	if err != nil {
		t.Fatal("synthetic new factor unavailable")
	}
	result, err := identity.ConfirmEnrollment(ctx, pending.Token, newCode(t, view))
	if err != nil || result.Session.Token == "" {
		t.Fatal("real synthetic factor confirmation failed")
	}
	return result.Session
}
func NewStaff(t *testing.T, store *db.Store, role core.Role) SyntheticStaff {
	t.Helper()
	ctx := context.Background()
	var database, schema string
	if store == nil || store.Pool == nil {
		t.Fatal("private fixture store required")
	}
	if err := store.Pool.QueryRow(ctx, "select current_database(),current_schema()").Scan(&database, &schema); err != nil {
		t.Fatal("private fixture identity unavailable")
	}
	owned := false
	for _, prefix := range []string{"test_sessions_", "test_intake_", "test_portal_"} {
		if strings.HasPrefix(schema, prefix) {
			owned = true
		}
	}
	if database != "osee_testops_test" || !owned || (role != core.RoleOwner && role != core.RoleAdmin) {
		t.Fatal("real staff fixtures are restricted to owned private test schemas")
	}
	instance := identifier(t)
	authority := auth.NewService(store, nil)
	identity, err := auth.NewStaffIdentity(authority, random(t), instance)
	if err != nil {
		t.Fatal("shared genuine fixture identity unavailable")
	}
	capability, err := identity.EnsureBootstrap(ctx)
	if err != nil {
		t.Fatal("private fixture bootstrap unavailable")
	}
	session := enroll(t, identity, capability, "synthetic.owner")
	if role == core.RoleAdmin {
		ownerHash := sha256.Sum256([]byte(session.Token))
		session.ExpiresAt = backdateSession(t, store, ownerHash)
		var owner, ownerSession core.ID
		if err = store.Pool.QueryRow(ctx, "select principal_id::text,id::text from auth_sessions where token_hash=$1", ownerHash[:]).Scan(&owner, &ownerSession); err != nil {
			t.Fatal("genuine synthetic issuer unavailable")
		}
		principal, challenge := identifier(t), identifier(t)
		token := base64.RawURLEncoding.EncodeToString(random(t))
		digest := sha256.Sum256([]byte(token))
		if _, err = store.Pool.Exec(ctx, "insert into auth_principals(id,role,enabled) values($1,'admin',false)", principal); err != nil {
			t.Fatal("disabled synthetic recipient creation failed")
		}
		if _, err = store.Pool.Exec(ctx, queries.CreateStaffCredential, instance, principal, "admin", "synthetic.admin", nil); err != nil {
			t.Fatal("unenrolled synthetic recipient creation failed")
		}
		now := time.Now().UTC()
		if _, err = store.Pool.Exec(ctx, queries.CreateStaffChallenge, challenge, instance, principal, "admin", "admin_invite", digest[:], int64(1), int64(1), nil, nil, owner, ownerSession, now, now.Add(5*time.Minute)); err != nil {
			t.Fatal("synthetic issuer-bound setup capability failed")
		}
		session = enroll(t, identity, auth.StaffChallenge{Token: token, ExpiresAt: now.Add(5 * time.Minute)}, "synthetic.admin")
	}
	digest := sha256.Sum256([]byte(session.Token))
	var principal core.Principal
	if err = store.Pool.QueryRow(ctx, "select principal_id::text from auth_sessions where token_hash=$1", digest[:]).Scan(&principal.UserID); err != nil {
		t.Fatal("genuine fixture principal unavailable")
	}
	principal.Role = role
	principal.MFA = true
	session.ExpiresAt = backdateSession(t, store, digest)
	return SyntheticStaff{Identity: identity, Instance: instance, Authority: authority, Principal: principal, Session: session}
}
func backdateSession(t *testing.T, store *db.Store, digest [32]byte) time.Time {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	expires := now.Add(20 * time.Minute)
	err := store.WithTx(ctx, func(tx pgx.Tx) error {
		var session, instance core.ID
		var version, epoch int64
		var verified time.Time
		if err := tx.QueryRow(ctx, `delete from auth_staff_attestations a using auth_sessions s where a.session_id=s.id and s.token_hash=$1
returning a.session_id::text,a.instance_id::text,a.factor_version,a.credential_epoch,a.verified_at`, digest[:]).Scan(&session, &instance, &version, &epoch, &verified); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "update auth_sessions set created_at=$2,expires_at=$3 where id=$1", session, now.Add(-10*time.Minute), expires); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, queries.CreateStaffAttestation, session, instance, version, epoch, verified)
		return err
	})
	if err != nil {
		t.Fatal("synthetic genuine attestation age setup failed")
	}
	return expires
}
