package testfixtures

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

// AddAdmin confirms a recipient-owned factor from a synthetic issuer-bound invite.
func AddAdmin(t *testing.T, store *db.Store, owner SyntheticStaff, username string) SyntheticStaff {
	t.Helper()
	ctx := context.Background()
	var database, schema string
	if err := store.Pool.QueryRow(ctx, "select current_database(),current_schema()").Scan(&database, &schema); err != nil {
		t.Fatal("private admin fixture identity unavailable")
	}
	if database != "osee_testops_test" || owner.Identity == nil || owner.Principal.Role != core.RoleOwner || len(schema) < 13 || schema[:12] != "test_intake_" {
		t.Fatal("admin fixture requires its private intake schema and genuine owner")
	}
	principal, challenge := identifier(t), identifier(t)
	token := base64.RawURLEncoding.EncodeToString(random(t))
	digest := sha256.Sum256([]byte(token))
	issuerHash := sha256.Sum256([]byte(owner.Session.Token))
	var issuerSession core.ID
	if err := store.Pool.QueryRow(ctx, "select id::text from auth_sessions where principal_id=$1 and token_hash=$2 and revoked_at is null", owner.Principal.UserID, issuerHash[:]).Scan(&issuerSession); err != nil {
		t.Fatal("genuine synthetic issuer session unavailable")
	}
	if _, err := store.Pool.Exec(ctx, "insert into auth_principals(id,role,enabled) values($1,'admin',false)", principal); err != nil {
		t.Fatal("synthetic disabled admin fixture failed")
	}
	if _, err := store.Pool.Exec(ctx, queries.CreateStaffCredential, owner.Instance, principal, "admin", username, nil); err != nil {
		t.Fatal("synthetic pending admin fixture failed")
	}
	now := time.Now().UTC()
	if _, err := store.Pool.Exec(ctx, queries.CreateStaffChallenge, challenge, owner.Instance, principal, "admin", "admin_invite", digest[:], int64(1), int64(1), nil, nil, owner.Principal.UserID, issuerSession, now, now.Add(5*time.Minute)); err != nil {
		t.Fatal("synthetic bound invitation fixture failed")
	}
	session := enroll(t, owner.Identity, auth.StaffChallenge{Token: token, ExpiresAt: now.Add(5 * time.Minute)}, username)
	sessionHash := sha256.Sum256([]byte(session.Token))
	session.ExpiresAt = backdateSession(t, store, sessionHash)
	return SyntheticStaff{Identity: owner.Identity, Instance: owner.Instance, Authority: owner.Authority, Principal: core.Principal{UserID: principal, Role: core.RoleAdmin, MFA: true}, Session: session}
}
