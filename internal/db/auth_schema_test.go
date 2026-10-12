package db_test

import (
	"context"
	"testing"

	"errors"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAuthMigrationsApplyOnce(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	for _, table := range []string{"auth_principals", "auth_invites", "auth_sessions"} {
		var exists bool
		if err := s.Pool.QueryRow(ctx, "select to_regclass($1) is not null", table).Scan(&exists); err != nil {
			t.Fatal("schema lookup failed", err)
		}
		if !exists {
			t.Errorf("auth relation missing: %s", table)
		}
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal("repeat migration failed", err)
	}
	var count int
	if err := s.Pool.QueryRow(ctx, "select count(*) from schema_versions where version=2").Scan(&count); err != nil {
		t.Fatal("version lookup failed", err)
	}
	if count != 1 {
		t.Errorf("expected migration version 2 exactly once, got %d", count)
	}
}

func TestAuthPrincipalRoleAndBindingConstraints(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	var exists bool
	if err := s.Pool.QueryRow(ctx, "select to_regclass('auth_principals') is not null").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("expected auth principal schema before validating role/binding constraints")
	}
	tx := transaction(t, s)
	participant := id(t)
	exec(t, tx, "insert into participants(id) values($1)", participant)
	for _, role := range []string{"system", "unknown", "participant", "partner"} {
		exec(t, tx, "savepoint invalid_role")
		_, err := tx.Exec(ctx, "insert into auth_principals(id,role) values($1,$2)", id(t), role)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Errorf("expected role/binding check rejection for %s", role)
		}
		exec(t, tx, "rollback to invalid_role")
	}
	exec(t, tx, "savepoint invalid_staff_binding")
	_, err := tx.Exec(ctx, "insert into auth_principals(id,role,participant_id) values($1,'admin',$2)", id(t), participant)
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
		t.Error("expected staff/participant binding rejection")
	}
	exec(t, tx, "rollback to invalid_staff_binding")
	exec(t, tx, "insert into auth_principals(id,role,participant_id) values($1,'participant',$2)", id(t), participant)
}

func TestAuthSecretsAndLifetimesConstrained(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	var exists bool
	if err := s.Pool.QueryRow(ctx, "select to_regclass('auth_sessions') is not null").Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("expected auth session schema before validating hash/expiry constraints")
	}
	tx := transaction(t, s)
	principal := id(t)
	exec(t, tx, "insert into auth_principals(id,role) values($1,'admin')", principal)
	for _, invalid := range []string{
		"insert into auth_sessions(id,principal_id,token_hash,expires_at) values($1,$2,decode('00','hex'),now()+interval '10 minutes')",
		"insert into auth_sessions(id,principal_id,token_hash,expires_at) values($1,$2,decode(repeat('00',32),'hex'),now()-interval '1 second')",
		"insert into auth_invites(id,principal_id,token_hash,expires_at) values($1,$2,decode(repeat('01',32),'hex'),now()+interval '11 minutes')",
		"insert into auth_sessions(id,principal_id,token_hash,expires_at) values($1,$2,decode(repeat('02',32),'hex'),now()+interval '31 minutes')",
	} {
		exec(t, tx, "savepoint invalid_secret")
		_, err := tx.Exec(ctx, invalid, id(t), principal)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Error("expected secret/lifetime constraint rejection")
		}
		exec(t, tx, "rollback to invalid_secret")
	}
}
