package db_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"osee-testops-lite/internal/db"
)

func staffSchemaFixture(t *testing.T) *db.Store {
	t.Helper()
	dsn := os.Getenv("OSEE_TEST_DATABASE_URL")
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/osee_testops_test" || u.RawQuery != "sslmode=disable" {
		t.Fatal("explicit isolated test database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal("test database open failed")
	}
	var database string
	if err = base.Pool.QueryRow(ctx, "select current_database()").Scan(&database); err != nil || database != "osee_testops_test" {
		base.Close()
		t.Fatal("wrong test database")
	}
	schema := "staff_schema_" + strings.ReplaceAll(id(t), "-", "")
	if _, err = base.Pool.Exec(ctx, "create schema "+pgx.Identifier{schema}.Sanitize()); err != nil {
		base.Close()
		t.Fatal("test schema create failed")
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		defer base.Close()
		if _, failure := base.Pool.Exec(cleanup, "drop schema "+pgx.Identifier{schema}.Sanitize()+" cascade"); failure != nil {
			t.Error("exact test schema cleanup failed")
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("test configuration failed")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("test schema pool failed")
	}
	store := &db.Store{Pool: pool}
	t.Cleanup(store.Close)
	if err = store.Migrate(ctx); err != nil {
		t.Fatal("private fresh migration failed", err)
	}
	return store
}

func requireStaffSchema(t *testing.T, s *db.Store) {
	t.Helper()
	for _, table := range []string{"app_instance", "auth_staff_credentials", "auth_staff_factors", "auth_staff_challenges", "auth_staff_recovery", "auth_staff_attestations", "auth_staff_rates", "auth_bootstrap", "app_operating_state"} {
		var exists bool
		if err := s.Pool.QueryRow(context.Background(), "select to_regclass($1) is not null", table).Scan(&exists); err != nil {
			t.Fatal("staff schema lookup failed")
		}
		if !exists {
			t.Fatal("required staff schema relation absent:", table)
		}
	}
}

func rejectStaffSchema(t *testing.T, tx pgx.Tx, code, statement string, args ...any) {
	t.Helper()
	exec(t, tx, "savepoint staff_rejection")
	_, err := tx.Exec(context.Background(), statement, args...)
	if err == nil {
		_, err = tx.Exec(context.Background(), "set constraints all immediate")
	}
	var failure *pgconn.PgError
	if !errors.As(err, &failure) || failure.Code != code {
		t.Errorf("expected constrained rejection %s; actual code %s", code, staffSchemaErrorCode(err))
	}
	exec(t, tx, "rollback to staff_rejection")
	exec(t, tx, "release savepoint staff_rejection")
}

func staffSchemaErrorCode(err error) string {
	var failure *pgconn.PgError
	if errors.As(err, &failure) {
		return failure.Code
	}
	if err == nil {
		return "ACCEPTED"
	}
	return "NON_POSTGRES_ERROR"
}

func staffSchemaCredential(t *testing.T, tx pgx.Tx, instance, role, username string) string {
	t.Helper()
	principal := id(t)
	exec(t, tx, "insert into auth_principals(id,role,enabled) values($1,$2,false)", principal, role)
	exec(t, tx, `insert into auth_staff_credentials(instance_id,principal_id,role,username,password_hash)
values($1,$2,$3,$4,'$argon2id$v=19$m=19456,t=2,p=1$' || repeat('A',22) || '$' || repeat('A',43))`, instance, principal, role, username)
	return principal
}

func staffSchemaFactor(t *testing.T, tx pgx.Tx, instance, principal string, version int64) {
	t.Helper()
	exec(t, tx, `insert into auth_staff_factors(instance_id,principal_id,factor_version,encrypted_seed)
values($1,$2,$3,decode(repeat('00',60),'hex'))`, instance, principal, version)
	exec(t, tx, "update auth_staff_credentials set factor_version=$2 where principal_id=$1", principal, version)
}
