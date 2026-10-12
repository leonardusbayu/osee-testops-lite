package demo

import (
	"context"
	"crypto/sha256"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/url"
	"os"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) *db.Store {
	t.Helper()
	dsn := os.Getenv("OSEE_TEST_DATABASE_URL")
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/osee_testops_test" || u.RawQuery != "sslmode=disable" {
		t.Fatal("isolated fixture required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	base, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := core.NewID()
	schema := "test_demo_" + strings.ReplaceAll(string(id), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = base.Exec(context.Background(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	store := &db.Store{Pool: pool}
	t.Cleanup(func() {
		pool.Close()
		if _, err := base.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("exact owned schema cleanup failed")
		}
		base.Close()
	})
	if err = store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}
func TestDemoSeedIsExplicitAndIdempotent(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	if err := Seed(ctx, s); err != nil {
		t.Fatal("explicit synthetic seed not available", err)
	}
	first, err := Principal(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if err = Seed(ctx, s); err != nil {
		t.Fatal(err)
	}
	second, err := Principal(ctx, s)
	if err != nil || first != second {
		t.Error("repeat seed changed identity")
	}
	var count int
	var role, email string
	var enabled bool
	if err = s.Pool.QueryRow(ctx, "select count(*) from development_fixtures").Scan(&count); err != nil || count != 1 {
		t.Error("seed must create one explicit marker")
	}
	if err = s.Pool.QueryRow(ctx, "select a.role,a.enabled,p.email from auth_principals a join participants p on p.id=a.participant_id where a.id=$1", first).Scan(&role, &enabled, &email); err != nil || role != "participant" || !enabled || email != "participant-demo@osee.invalid" {
		t.Error("synthetic seed granted wrong identity")
	}
}
func TestDemoIssueRefusesMissingMarkerAndNeverSeedsImplicitly(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	if code, err := Issue(ctx, s); err == nil || code != "" {
		t.Error("unseeded demo issued credential")
	}
	var count int
	if err := s.Pool.QueryRow(ctx, "select count(*) from development_fixtures").Scan(&count); err != nil || count != 0 {
		t.Error("public access seeded or missing additive marker table")
	}
}
func TestDemoInvitationIsShortLivedHashedAndParticipantBound(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	if err := Seed(ctx, s); err != nil {
		t.Fatal(err)
	}
	principal, err := Principal(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	code, err := Issue(ctx, s)
	if err != nil || len(code) != 43 {
		t.Fatal("expected internal random invite")
	}
	hash := sha256.Sum256([]byte(code))
	var target core.ID
	var created, expires time.Time
	var saved []byte
	if err = s.Pool.QueryRow(ctx, "select principal_id,token_hash,created_at,expires_at from auth_invites where token_hash=$1", hash[:]).Scan(&target, &saved, &created, &expires); err != nil || target != principal || string(saved) != string(hash[:]) || expires.Sub(created) > time.Minute || !expires.After(created) {
		t.Error("demo invite lost hash/short-lifetime/exact target binding")
	}
	var count int
	if err = s.Pool.QueryRow(ctx, "select count(*) from auth_principals where role<>'participant'").Scan(&count); err != nil || count != 0 {
		t.Error("demo created privileged actor")
	}
}
func TestDemoChangedDisabledOrPrivilegedBindingFailsClosed(t *testing.T) {
	s := fixture(t)
	ctx := context.Background()
	if err := Seed(ctx, s); err != nil {
		t.Fatal(err)
	}
	principal, err := Principal(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"update auth_principals set enabled=false where id=$1", "update auth_principals set role='admin',participant_id=null where id=$1", "update participants set email='different@example.invalid' where id=(select participant_id from development_fixtures)"} {
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		args := []any{principal}
		if !strings.Contains(mutation, "$1") {
			args = nil
		}
		if _, err = tx.Exec(ctx, mutation, args...); err != nil {
			tx.Rollback(ctx)
			t.Fatal(err)
		}
		// Commit mutation so the public adapter observes current authority, then restore explicitly.
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if code, err := Issue(ctx, s); err == nil || code != "" {
			t.Error("changed marker binding issued credential")
		}
		if _, err = s.Pool.Exec(ctx, "update auth_principals set role='participant',enabled=true,participant_id=(select participant_id from development_fixtures) where id=$1", principal); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Pool.Exec(ctx, "update participants set email='participant-demo@osee.invalid' where id=(select participant_id from development_fixtures)"); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = s.Pool.QueryRow(ctx, "select count(*) from auth_invites").Scan(&count); err != nil || count != 0 {
		t.Error("denied binding had invite side effect")
	}
}
