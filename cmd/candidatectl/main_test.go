package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

func cliIdentityFixture(t *testing.T) (*auth.StaffIdentity, *db.Store) {
	t.Helper()
	dsn := os.Getenv("OSEE_TEST_DATABASE_URL")
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/osee_testops_test" || u.RawQuery != "sslmode=disable" {
		t.Fatal("explicit private synthetic CLI database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal("private CLI fixture database unavailable")
	}
	t.Cleanup(base.Close)
	var actual string
	if err = base.Pool.QueryRow(ctx, "select current_database()").Scan(&actual); err != nil || actual != "osee_testops_test" {
		t.Fatal("wrong CLI fixture database")
	}
	id, err := core.NewID()
	if err != nil {
		t.Fatal("fixture ID failed")
	}
	schema := "staff_cli_" + strings.ReplaceAll(string(id), "-", "")
	if _, err = base.Pool.Exec(ctx, "create schema "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal("CLI fixture schema failed")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := base.Pool.Exec(cleanup, "drop schema "+pgx.Identifier{schema}.Sanitize()+" cascade"); err != nil {
			t.Error("CLI fixture schema cleanup failed")
		}
	})
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("CLI fixture pool configuration failed")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("CLI fixture pool failed")
	}
	store := &db.Store{Pool: pool}
	t.Cleanup(store.Close)
	if err = store.Migrate(ctx); err != nil {
		t.Fatal("CLI fixture migration failed")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal("fixture key generation failed")
	}
	identity, err := auth.NewStaffIdentity(auth.NewService(store, nil), key, id)
	if err != nil {
		t.Fatal("CLI identity construction failed")
	}
	return identity, store
}

func TestCandidateCtlPrivateCapabilityRoundtrip(t *testing.T) {
	identity, store := cliIdentityFixture(t)
	path := filepath.Join(t.TempDir(), "setup-capability.txt")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal("private fixture permissions failed")
	}
	var output bytes.Buffer
	if err := executeBootstrap(context.Background(), identity, bootstrapOptions{path: path}, &output); err != nil {
		t.Fatal("trusted CLI did not write a private capability")
	}
	capability, err := os.ReadFile(path)
	if err != nil || len(capability) != 43 {
		t.Fatal("private capability file invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("private capability file is not owner-only regular data")
	}
	if strings.Contains(output.String(), string(capability)) || !strings.Contains(output.String(), "private_capability_written") {
		t.Fatal("CLI disclosed capability or omitted truthful status")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(string(capability))
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != string(capability) {
		t.Fatal("private capability not canonical")
	}
	expected := sha256.Sum256(capability)
	var digest []byte
	var start, end time.Time
	if err = store.Pool.QueryRow(context.Background(), "select token_hash,created_at,expires_at from auth_bootstrap").Scan(&digest, &start, &end); err != nil || !bytes.Equal(digest, expected[:]) || end.Sub(start) != 10*time.Minute {
		t.Fatal("CLI file did not match digest-only ten-minute bootstrap")
	}
	if err = executeBootstrap(context.Background(), identity, bootstrapOptions{path: path}, &output); err == nil {
		t.Fatal("CLI silently overwrote or recovered live capability")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, capability) {
		t.Fatal("refused repeated CLI changed private capability")
	}
	if err = executeBootstrap(context.Background(), identity, bootstrapOptions{path: path, reset: true}, &output); err != nil {
		t.Fatal("explicit empty CLI reset failed")
	}
	rotated, err := os.ReadFile(path)
	if err != nil || bytes.Equal(rotated, capability) || len(rotated) != 43 || strings.Contains(output.String(), string(rotated)) {
		t.Fatal("empty reset did not privately rotate capability")
	}
	var active, sessions int
	if err = store.Pool.QueryRow(context.Background(), "select (select count(*) from auth_principals where enabled),(select count(*) from auth_sessions)").Scan(&active, &sessions); err != nil || active != 0 || sessions != 0 {
		t.Fatal("trusted bootstrap CLI granted staff authority")
	}
}

func TestCandidateCtlRejectsUnsafePrivatePaths(t *testing.T) {
	identity, store := cliIdentityFixture(t)
	public := t.TempDir()
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal("disclosure fixture failed")
	}
	var output bytes.Buffer
	if err := executeBootstrap(context.Background(), identity, bootstrapOptions{path: filepath.Join(public, "setup-capability.txt")}, &output); err == nil {
		t.Fatal("broad private directory accepted")
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal("private fixture failed")
	}
	outside := filepath.Join(t.TempDir(), "nonsecret-target")
	if err := os.WriteFile(outside, []byte("nonsecret"), 0600); err != nil {
		t.Fatal("outside fixture failed")
	}
	link := filepath.Join(private, "setup-capability.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal("real symlink fixture failed")
	}
	if err := executeBootstrap(context.Background(), identity, bootstrapOptions{path: link, reset: true}, &output); err == nil {
		t.Fatal("symlink capability path accepted")
	}
	var rows int
	if err := store.Pool.QueryRow(context.Background(), "select count(*) from auth_bootstrap").Scan(&rows); err != nil || rows != 0 {
		t.Fatal("unsafe private path changed bootstrap state")
	}
}

func TestCandidateCtlRefusesUntrustedArguments(t *testing.T) {
	get := func(string) string { return "" }
	for _, args := range [][]string{{}, {"bootstrap"}, {"bootstrap", "--empty-only", "--reset-empty"}, {"bootstrap", "--empty-only", "--capability-file", "relative"}, {"bootstrap", "--empty-only", "--password", "claimed"}, {"unknown"}} {
		var output bytes.Buffer
		if err := run(args, get, &output); err == nil || output.Len() != 0 {
			t.Fatal("untrusted CLI request accepted or disclosed data")
		}
	}
}
