package db_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/riverqueue/river"

	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/jobs"
)

func fixture(t *testing.T) *db.Store {
	t.Helper()
	dsn := os.Getenv("OSEE_TEST_DATABASE_URL")
	u, e := url.Parse(dsn)
	if e != nil || u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/osee_testops_test" || u.RawQuery != "sslmode=disable" {
		t.Fatal("explicit isolated OSEE_TEST_DATABASE_URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, e := db.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	var name string
	if e = s.Pool.QueryRow(ctx, "select current_database()").Scan(&name); e != nil || name != "osee_testops_test" {
		t.Fatal("wrong database")
	}
	t.Log("authenticated isolated test database:", name)
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	return s
}
func id(t *testing.T) string {
	t.Helper()
	v, e := core.NewID()
	if e != nil {
		t.Fatal(e)
	}
	return string(v)
}
func exec(t *testing.T, tx pgx.Tx, q string, args ...any) {
	t.Helper()
	if _, e := tx.Exec(context.Background(), q, args...); e != nil {
		t.Fatal(e)
	}
}
func transaction(t *testing.T, s *db.Store) pgx.Tx {
	t.Helper()
	tx, e := s.Pool.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}
func TestFreshMigrationsApply(t *testing.T) {
	s := fixture(t)
	for _, table := range []string{"schema_versions", "participants", "registrations", "sessions", "payments", "payment_allocations", "inbound_receipts", "audit_events", "outbox", "artifacts", "policy_versions"} {
		var exists bool
		e := s.Pool.QueryRow(context.Background(), "select to_regclass($1) is not null", table).Scan(&exists)
		if e != nil || !exists {
			t.Errorf("required table missing: %s", table)
		}
	}
	if e := s.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	var n int
	if e := s.Pool.QueryRow(context.Background(), "select count(*) from schema_versions where version=1").Scan(&n); e != nil || n != 1 {
		t.Error("migration must apply exactly once")
	}
}
func TestDomainStatesRemainSeparate(t *testing.T) {
	s := fixture(t)
	tx := transaction(t, s)
	p, r := id(t), id(t)
	exec(t, tx, "insert into participants(id) values($1)", p)
	exec(t, tx, "insert into registrations(id,participant_id) values($1,$2)", r, p)
	var a, b, c string
	if e := tx.QueryRow(context.Background(), "select registration_state,attendance_state,result_state from registrations where id=$1", r).Scan(&a, &b, &c); e != nil || a != "DRAFT" || b != "NOT_CHECKED_IN" || c != "NOT_RECEIVED" {
		t.Fatal("separate state defaults missing")
	}
	for i, col := range []string{"registration_state", "attendance_state", "result_state"} {
		exec(t, tx, "savepoint statecheck")
		if _, e := tx.Exec(context.Background(), fmt.Sprintf("update registrations set %s=$1 where id=$2", col), []string{"VERIFIED", "CONFIRMED", "COMPLETED"}[i], r); e == nil {
			t.Error("cross-domain state accepted")
		}
		exec(t, tx, "rollback to statecheck")
	}
}
func TestMultipleAttemptsAndSharedContacts(t *testing.T) {
	s := fixture(t)
	tx := transaction(t, s)
	p, q := id(t), id(t)
	for _, v := range []string{p, q} {
		exec(t, tx, "insert into participants(id,email,phone) values($1,'shared@example.invalid','synthetic')", v)
	}
	for i := 0; i < 2; i++ {
		exec(t, tx, "insert into registrations(id,participant_id) values($1,$2)", id(t), p)
	}
	var n int
	exec(t, tx, "insert into registrations(id,participant_id) values($1,$2)", id(t), q)
	if e := tx.QueryRow(context.Background(), "select count(*) from registrations where participant_id=$1", p).Scan(&n); e != nil || n != 2 {
		t.Fatal("stable participant must have two attempts")
	}
	if e := tx.QueryRow(context.Background(), "select count(*) from participants where id=any($1::uuid[])", []string{p, q}).Scan(&n); e != nil || n != 2 {
		t.Fatal("shared contact merged participants")
	}
}
func TestEventIdentityConflict(t *testing.T) {
	s := fixture(t)
	tx := transaction(t, s)
	key := id(t)
	exec(t, tx, "insert into inbound_receipts(id,provider,event_key,fingerprint) values($1,'synthetic',$2,$3)", id(t), key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	exec(t, tx, "savepoint duplicate")
	if _, e := tx.Exec(context.Background(), "insert into inbound_receipts(id,provider,event_key,fingerprint) values($1,'synthetic',$2,$3)", id(t), key, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !uniqueViolation(e) {
		t.Fatalf("expected event identity unique violation, got %v", e)
	}
	exec(t, tx, "rollback to duplicate")
	var fingerprint string
	if e := tx.QueryRow(context.Background(), "select fingerprint from inbound_receipts where provider='synthetic' and event_key=$1", key).Scan(&fingerprint); e != nil || fingerprint != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatal("original event changed")
	}
}
func TestPaymentAllocationIsUnique(t *testing.T) {
	s := fixture(t)
	tx := transaction(t, s)
	p, r, pay := id(t), id(t), id(t)
	exec(t, tx, "insert into participants(id) values($1)", p)
	exec(t, tx, "insert into registrations(id,participant_id) values($1,$2)", r, p)
	exec(t, tx, "insert into payments(id,minor_units,currency) values($1,1,'IDR')", pay)
	exec(t, tx, "insert into payment_allocations(payment_id,registration_id) values($1,$2)", pay, r)
	if _, e := tx.Exec(context.Background(), "insert into payment_allocations(payment_id,registration_id) values($1,$2)", pay, r); !uniqueViolation(e) {
		t.Fatalf("expected payment allocation unique violation, got %v", e)
	}
}

func effects(t *testing.T, ctx context.Context, tx pgx.Tx, c *river.Client[pgx.Tx], key string) error {
	t.Helper()
	for _, q := range []string{"insert into participants(id) values($1)", "insert into audit_events(id,object_id,action) values($1,$1,'probe')", "insert into outbox(id,object_id,event_kind) values($1,$1,'probe')"} {
		if _, e := tx.Exec(ctx, q, key); e != nil {
			return e
		}
	}
	_, e := c.InsertTx(ctx, tx, jobs.ProbeArgs{ID: core.ID(key)}, nil)
	return e
}
func assertEffects(t *testing.T, s *db.Store, key string, want int) {
	t.Helper()
	for _, table := range []string{"participants", "audit_events", "outbox", "river_job"} {
		q := "select count(*) from " + table + " where id=$1::uuid"
		if table == "river_job" {
			q = "select count(*) from river_job where args->>'id'=$1"
		}
		var n int
		if e := s.Pool.QueryRow(context.Background(), q, key).Scan(&n); e != nil || n != want {
			t.Errorf("%s effects=%d want=%d error=%v", table, n, want, e)
		}
	}
	if s.Pool.Stat().AcquiredConns() != 0 {
		t.Error("transaction leaked acquired connection")
	}
}
func client(t *testing.T, s *db.Store) *river.Client[pgx.Tx] {
	t.Helper()
	c, e := jobs.NewClient(s.Pool)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestMutationEventAndOutboxRollbackTogether(t *testing.T) {
	s := fixture(t)
	c := client(t, s)
	key := id(t)
	sentinel := errors.New("callback failure")
	e := s.WithTx(context.Background(), func(tx pgx.Tx) error {
		if e := effects(t, context.Background(), tx, c, key); e != nil {
			return e
		}
		return sentinel
	})
	if !errors.Is(e, sentinel) {
		t.Fatal("callback error lost")
	}
	assertEffects(t, s, key, 0)
}
func TestTransactionPanicRollsBack(t *testing.T) {
	s := fixture(t)
	c := client(t, s)
	key := id(t)
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = s.WithTx(context.Background(), func(tx pgx.Tx) error {
			if e := effects(t, context.Background(), tx, c, key); e != nil {
				t.Fatal(e)
			}
			panic("synthetic panic")
		})
	}()
	if recovered != "synthetic panic" {
		t.Error("panic not propagated")
	}
	assertEffects(t, s, key, 0)
}
func TestTransactionContextCancellation(t *testing.T) {
	s := fixture(t)
	c := client(t, s)
	key := id(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := s.WithTx(ctx, func(tx pgx.Tx) error {
		if e := effects(t, ctx, tx, c, key); e != nil {
			return e
		}
		cancel()
		return nil
	})
	if e == nil {
		t.Error("cancelled transaction reported success")
	}
	assertEffects(t, s, key, 0)
}
func TestTransactionCommitFailure(t *testing.T) {
	s := fixture(t)
	c := client(t, s)
	key := id(t)
	e := s.WithTx(context.Background(), func(tx pgx.Tx) error {
		if e := effects(t, context.Background(), tx, c, key); e != nil {
			return e
		}
		_, _ = tx.Exec(context.Background(), "select 1/0")
		return nil
	})
	if e == nil {
		t.Error("failed commit reported success")
	}
	assertEffects(t, s, key, 0)
}
func TestSuccessfulTransactionCommitsJobAndAudit(t *testing.T) {
	s := fixture(t)
	c := client(t, s)
	key := id(t)
	if e := s.WithTx(context.Background(), func(tx pgx.Tx) error { return effects(t, context.Background(), tx, c, key) }); e != nil {
		t.Fatal(e)
	}
	assertEffects(t, s, key, 1)
}
func TestProbeWorkerCompletesAndRestartPreservesQueue(t *testing.T) {
	s := fixture(t)
	c := client(t, s)
	key := id(t)
	if e := s.WithTx(context.Background(), func(tx pgx.Tx) error { return effects(t, context.Background(), tx, c, key) }); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e := c.Start(ctx); e != nil {
		t.Fatal(e)
	}
	wait := func(key, want string) {
		t.Helper()
		for {
			var state string
			if e := s.Pool.QueryRow(ctx, "select state::text from river_job where args->>'id'=$1", key).Scan(&state); e != nil {
				t.Fatal(e)
			}
			if state == want {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("probe did not complete")
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	wait(key, "completed")
	if e := c.Stop(ctx); e != nil {
		t.Fatal(e)
	}
	key2 := id(t)
	if e := s.WithTx(ctx, func(tx pgx.Tx) error { return effects(t, ctx, tx, c, key2) }); e != nil {
		t.Fatal(e)
	}
	c2 := client(t, s)
	if e := c2.Start(ctx); e != nil {
		t.Fatal(e)
	}
	defer c2.Stop(context.Background())
	wait(key2, "completed")
	wait(key, "completed")
	t.Log("real River worker completed inert jobs before and after client restart")
}

func uniqueViolation(err error) bool {
	var p *pgconn.PgError
	return errors.As(err, &p) && p.Code == "23505"
}
func TestExactEventReplayCannotDuplicate(t *testing.T) {
	s := fixture(t)
	tx := transaction(t, s)
	key := id(t)
	hash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	exec(t, tx, "insert into inbound_receipts(id,provider,event_key,fingerprint) values($1,'synthetic',$2,$3)", id(t), key, hash)
	if _, e := tx.Exec(context.Background(), "insert into inbound_receipts(id,provider,event_key,fingerprint) values($1,'synthetic',$2,$3)", id(t), key, hash); !uniqueViolation(e) {
		t.Fatalf("expected replay unique violation, got %v", e)
	}
}
func TestArtifactsAndPoliciesImmutableAndInactive(t *testing.T) {
	s := fixture(t)
	tx := transaction(t, s)
	artifact, policy := id(t), id(t)
	exec(t, tx, "insert into artifacts(id,sha256,private_reference) values($1,$2,'synthetic-private-reference')", artifact, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	exec(t, tx, "insert into policy_versions(id,kind,version,values) values($1,'inactive-fixture',1,'{}')", policy)
	for _, q := range []string{"update artifacts set private_reference='changed' where id=$1", "delete from artifacts where id=$1", "update policy_versions set active=true where id=$2", "delete from policy_versions where id=$2"} {
		exec(t, tx, "savepoint immutable")
		args := []any{artifact}
		if q[len(q)-1:] == "2" {
			q = q[:len(q)-1] + "1"
			args = []any{policy}
		}
		if _, e := tx.Exec(context.Background(), q, args...); e == nil {
			t.Error("immutable record changed")
		}
		exec(t, tx, "rollback to immutable")
	}
	var active bool
	if e := tx.QueryRow(context.Background(), "select active from policy_versions where id=$1", policy).Scan(&active); e != nil || active {
		t.Fatal("foundation policy must remain inactive")
	}
}
