package sessions

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/testfixtures"
)

const origin = "http://127.0.0.1:8090"

type fixture struct {
	store     *db.Store
	authority *auth.Service
	service   *Service
	actor     core.Principal
	token     string
}

func id(t *testing.T) core.ID {
	t.Helper()
	value, err := core.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func exec(t *testing.T, store *db.Store, statement string, args ...any) {
	t.Helper()
	if _, err := store.Pool.Exec(context.Background(), statement, args...); err != nil {
		t.Fatal("synthetic fixture persistence failed", err)
	}
}
func testFixture(t *testing.T) *fixture {
	t.Helper()
	dsn := os.Getenv("OSEE_TEST_DATABASE_URL")
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/osee_testops_test" || u.RawQuery != "sslmode=disable" {
		t.Fatal("explicit isolated test database required")
	}
	base, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal("isolated test database unavailable")
	}
	schema := "test_sessions_" + strings.ReplaceAll(string(id(t)), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = base.Exec(context.Background(), "CREATE SCHEMA "+quoted); err != nil {
		base.Close()
		t.Fatal(err)
	}
	cfg := base.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := base.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("exact test schema cleanup failed")
		}
		base.Close()
	})
	store := &db.Store{Pool: pool}
	if err = store.Migrate(context.Background()); err != nil {
		t.Fatal("test schema migration failed", err)
	}
	genuine := testfixtures.NewStaff(t, store, core.RoleAdmin)
	f := &fixture{store: store, actor: genuine.Principal, token: genuine.Session.Token, authority: genuine.Authority}
	f.service = NewService(f.authority)
	return f
}

// The private fixture has genuine credentials, factor confirmation and current attestation.
func (f *fixture) authorized(t *testing.T, fn func(context.Context)) {
	t.Helper()
	req := httptest.NewRequest("POST", origin+"/internal-test-only", nil)
	req.Header.Set("Origin", origin)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: f.token})
	proof, err := f.authority.RequestCSRF(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-CSRF-Token", proof)
	called := false
	h := f.authority.RequireStaff(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; fn(r.Context()); w.WriteHeader(204) }))
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if !called || out.Code != 204 {
		t.Fatalf("synthetic trusted test boundary unavailable: %d", out.Code)
	}
}
func command(f *fixture) core.SessionCommand {
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond)
	return core.SessionCommand{StartsAt: start, CutoffAt: start.Add(-time.Hour), Capacity: 20, AssignedStaffID: f.actor.UserID, GuideReference: "synthetic-guide-v1", MeetingReference: "synthetic-meeting-v1"}
}
func change(s core.Session) core.SessionChange {
	return core.SessionChange{ExpectedVersion: s.ScheduleVersion, StartsAt: s.StartsAt.Add(24 * time.Hour), CutoffAt: s.CutoffAt.Add(24 * time.Hour), AssignedStaffID: s.AssignedStaffID, GuideReference: "synthetic-guide-v2", MeetingReference: "synthetic-meeting-v2", Reason: "Synthetic reschedule exercise"}
}
func create(t *testing.T, f *fixture, ctx context.Context) core.Session {
	t.Helper()
	result, err := f.service.Create(ctx, f.actor, command(f))
	if err != nil {
		t.Fatalf("expected transactional session creation: %v", err)
	}
	return result
}
func count(t *testing.T, f *fixture, statement string, args ...any) int {
	t.Helper()
	var n int
	if err := f.store.Pool.QueryRow(context.Background(), statement, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWIBDisplayAndCutoff(t *testing.T) {
	start := time.Date(2026, 10, 11, 2, 0, 0, 0, time.UTC)
	s := core.Session{StartsAt: start, CutoffAt: start.Add(-time.Hour), ScheduleVersion: 2}
	if s.DisplayWIB() != "Sun, 11 Oct 2026 · 09:00 WIB" {
		t.Error("expected UTC instant to display as 09:00 WIB")
	}
	if !s.BookingOpen(s.CutoffAt.Add(-time.Nanosecond)) || s.BookingOpen(s.CutoffAt) || s.BookingOpen(s.CutoffAt.Add(time.Nanosecond)) {
		t.Error("expected strictly-before cutoff boundary on one instant")
	}
	if s.AcceptsSchedule(1) || !s.AcceptsSchedule(2) || s.AcceptsSchedule(3) || s.AcceptsSchedule(0) {
		t.Error("expected latest positive schedule version only")
	}
	if (core.Session{}).BookingOpen(start) || (core.Session{}).DisplayWIB() != "Not scheduled" {
		t.Error("unscheduled values must not imply an available schedule")
	}
}
func TestSessionsCreatePersistsNormalizedValuesAndActor(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		in := command(f)
		in.StartsAt = in.StartsAt.In(time.FixedZone("WIB", 7*60*60))
		in.CutoffAt = in.CutoffAt.In(time.FixedZone("WIB", 7*60*60))
		s, err := f.service.Create(ctx, f.actor, in)
		if err != nil {
			t.Fatalf("expected creation, got %v", err)
		}
		if s.Version != 1 || s.ScheduleVersion != 1 || s.HostReady || s.Capacity != 20 || s.AssignedStaffID != f.actor.UserID || !s.StartsAt.Equal(in.StartsAt) || s.StartsAt.Location() != time.UTC {
			t.Error("expected normalized UTC persisted initial values")
		}
		var actor string
		if err = f.store.Pool.QueryRow(ctx, "select actor_id::text from audit_events where object_id=$1 and action='session_created'", s.ID).Scan(&actor); err != nil || actor != string(f.actor.UserID) {
			t.Error("expected immutable initiating staff audit attribution")
		}
		if count(t, f, "select count(*) from session_schedule_history where session_id=$1 and schedule_version=1", s.ID) != 1 || count(t, f, "select count(*) from outbox where object_id=$1 and schedule_version=1", s.ID) != 1 {
			t.Error("expected one atomic history and versioned outbox event")
		}
	})
}
func TestClockDoesNotImplyHostReady(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		s := create(t, f, ctx)
		if s.HostReady {
			t.Error("clock must not imply host readiness")
		}
		if err := f.service.SetHostReady(ctx, f.actor, s.ID, true); err != nil {
			t.Fatalf("expected explicit readiness: %v", err)
		}
		if err := f.service.SetHostReady(ctx, f.actor, s.ID, true); err != nil {
			t.Fatal(err)
		}
		var ready bool
		var version, schedule int64
		if err := f.store.Pool.QueryRow(ctx, "select host_ready,version,schedule_version from sessions where id=$1", s.ID).Scan(&ready, &version, &schedule); err != nil {
			t.Fatal(err)
		}
		if !ready || version != 2 || schedule != 1 || count(t, f, "select count(*) from audit_events where object_id=$1 and action='session_host_ready_changed'", s.ID) != 1 {
			t.Error("expected explicit idempotent readiness separate from schedule revision")
		}
		if count(t, f, "select count(*) from registrations where attendance_state <> 'NOT_CHECKED_IN'") != 0 {
			t.Error("readiness changed attendance")
		}
	})
}
func TestRescheduleIncrementsVersionAndPreservesHistory(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		s := create(t, f, ctx)
		if err := f.service.SetHostReady(ctx, f.actor, s.ID, true); err != nil {
			t.Fatal(err)
		}
		in := change(s)
		next, err := f.service.Reschedule(ctx, f.actor, s.ID, in)
		if err != nil {
			t.Fatalf("expected reschedule: %v", err)
		}
		if next.ScheduleVersion != 2 || next.Version != 3 || next.HostReady || !next.StartsAt.Equal(in.StartsAt) || next.MeetingReference != in.MeetingReference || next.AcceptsSchedule(s.ScheduleVersion) {
			t.Error("expected incremented latest schedule and invalidated readiness/old-version authorization")
		}
		var prior, nextStart time.Time
		var actor, reason string
		if err = f.store.Pool.QueryRow(ctx, "select starts_at from session_schedule_history where session_id=$1 and schedule_version=1", s.ID).Scan(&prior); err != nil {
			t.Fatal(err)
		}
		if err = f.store.Pool.QueryRow(ctx, "select starts_at,actor_id::text,reason from session_schedule_history where session_id=$1 and schedule_version=2", s.ID).Scan(&nextStart, &actor, &reason); err != nil {
			t.Fatal(err)
		}
		if !prior.Equal(s.StartsAt) || !nextStart.Equal(in.StartsAt) || actor != string(f.actor.UserID) || reason != in.Reason {
			t.Error("expected complete actor-bound preserved schedule snapshots")
		}
		if _, err = f.service.Reschedule(ctx, f.actor, s.ID, in); !errors.Is(err, ErrConflict) {
			t.Errorf("expected stale schedule conflict: %v", err)
		}
		if count(t, f, "select count(*) from session_schedule_history where session_id=$1", s.ID) != 2 {
			t.Error("conflict wrote history")
		}
		if _, err = f.store.Pool.Exec(ctx, "update session_schedule_history set reason='tampered' where session_id=$1", s.ID); err == nil {
			t.Error("immutable schedule history can be modified")
		}
		if _, err = f.store.Pool.Exec(ctx, "delete from session_schedule_history where session_id=$1", s.ID); err == nil {
			t.Error("immutable schedule history can be deleted")
		}
	})
}
func TestSessionsRejectForgedAuthorityAndDifferentServiceProof(t *testing.T) {
	f := testFixture(t)
	if _, err := f.service.Create(context.Background(), f.actor, command(f)); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Errorf("expected bare actor rejection: %v", err)
	}
	f.authorized(t, func(ctx context.Context) {
		bad := f.actor
		bad.UserID = id(t)
		if _, err := f.service.Create(ctx, bad, command(f)); !errors.Is(err, auth.ErrForbidden) {
			t.Errorf("expected forged actor rejection: %v", err)
		}
		other := NewService(auth.NewService(f.store, nil))
		if _, err := other.Create(ctx, f.actor, command(f)); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("expected other-service proof rejection: %v", err)
		}
		if count(t, f, "select count(*) from sessions") != 0 {
			t.Error("forged authority wrote sessions")
		}
	})
}
func TestSessionsRecheckRevocationAndMFA(t *testing.T) {
	for _, kind := range []string{"revoked", "disabled", "mfa-expired", "mfa-future", "mfa-missing", "session-expired"} {
		t.Run(kind, func(t *testing.T) {
			f := testFixture(t)
			f.authorized(t, func(ctx context.Context) {
				switch kind {
				case "revoked":
					exec(t, f.store, "update auth_sessions set revoked_at=now()")
				case "disabled":
					exec(t, f.store, "update auth_principals set enabled=false")
				case "mfa-expired":
					exec(t, f.store, "update auth_sessions set mfa_verified_at=now()-interval '6 minutes'")
				case "mfa-future":
					exec(t, f.store, "update auth_sessions set mfa_verified_at=now()+interval '1 minute'")
				case "mfa-missing":
					exec(t, f.store, "update auth_sessions set mfa_verified_at=null")
				case "session-expired":
					exec(t, f.store, "delete from auth_staff_attestations")
					exec(t, f.store, "update auth_sessions set created_at=now()-interval '30 minutes',expires_at=now()-interval '1 minute',mfa_verified_at=now()-interval '2 minutes'")
				}
				if _, err := f.service.Create(ctx, f.actor, command(f)); err == nil || errors.Is(err, auth.ErrUnavailable) {
					t.Errorf("expected current authority denial, got %v", err)
				}
				if count(t, f, "select count(*) from sessions") != 0 {
					t.Error("stale authority wrote session")
				}
			})
		})
	}
}
func TestSessionsAuthorityRecheckedBeforeCommit(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		err := f.authority.WithStaffTx(ctx, f.actor, func(tx pgx.Tx, p core.Principal) error {
			if _, err := tx.Exec(ctx, "update auth_sessions set mfa_verified_at=now()-interval '6 minutes'"); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "insert into sessions(id,starts_at,cutoff_at,capacity) values($1,$2,$3,20)", id(t), command(f).StartsAt, command(f).CutoffAt)
			return err
		})
		if !errors.Is(err, auth.ErrForbidden) {
			t.Errorf("expected pre-commit current MFA denial: %v", err)
		}
		if count(t, f, "select count(*) from sessions") != 0 {
			t.Error("expired authority committed mutation")
		}
	})
}
func TestSessionsRejectInvalidCommandsWithoutWrites(t *testing.T) {
	f := testFixture(t)
	initialAudit := count(t, f, "select count(*) from audit_events")
	mutations := []struct {
		name string
		edit func(*core.SessionCommand)
	}{
		{"zero-start", func(in *core.SessionCommand) { in.StartsAt = time.Time{} }},
		{"zero-cutoff", func(in *core.SessionCommand) { in.CutoffAt = time.Time{} }},
		{"past", func(in *core.SessionCommand) {
			in.StartsAt = time.Now().Add(-time.Hour)
			in.CutoffAt = in.StartsAt.Add(-time.Hour)
		}},
		{"after-start", func(in *core.SessionCommand) { in.CutoffAt = in.StartsAt.Add(time.Minute) }},
		{"closed-cutoff", func(in *core.SessionCommand) { in.CutoffAt = time.Now().Add(-time.Minute) }},
		{"capacity", func(in *core.SessionCommand) { in.Capacity = 0 }},
		{"bad-staff-id", func(in *core.SessionCommand) { in.AssignedStaffID = "not-an-id" }},
		{"unknown-staff", func(in *core.SessionCommand) { in.AssignedStaffID = id(t) }},
		{"empty-guide", func(in *core.SessionCommand) { in.GuideReference = "" }},
		{"oversize-guide", func(in *core.SessionCommand) { in.GuideReference = strings.Repeat("a", 129) }},
		{"secret-url", func(in *core.SessionCommand) { in.MeetingReference = "https://meeting.invalid/?password=secret" }},
	}
	f.authorized(t, func(ctx context.Context) {
		for _, tc := range mutations {
			t.Run(tc.name, func(t *testing.T) {
				in := command(f)
				tc.edit(&in)
				if _, err := f.service.Create(ctx, f.actor, in); !errors.Is(err, ErrInvalidInput) {
					t.Errorf("expected invalid input, got %v", err)
				}
			})
		}
		if count(t, f, "select count(*) from sessions") != 0 || count(t, f, "select count(*) from audit_events") != initialAudit || count(t, f, "select count(*) from outbox") != 0 {
			t.Error("invalid input wrote partial state")
		}
	})
}
func TestSessionsAtomicRollbackOnOutboxFailure(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		s := create(t, f, ctx)
		exec(t, f.store, "CREATE FUNCTION reject_test_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected session outbox failure'; END $$; CREATE TRIGGER reject_test_outbox BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_test_outbox()")
		if _, err := f.service.Reschedule(ctx, f.actor, s.ID, change(s)); !errors.Is(err, auth.ErrUnavailable) {
			t.Errorf("expected safe atomic failure, got %v", err)
		}
		var version int64
		var start time.Time
		if err := f.store.Pool.QueryRow(ctx, "select schedule_version,starts_at from sessions where id=$1", s.ID).Scan(&version, &start); err != nil {
			t.Fatal(err)
		}
		if version != 1 || !start.Equal(s.StartsAt) || count(t, f, "select count(*) from session_schedule_history where session_id=$1", s.ID) != 1 || count(t, f, "select count(*) from audit_events where object_id=$1", s.ID) != 1 || count(t, f, "select count(*) from outbox where object_id=$1", s.ID) != 1 {
			t.Error("downstream failure left partial session/history/audit/outbox state")
		}
	})
}
func TestRescheduleConcurrentExpectedVersion(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		s := create(t, f, ctx)
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, err := f.service.Reschedule(ctx, f.actor, s.ID, change(s)); errs <- err }()
		}
		wg.Wait()
		close(errs)
		success, conflict := 0, 0
		for err := range errs {
			if err == nil {
				success++
			} else if errors.Is(err, ErrConflict) {
				conflict++
			} else {
				t.Errorf("unexpected concurrent failure: %v", err)
			}
		}
		if success != 1 || conflict != 1 || count(t, f, "select count(*) from session_schedule_history where session_id=$1", s.ID) != 2 {
			t.Error("expected one schedule commit and one conflict with intact history")
		}
	})
}
func TestSessionsCancelledContextCannotCommit(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := f.service.Create(cancelled, f.actor, command(f)); err == nil {
			t.Error("cancelled operation committed")
		}
		if count(t, f, "select count(*) from sessions") != 0 {
			t.Error("cancelled operation left mutation")
		}
	})
}
func TestSessionsLegacyHistoryMigrationIsRepeatable(t *testing.T) {
	f := testFixture(t)
	// Reconstruct the pre-v4 legacy boundary inside this owned schema, not the shared/development DB.
	exec(t, f.store, "drop table if exists session_schedule_history; delete from schema_versions where version=4")
	legacy := id(t)
	start := command(f).StartsAt
	exec(t, f.store, "insert into sessions(id,starts_at,cutoff_at,capacity,host_ready) values($1,$2,$3,10,true)", legacy, start, start.Add(-time.Hour))
	if err := f.store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count(t, f, "select count(*) from schema_versions where version=4") != 1 {
		t.Fatal("expected additive v4 sessions migration")
	}
	if count(t, f, "select count(*) from session_schedule_history where session_id=$1 and schedule_version=1 and actor_id is null and reason='legacy_snapshot'", legacy) != 1 {
		t.Error("expected one explicit legacy snapshot without fabricated actor")
	}
	f.authorized(t, func(ctx context.Context) {
		in := change(core.Session{StartsAt: start, CutoffAt: start.Add(-time.Hour), ScheduleVersion: 1, AssignedStaffID: f.actor.UserID})
		next, err := f.service.Reschedule(ctx, f.actor, legacy, in)
		if err != nil || next.ScheduleVersion != 2 || next.HostReady {
			t.Fatalf("legacy reschedule incompatible: %v", err)
		}
	})
}
