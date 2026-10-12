package sessions

import (
	"context"
	"errors"
	"osee-testops-lite/internal/core"
	"strings"
	"testing"
	"time"
)

func TestSessionsMissingClockCannotOpenCutoff(t *testing.T) {
	s := core.Session{StartsAt: time.Now().Add(48 * time.Hour), CutoffAt: time.Now().Add(47 * time.Hour)}
	if s.BookingOpen(time.Time{}) {
		t.Error("missing decision instant must not open booking")
	}
}
func TestSessionsRescheduleAfterCutoffRequiresReview(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		s := create(t, f, ctx)
		exec(t, f.store, "update sessions set cutoff_at=clock_timestamp()-interval '1 minute' where id=$1", s.ID)
		_, err := f.service.Reschedule(ctx, f.actor, s.ID, change(s))
		if err == nil || err.Error() != "review_required" {
			t.Errorf("expected closed-cutoff review hold, got %v", err)
		}
		if count(t, f, "select count(*) from session_schedule_history where session_id=$1", s.ID) != 1 {
			t.Error("closed-cutoff operation wrote history")
		}
	})
}

// Use an actual assigned-principal lock and confirm the database wait before letting the cutoff expire.
func TestSessionsDecisionRechecksCutoffAfterAssignmentWait(t *testing.T) {
	for _, mode := range []string{"create", "reschedule"} {
		t.Run(mode, func(t *testing.T) {
			f := testFixture(t)
			var assigned core.ID
			if err := f.store.Pool.QueryRow(context.Background(), "select id::text from auth_principals where role='owner' and enabled").Scan(&assigned); err != nil {
				t.Fatal("genuinely enrolled synthetic assignee unavailable")
			}

			f.authorized(t, func(ctx context.Context) {
				input := command(f)
				var current core.Session
				if mode == "reschedule" {
					current = create(t, f, ctx)
				}
				locker, err := f.store.Pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer locker.Rollback(context.Background())
				if _, err = locker.Exec(ctx, "select id from auth_principals where id=$1 for update", assigned); err != nil {
					t.Fatal(err)
				}
				cutoff := time.Now().UTC().Add(600 * time.Millisecond).Truncate(time.Microsecond)
				if mode == "reschedule" {
					exec(t, f.store, "update sessions set cutoff_at=$2 where id=$1", current.ID, cutoff)
				} else {
					input.CutoffAt = cutoff
				}
				result := make(chan error, 1)
				go func() {
					if mode == "reschedule" {
						in := change(current)
						in.AssignedStaffID = assigned
						_, err := f.service.Reschedule(ctx, f.actor, current.ID, in)
						result <- err
					} else {
						input.AssignedStaffID = assigned
						_, err := f.service.Create(ctx, f.actor, input)
						result <- err
					}
				}()
				waiting := false
				limit := time.Now().Add(3 * time.Second)
				for time.Now().Before(limit) {
					var observed bool
					err = f.store.Pool.QueryRow(ctx, "select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%FROM auth_principals p%FOR SHARE%')").Scan(&observed)
					if err != nil {
						t.Fatal(err)
					}
					if observed {
						waiting = true
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				if !waiting {
					t.Fatal("expected observed PostgreSQL assignment lock wait")
				}
				if delay := time.Until(cutoff.Add(10 * time.Millisecond)); delay > 0 {
					time.Sleep(delay)
				}
				if err = locker.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-result:
					if mode == "create" && !errors.Is(err, ErrInvalidInput) {
						t.Errorf("expected expired creation cutoff denial, got %v", err)
					}
					if mode == "reschedule" && (err == nil || err.Error() != "review_required") {
						t.Errorf("expected current-cutoff review hold after lock wait, got %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("session mutation did not finish after assigned lock release")
				}
				if mode == "create" && count(t, f, "select count(*) from sessions") != 0 {
					t.Error("expired create cutoff committed")
				}
				if mode == "reschedule" && count(t, f, "select count(*) from session_schedule_history where session_id=$1", current.ID) != 1 {
					t.Error("expired existing cutoff committed reschedule")
				}
			})
		})
	}
}
func TestSessionsReasonAndUnavailableAssignmentBoundaries(t *testing.T) {
	f := testFixture(t)
	f.authorized(t, func(ctx context.Context) {
		s := create(t, f, ctx)
		for _, reason := range []string{"", "   ", "reason\nwith control", strings.Repeat("x", 501), string([]byte{0xff})} {
			in := change(s)
			in.Reason = reason
			if _, err := f.service.Reschedule(ctx, f.actor, s.ID, in); !errors.Is(err, ErrInvalidInput) {
				t.Errorf("expected invalid reason denial: %v", err)
			}
		}
		other := id(t)
		exec(t, f.store, "insert into auth_principals(id,role,enabled) values($1,'owner',false)", other)
		in := command(f)
		in.AssignedStaffID = other
		if _, err := f.service.Create(ctx, f.actor, in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected disabled staff assignment denial: %v", err)
		}
		partner := id(t)
		partnerPrincipal := id(t)
		exec(t, f.store, "insert into auth_principals(id,role,partner_id) values($1,'partner',$2)", partnerPrincipal, partner)
		in.AssignedStaffID = partnerPrincipal
		if _, err := f.service.Create(ctx, f.actor, in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected non-staff assignment denial: %v", err)
		}
		if count(t, f, "select count(*) from session_schedule_history where session_id=$1", s.ID) != 1 {
			t.Error("validation failure wrote history")
		}
	})
}
