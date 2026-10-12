package intake

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
)

func TestIntakeConcurrentOrderReuseCommitsOnlyOneAttempt(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	a := input(f, "one")
	b := input(f, "two")
	b.OrderReference = a.OrderReference
	results := make(chan error, 2)
	var wg sync.WaitGroup
	f.proof(t, func(ctx context.Context) {
		for _, in := range []core.IntakeCommand{a, b} {
			wg.Go(func() { _, err := f.service.Submit(ctx, in); results <- err })
		}
		wg.Wait()
	})
	close(results)
	passed, held := 0, 0
	for err := range results {
		if err == nil {
			passed++
		} else if errors.Is(err, core.ErrConflict) {
			held++
		} else {
			t.Fatalf("unexpected order result: %v", err)
		}
	}
	if passed != 1 || held != 1 || count(t, f, "select count(*) from participants") != 1 || count(t, f, "select count(*) from registrations") != 1 || count(t, f, "select count(*) from intake_conflicts") != 1 {
		t.Fatal("concurrent order identity created duplicate person/attempt")
	}
}

func TestIntakeReceiptWithoutOutcomeCannotClaimSuccess(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	in := input(f, "collision")
	hash, err := fingerprint(in)
	if err != nil {
		t.Fatal(err)
	}
	persist(t, f.store, "insert into inbound_receipts(id,provider,event_key,fingerprint) values($1,$2,$3,$4)", newID(t), "partner:"+string(f.actor.PartnerID), in.EventReference, hash)
	if _, err := f.submit(t, in); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("orphan/non-intake receipt claimed success: %v", err)
	}
	if count(t, f, "select count(*) from intake_conflicts where reason='receipt_collision'") != 1 || count(t, f, "select count(*) from registrations") != 0 {
		t.Fatal("receipt collision not held/audited")
	}
}

func TestIntakeCurrentAuthorityIsRequired(t *testing.T) {
	for _, mutation := range []string{"disabled", "expired", "mfa missing"} {
		t.Run(mutation, func(t *testing.T) {
			f := testFixture(t, core.RoleAdmin)
			in := input(f, "authority")
			f.proof(t, func(ctx context.Context) {
				expected := auth.ErrUnauthenticated
				switch mutation {
				case "disabled":
					persist(t, f.store, "update auth_principals set enabled=false")
				case "expired":
					persist(t, f.store, "delete from auth_staff_attestations")
					persist(t, f.store, "update auth_sessions set created_at=now()-interval '30 minutes',expires_at=now()-interval '1 minute',mfa_verified_at=now()-interval '2 minutes'")
				default:
					persist(t, f.store, "update auth_sessions set mfa_verified_at=null")
					expected = auth.ErrForbidden
				}
				if _, err := f.service.Submit(ctx, in); !errors.Is(err, expected) {
					t.Fatalf("current authority not checked: %v", err)
				}
			})
			if count(t, f, "select count(*) from registrations") != 0 {
				t.Fatal("invalid source created registration")
			}
		})
	}
}

func TestIntakeCutoffAndSessionExpiryRecheckedAfterActualWait(t *testing.T) {
	for _, boundary := range []string{"cutoff", "session expiry"} {
		t.Run(boundary, func(t *testing.T) {
			f := testFixture(t, core.RolePartner)
			in := input(f, "wait")
			until := time.Now().UTC().Add(time.Second)
			if boundary == "cutoff" {
				persist(t, f.store, "update sessions set cutoff_at=$2 where id=$1", f.session, until)
			} else {
				persist(t, f.store, "update auth_sessions set expires_at=$1", until)
			}
			lock, err := f.store.Pool.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = lock.Rollback(context.Background()) })
			if _, err = lock.Exec(context.Background(), "select id from sessions where id=$1 for update", f.session); err != nil {
				t.Fatal(err)
			}
			var result error
			f.proof(t, func(ctx context.Context) {
				deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := f.service.Submit(deadline, in); done <- err }()
				waitForRowWait(t, f, deadline)
				timer := time.NewTimer(time.Until(until) + 30*time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-deadline.Done():
					t.Fatal("bounded wait deadline")
				}
				if err := lock.Commit(deadline); err != nil {
					t.Fatal(err)
				}
				select {
				case result = <-done:
				case <-deadline.Done():
					t.Fatal("submit did not finish after lock release")
				}
			})
			want := core.ErrReviewRequired
			if boundary == "session expiry" {
				want = auth.ErrUnauthenticated
			}
			if !errors.Is(result, want) {
				t.Fatalf("expired decision committed after observed wait: %v", result)
			}
			if count(t, f, "select count(*) from registrations") != 0 || count(t, f, "select count(*) from inbound_receipts") != 0 {
				t.Fatal("expired wait left partial intake")
			}
		})
	}
}

func waitForRowWait(t *testing.T, f *fixture, ctx context.Context) {
	t.Helper()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		err := f.store.Pool.QueryRow(ctx, "select exists(select 1 from pg_stat_activity where datname=current_database() and application_name=$1 and wait_event_type='Lock' and query like '%SELECT starts_at,cutoff_at,schedule_version%')", f.store.Pool.Config().ConnConfig.RuntimeParams["application_name"]).Scan(&waiting)
		if err != nil {
			t.Fatal("lock observation failed", err)
		}
		if waiting {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("actual session row wait was not observed")
		}
	}
}

func TestIntakeLegacyRowsKeepUnknownProvenance(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	persist(t, f.store, `DROP TABLE intake_conflicts,intake_records,intake_person_bindings; ALTER TABLE participants DROP COLUMN display_name; ALTER TABLE registrations DROP COLUMN partner_id,DROP COLUMN product_reference,DROP COLUMN intake_schedule_version; DELETE FROM schema_versions WHERE version=5;`)
	person, attempt := newID(t), newID(t)
	persist(t, f.store, "insert into participants(id,email) values($1,'legacy@example.invalid')", person)
	persist(t, f.store, "insert into registrations(id,participant_id,session_id) values($1,$2,$3)", attempt, person, f.session)
	if err := f.store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count(t, f, "select count(*) from registrations where id=$1 and partner_id is null and product_reference is null and intake_schedule_version is null", attempt) != 1 || count(t, f, "select count(*) from intake_records") != 0 || count(t, f, "select count(*) from intake_person_bindings") != 0 {
		t.Fatal("legacy provenance was fabricated")
	}
	if count(t, f, "select count(*) from participants where id=$1 and display_name is null", person) != 1 {
		t.Fatal("legacy person identity fabricated")
	}
}

func TestIntakeCutoffRecheckedAfterDownstreamWork(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	persist(t, f.store, `CREATE FUNCTION close_intake_cutoff() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE sessions SET cutoff_at=clock_timestamp()-interval '1 second'; RETURN NEW; END $$; CREATE TRIGGER close_intake_cutoff AFTER INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION close_intake_cutoff();`)
	if _, err := f.submit(t, input(f, "trigger-cutoff")); !errors.Is(err, core.ErrReviewRequired) {
		t.Fatalf("changed cutoff before commit accepted: %v", err)
	}
	if count(t, f, "select count(*) from registrations") != 0 {
		t.Fatal("late decision did not roll back")
	}
}

func TestIntakeConflictAuditFailureIsNotAcknowledged(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	in := input(f, "original")
	first := accepted(t, f, in)
	persist(t, f.store, `CREATE FUNCTION reject_intake_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic conflict audit failure'; END $$; CREATE TRIGGER reject_intake_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_intake_audit();`)
	changed := in
	changed.Name = "Different Synthetic Person"
	if _, err := f.submit(t, changed); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("failed audit falsely acknowledged conflict: %v", err)
	}
	if count(t, f, "select count(*) from intake_conflicts") != 0 || accepted(t, f, in) != first {
		t.Fatal("audit failure altered original/evidence")
	}
}

func TestIntakeInitiatingActorAndVersionBoundOutbox(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	in := input(f, "audit")
	outcome := accepted(t, f, in)
	if count(t, f, "select count(*) from audit_events where object_id=$1 and actor_id=$2 and action='intake_created'", outcome.ID, f.actor.UserID) != 1 {
		t.Fatal("initiating actor lost")
	}
	if count(t, f, "select count(*) from outbox where object_id=$1 and schedule_version=1 and payload->>'registration_id'=$2 and payload->>'session_id'=$3", outcome.ID, string(outcome.ID), string(f.session)) != 1 {
		t.Fatal("outbox not bound to the accepted attempt/schedule")
	}
	hash := sha256.Sum256([]byte(f.token))
	if count(t, f, "select count(*) from auth_sessions where token_hash=$1 and mfa_verified_at is null", hash[:]) != 1 {
		t.Fatal("partner intake invented privileged MFA")
	}
}
