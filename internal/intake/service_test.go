package intake

import (
	"context"
	"errors"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReturningParticipantKeepsTwoAttempts(t *testing.T) {
	f := testFixture(t, core.RoleParticipant)
	a := input(f, "a")
	a.PersonReference = ""
	a.ParticipantID = f.actor.ParticipantID
	first := accepted(t, f, a)
	b := a
	b.EventReference = "event-b"
	b.OrderReference = "order-b"
	second := accepted(t, f, b)
	if first.ID == second.ID || first.ParticipantID != f.actor.ParticipantID || second.ParticipantID != first.ParticipantID {
		t.Fatal("returning person must retain two separate attempts")
	}
	for _, r := range []core.Registration{first, second} {
		if r.State != core.RegistrationDraft || r.ExternalRegistrationState != "NOT_REGISTERED" || r.PartnerID != "" {
			t.Fatal("intake falsely confirmed/attributed/enrolled")
		}
	}
	persist(t, f.store, "update registrations set result_state='RELEASED' where id=$1", first.ID)
	if count(t, f, "select count(*) from registrations where id=$1 and result_state='NOT_RECEIVED'", second.ID) != 1 {
		t.Fatal("attempt result state overwritten")
	}
	var email string
	if err := f.store.Pool.QueryRow(context.Background(), "select email from participants where id=$1", f.actor.ParticipantID).Scan(&email); err != nil || email != "original@example.invalid" {
		t.Fatal("intake rebound returning contact")
	}
	if count(t, f, "select count(*) from participants") != 1 {
		t.Fatal("returning identity duplicated")
	}
}
func TestSharedPhoneCreatesDistinctParticipants(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	first := accepted(t, f, input(f, "a"))
	second := accepted(t, f, input(f, "b"))
	if first.ParticipantID == second.ParticipantID || first.ID == second.ID {
		t.Fatal("shared contact merged people")
	}
	if count(t, f, "select count(*) from participants where email='new@example.invalid' and phone='shared-phone'") != 2 {
		t.Fatal("expected two people with shared contacts")
	}
}
func TestPartnerAttributionIsTrusted(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	first := accepted(t, f, input(f, "a"))
	if first.PartnerID != f.actor.PartnerID {
		t.Fatal("partner not derived from trusted current session")
	}
	for _, field := range []string{"partner", "participant"} {
		t.Run(field, func(t *testing.T) {
			in := input(f, field)
			if field == "partner" {
				in.PartnerID = newID(t)
			} else {
				in.ParticipantID = first.ParticipantID
			}
			_, err := f.submit(t, in)
			if !errors.Is(err, auth.ErrForbidden) {
				t.Fatalf("expected forged attribution denial: %v", err)
			}
		})
	}
	if count(t, f, "select count(*) from registrations") != 1 {
		t.Fatal("forged attribution created records")
	}
	f.proof(t, func(ctx context.Context) {
		if !errors.Is(f.authority.AuthorizeParticipant(ctx, first.ParticipantID), auth.ErrForbidden) {
			t.Fatal("unreviewed partner view activated")
		}
	})
}
func TestPartnerReplayAndConflict(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	in := input(f, "replay")
	first := accepted(t, f, in)
	again := accepted(t, f, in)
	if first != again {
		t.Fatal("exact retry did not return immutable original outcome")
	}
	bad := in
	bad.Name = "Conflicting Synthetic Person"
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := f.submit(t, bad); !errors.Is(err, core.ErrConflict) {
			t.Fatalf("expected conflict hold: %v", err)
		}
	}
	if count(t, f, "select count(*) from registrations") != 1 || count(t, f, "select count(*) from inbound_receipts") != 1 || count(t, f, "select count(*) from intake_conflicts") != 1 || count(t, f, "select count(*) from audit_events where action='intake_conflict'") != 1 {
		t.Fatal("conflict audit not durable/bounded or original overwritten")
	}
	if accepted(t, f, in) != first {
		t.Fatal("conflicting reuse changed original accepted attempt")
	}
}
func TestIntakePartnerExactPersonReferenceReturnsSeparateAttempts(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	a := input(f, "a")
	b := input(f, "b")
	b.PersonReference = a.PersonReference
	first := accepted(t, f, a)
	second := accepted(t, f, b)
	if first.ParticipantID != second.ParticipantID || first.ID == second.ID {
		t.Fatal("source person binding not stable/attempt not distinct")
	}
}
func TestIntakeSourceNamespacesAreIndependent(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	in := input(f, "same")
	first := accepted(t, f, in)
	partner := newID(t)
	persist(t, f.store, "update auth_principals set partner_id=$2 where id=$1", f.actor.UserID, partner)
	second := accepted(t, f, in)
	if first.ID == second.ID || first.ParticipantID == second.ParticipantID || second.PartnerID != partner {
		t.Fatal("source namespace leaked prior partner attribution/identity")
	}
}
func TestIntakeOrderReuseHeldAndAudited(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	a := input(f, "a")
	accepted(t, f, a)
	b := input(f, "b")
	b.OrderReference = a.OrderReference
	if _, err := f.submit(t, b); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("same source order reused: %v", err)
	}
	if count(t, f, "select count(*) from registrations") != 1 || count(t, f, "select count(*) from intake_conflicts where reason='order_reuse'") != 1 {
		t.Fatal("order reuse not preserved as conflict")
	}
}
func TestIntakeConcurrentExactReplay(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	in := input(f, "concurrent")
	var wg sync.WaitGroup
	results := make(chan core.Registration, 2)
	failures := make(chan error, 2)
	f.proof(t, func(ctx context.Context) {
		for range 2 {
			wg.Go(func() { r, err := f.service.Submit(ctx, in); results <- r; failures <- err })
		}
		wg.Wait()
	})
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("concurrent exact retry failed: %v", err)
		}
	}
	var first core.ID
	for r := range results {
		if first == "" {
			first = r.ID
		} else if first != r.ID {
			t.Fatal("concurrent replay duplicated attempt")
		}
	}
	if count(t, f, "select count(*) from registrations") != 1 || count(t, f, "select count(*) from intake_person_bindings") != 1 || count(t, f, "select count(*) from outbox where event_kind='intake_created'") != 1 {
		t.Fatal("concurrent retry duplicated persisted effects")
	}
}
func TestIntakeReplayAfterCutoffAndScheduleChange(t *testing.T) {
	f := testFixture(t, core.RoleParticipant)
	in := input(f, "past")
	in.PersonReference = ""
	first := accepted(t, f, in)
	persist(t, f.store, "update sessions set starts_at=now()+interval '1 day',cutoff_at=now()-interval '1 second',schedule_version=schedule_version+1 where id=$1", f.session)
	if accepted(t, f, in) != first {
		t.Fatal("accepted retry lost after cutoff/reschedule")
	}
	later := in
	later.EventReference = "event-later"
	later.OrderReference = "order-later"
	if _, err := f.submit(t, later); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("stale schedule not rejected: %v", err)
	}
	later.ScheduleVersion = 2
	if _, err := f.submit(t, later); !errors.Is(err, core.ErrReviewRequired) {
		t.Fatalf("closed cutoff not held: %v", err)
	}
}
func TestIntakeAtomicRollback(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	persist(t, f.store, `CREATE FUNCTION reject_intake_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic downstream failure'; END $$; CREATE TRIGGER reject_intake_outbox BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_intake_outbox();`)
	if _, err := f.submit(t, input(f, "rollback")); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("expected safe downstream failure: %v", err)
	}
	for _, table := range []string{"participants", "registrations", "inbound_receipts", "intake_records", "intake_person_bindings", "audit_events", "outbox"} {
		if count(t, f, "select count(*) from "+table) != 0 {
			t.Errorf("partial transaction in %s", table)
		}
	}
}
func TestIntakeImmutableHistoryAndRepeatMigration(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	in := input(f, "immutable")
	accepted(t, f, in)
	for _, table := range []string{"intake_records", "intake_person_bindings"} {
		if _, err := f.store.Pool.Exec(context.Background(), "delete from "+table); err == nil {
			t.Errorf("%s is mutable", table)
		}
	}
	if err := f.store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count(t, f, "select count(*) from schema_versions where version=5") != 1 || count(t, f, "select count(*) from intake_records") != 1 {
		t.Fatal("repeat migration changed outcomes")
	}
}
func TestIntakeAuthorityCannotBeForgedOrReused(t *testing.T) {
	f := testFixture(t, core.RoleParticipant)
	in := input(f, "proof")
	in.PersonReference = ""
	if _, err := f.service.Submit(context.Background(), in); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("unproved source accepted: %v", err)
	}
	f.proof(t, func(ctx context.Context) {
		other := NewService(auth.NewService(f.store, nil))
		if _, err := other.Submit(ctx, in); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("proof crossed authorizer: %v", err)
		}
		persist(t, f.store, "update auth_sessions set revoked_at=now()")
		if _, err := f.service.Submit(ctx, in); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("revoked authority retained: %v", err)
		}
	})
}
func TestIntakeForeignReturningIDDenied(t *testing.T) {
	f := testFixture(t, core.RoleParticipant)
	in := input(f, "foreign")
	in.PersonReference = ""
	in.ParticipantID = newID(t)
	if _, err := f.submit(t, in); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("foreign identity permitted: %v", err)
	}
	if count(t, f, "select count(*) from registrations") != 0 {
		t.Fatal("foreign person mutation persisted")
	}
}
func TestIntakeInputBoundsAndConsent(t *testing.T) {
	cases := []struct {
		name   string
		change func(*core.IntakeCommand)
	}{
		{"event whitespace", func(in *core.IntakeCommand) { in.EventReference = " event" }},
		{"order length", func(in *core.IntakeCommand) { in.OrderReference = strings.Repeat("a", 129) }},
		{"invalid session", func(in *core.IntakeCommand) { in.SessionID = "malformed" }},
		{"zero revision", func(in *core.IntakeCommand) { in.ScheduleVersion = 0 }},
		{"name control", func(in *core.IntakeCommand) { in.Name = "synthetic\nname" }},
		{"name length", func(in *core.IntakeCommand) { in.Name = strings.Repeat("界", 121) }},
		{"email header", func(in *core.IntakeCommand) { in.Email = "Name <person@example.invalid>" }},
		{"no contact", func(in *core.IntakeCommand) { in.Email = ""; in.Phone = "" }},
		{"missing consent choice", func(in *core.IntakeCommand) { in.CommunicationConsent = nil }},
		{"missing consent reference", func(in *core.IntakeCommand) { in.ConsentVersion = "" }},
		{"future consent", func(in *core.IntakeCommand) { in.ConsentedAt = time.Now().Add(time.Hour) }},
		{"missing consent time", func(in *core.IntakeCommand) { in.ConsentedAt = time.Time{} }},
	}
	f := testFixture(t, core.RoleAdmin)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := input(f, "invalid")
			tc.change(&in)
			if _, err := f.submit(t, in); !errors.Is(err, core.ErrInvalidInput) {
				t.Fatalf("expected bounded-input refusal: %v", err)
			}
		})
	}
	in := input(f, "optout")
	no := false
	in.CommunicationConsent = &no
	accepted(t, f, in)
	if count(t, f, "select count(*) from intake_records where (consent_snapshot->>'communication')::boolean=false") != 1 {
		t.Fatal("opt-out incorrectly forced/rebound")
	}
}
func TestIntakeMFARecheckedBeforeCommit(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	persist(t, f.store, `CREATE FUNCTION stale_intake_mfa() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE auth_sessions SET mfa_verified_at=clock_timestamp()-interval '6 minutes'; RETURN NEW; END $$; CREATE TRIGGER stale_intake_mfa AFTER INSERT ON registrations FOR EACH ROW EXECUTE FUNCTION stale_intake_mfa();`)
	if _, err := f.submit(t, input(f, "expired-mfa")); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("expired current staff authority committed: %v", err)
	}
	if count(t, f, "select count(*) from registrations") != 0 {
		t.Fatal("expired MFA registration persisted")
	}
}
