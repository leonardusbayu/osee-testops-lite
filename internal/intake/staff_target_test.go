package intake

import (
	"context"
	"errors"
	"sync"
	"testing"

	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/testfixtures"
)

func selectedPerson(t *testing.T, f *fixture) core.ID {
	t.Helper()
	person := newID(t)
	persist(t, f.store, "insert into participants(id,display_name,email,phone) values($1,'Existing Person','existing@example.invalid','existing-phone')", person)
	return person
}
func targetSubmit(t *testing.T, f *fixture, person core.ID, in core.IntakeCommand) (core.Registration, error) {
	t.Helper()
	var result core.Registration
	var err error
	f.proof(t, func(ctx context.Context) { result, err = f.service.SubmitForParticipant(ctx, person, in) })
	return result, err
}
func targetAccepted(t *testing.T, f *fixture, person core.ID, in core.IntakeCommand) core.Registration {
	t.Helper()
	result, err := targetSubmit(t, f, person, in)
	if err != nil {
		t.Fatalf("selected-person attempt rejected: %v", err)
	}
	if result.ParticipantID != person || result.State != core.RegistrationDraft || result.ExternalRegistrationState != "NOT_REGISTERED" {
		t.Fatal("selection changed target or fabricated registered state")
	}
	return result
}
func intakeEffects(t *testing.T, f *fixture) [6]int {
	t.Helper()
	return [6]int{count(t, f, "select count(*) from participants"), count(t, f, "select count(*) from registrations"), count(t, f, "select count(*) from intake_person_bindings"), count(t, f, "select count(*) from inbound_receipts"), count(t, f, "select count(*) from audit_events"), count(t, f, "select count(*) from outbox")}
}
func TestStaffTargetExistingPersonAcrossAdmins(t *testing.T) {
	f := testFixture(t, core.RoleParticipant)
	person := f.actor.ParticipantID
	persist(t, f.store, "update participants set display_name='Existing Person' where id=$1", person)
	participantPrincipal := f.actor.UserID
	owner := testfixtures.NewStaff(t, f.store, core.RoleOwner)
	a := testfixtures.AddAdmin(t, f.store, owner, "selected.admin.a")
	b := testfixtures.AddAdmin(t, f.store, owner, "selected.admin.b")
	f.authority = owner.Authority
	f.service = NewService(f.authority)
	people, principals := count(t, f, "select count(*) from participants"), count(t, f, "select count(*) from auth_principals")
	fa, fb := *f, *f
	fa.actor = a.Principal
	fa.token = a.Session.Token
	fb.actor = b.Principal
	fb.token = b.Session.Token
	firstInput := input(&fa, "admin-a")
	first := targetAccepted(t, &fa, person, firstInput)
	second := targetAccepted(t, &fb, person, input(&fb, "admin-b"))
	fb.proof(t, func(ctx context.Context) {
		if _, err := fb.service.Receipt(ctx, firstInput.EventReference); !errors.Is(err, core.ErrInvalidInput) {
			t.Fatal("receipt escaped the current administrator source")
		}
	})
	if first.ID == second.ID || count(t, f, "select count(*) from participants") != people || count(t, f, "select count(*) from registrations where participant_id=$1", person) != 2 || count(t, f, "select count(*) from auth_principals") != principals {
		t.Fatal("two administrators merged identities or granted extra access")
	}
	if count(t, f, "select count(*) from auth_principals where id=$1 and participant_id=$2 and role='participant'", participantPrincipal, person) != 1 || count(t, f, "select count(*) from intake_person_bindings where participant_id=$1", person) != 2 {
		t.Fatal("participant auth ownership or explicit source binding changed")
	}
	if count(t, f, "select count(*) from audit_events where action='intake_created' and actor_id in ($1,$2)", a.Principal.UserID, b.Principal.UserID) != 2 || count(t, f, "select count(*) from outbox where event_kind='intake_created'") != 2 {
		t.Fatal("real actor or pending work provenance missing")
	}
}
func TestStaffTargetForbiddenForParticipantPartner(t *testing.T) {
	for _, role := range []core.Role{core.RoleParticipant, core.RolePartner} {
		t.Run(string(role), func(t *testing.T) {
			f := testFixture(t, role)
			person := selectedPerson(t, f)
			before := intakeEffects(t, f)
			if _, err := targetSubmit(t, f, person, input(f, "forbidden")); !errors.Is(err, auth.ErrForbidden) {
				t.Fatalf("non-staff selected target: %v", err)
			}
			if before != intakeEffects(t, f) {
				t.Fatal("forbidden selected target left effects")
			}
		})
	}
	f := testFixture(t, core.RoleAdmin)
	person := selectedPerson(t, f)
	if _, err := f.service.SubmitForParticipant(context.Background(), person, input(f, "claimed")); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("claimed context granted selected-person authority")
	}
}
func TestStaffTargetProfileAndBindingImmutable(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	person := selectedPerson(t, f)
	principal := newID(t)
	persist(t, f.store, "insert into auth_principals(id,role,participant_id) values($1,'participant',$2)", principal, person)
	in := input(f, "immutable")
	in.Name = "Caller Supplied Name"
	in.Email = "caller@example.invalid"
	in.Phone = "caller-phone"
	first := targetAccepted(t, f, person, in)
	if count(t, f, "select count(*) from participants where id=$1 and display_name='Existing Person' and email='existing@example.invalid' and phone='existing-phone'", person) != 1 || count(t, f, "select count(*) from auth_principals where id=$1 and participant_id=$2", principal, person) != 1 {
		t.Fatal("selection reassigned profile or authentication")
	}
	if count(t, f, `select count(*) from intake_records where registration_id=$1 and participant_snapshot->>'Name'='Existing Person' and participant_snapshot->>'Email'='existing@example.invalid' and participant_snapshot->>'Phone'='existing-phone'`, first.ID) != 1 {
		t.Fatal("selected snapshot trusted caller profile instead of stored profile")
	}
	secondInput := input(f, "same-source-binding")
	secondInput.PersonReference = in.PersonReference
	second := targetAccepted(t, f, person, secondInput)
	if second.ID == first.ID || count(t, f, "select count(*) from intake_person_bindings where participant_id=$1", person) != 1 {
		t.Fatal("same selected source binding was transferred or duplicated")
	}
	legacy := input(f, "legacy-claim")
	legacy.ParticipantID = person
	if _, err := f.submit(t, legacy); !errors.Is(err, auth.ErrForbidden) {
		t.Fatal("legacy claimed ParticipantID became authorized")
	}
	if _, err := targetSubmit(t, f, person, legacy); !errors.Is(err, auth.ErrForbidden) {
		t.Fatal("selected path accepted legacy provenance claim")
	}
}
func TestStaffTargetMissingAndConflictingBinding(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	first, other := selectedPerson(t, f), selectedPerson(t, f)
	for _, person := range []core.ID{"", "not-a-uuid", newID(t)} {
		before := intakeEffects(t, f)
		if _, err := targetSubmit(t, f, person, input(f, "missing")); !errors.Is(err, core.ErrInvalidInput) {
			t.Errorf("missing/invalid target not refused: %v", err)
		}
		if before != intakeEffects(t, f) {
			t.Fatal("missing target left effects")
		}
	}
	in := input(f, "binding")
	targetAccepted(t, f, first, in)
	before := intakeEffects(t, f)
	changed := input(f, "binding-reuse")
	changed.PersonReference = in.PersonReference
	if _, err := targetSubmit(t, f, other, changed); !errors.Is(err, core.ErrConflict) {
		t.Fatalf("conflicting selected binding accepted: %v", err)
	}
	if before != intakeEffects(t, f) || count(t, f, "select count(*) from intake_person_bindings where participant_id=$1", other) != 0 {
		t.Fatal("conflicting reference transferred another identity")
	}
}
func TestStaffTargetRetryAndLostReplyReceipt(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	person := selectedPerson(t, f)
	in := input(f, "lost-reply")
	before := intakeEffects(t, f)
	first := targetAccepted(t, f, person, in)
	persist(t, f.store, "update sessions set cutoff_at=clock_timestamp()-interval '1 minute',schedule_version=2 where id=$1", f.session)
	persist(t, f.store, "update participants set display_name='Later profile edit' where id=$1", person)
	retry := targetAccepted(t, f, person, in)
	var receipt core.Registration
	f.proof(t, func(ctx context.Context) {
		var err error
		receipt, err = f.service.Receipt(ctx, in.EventReference)
		if err != nil {
			t.Fatalf("persisted receipt lookup failed: %v", err)
		}
	})
	after := intakeEffects(t, f)
	if first != retry || first != receipt || after[0] != before[0] || after[1] != before[1]+1 || after[3] != before[3]+1 || after[4] != before[4]+1 || after[5] != before[5]+1 {
		t.Fatal("lost-reply retry changed immutable attempt or duplicated work")
	}
	different := selectedPerson(t, f)
	if _, err := targetSubmit(t, f, different, in); !errors.Is(err, core.ErrConflict) {
		t.Fatal("event target not included in immutable fingerprint")
	}
	changed := in
	changed.Name = "Changed fingerprint"
	if _, err := targetSubmit(t, f, person, changed); !errors.Is(err, core.ErrConflict) {
		t.Fatal("changed command fingerprint was silently replayed")
	}
	if count(t, f, "select count(*) from intake_conflicts where event_reference=$1", in.EventReference) != 2 {
		t.Fatal("changed target/command conflict evidence was not durable")
	}
}
func TestStaffTargetConcurrentReplay(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	person := selectedPerson(t, f)
	in := input(f, "concurrent")
	results := make(chan core.Registration, 6)
	failures := make(chan error, 6)
	var wg sync.WaitGroup
	f.proof(t, func(ctx context.Context) {
		for range 6 {
			wg.Go(func() {
				result, err := f.service.SubmitForParticipant(ctx, person, in)
				results <- result
				failures <- err
			})
		}
		wg.Wait()
	})
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("concurrent retry denied: %v", err)
		}
	}
	var one core.ID
	for result := range results {
		if one == "" {
			one = result.ID
		}
		if result.ID != one || result.ParticipantID != person {
			t.Fatal("concurrent retries returned different identities")
		}
	}
	if count(t, f, "select count(*) from registrations") != 1 || count(t, f, "select count(*) from outbox") != 1 || count(t, f, "select count(*) from participants where id=$1", person) != 1 {
		t.Fatal("concurrent retry duplicated effects")
	}
}
func TestStaffTargetMinimalAndLegacyUnknownProfile(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	person := newID(t)
	persist(t, f.store, "insert into participants(id) values($1)", person)
	in := input(f, "legacy-profile")
	in.Name = ""
	in.Email = ""
	in.Phone = ""
	result := targetAccepted(t, f, person, in)
	if count(t, f, `select count(*) from intake_records where registration_id=$1 and participant_snapshot->>'Name'='' and participant_snapshot->>'Email'='' and participant_snapshot->>'Phone'=''`, result.ID) != 1 || count(t, f, "select count(*) from participants where id=$1 and display_name is null and email is null and phone is null", person) != 1 {
		t.Fatal("unknown legacy profile was fabricated or overwritten")
	}
}
