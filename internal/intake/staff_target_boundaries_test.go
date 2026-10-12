package intake

import (
	"context"
	"errors"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"testing"
)

func TestStaffTargetFinalCutoffVersionRollback(t *testing.T) {
	for _, mode := range []string{"cutoff", "version", "mfa", "epoch", "seed", "outbox-fault"} {
		t.Run(mode, func(t *testing.T) {
			f := testFixture(t, core.RoleAdmin)
			person := selectedPerson(t, f)
			before := intakeEffects(t, f)
			statements := map[string]string{
				"cutoff":       "UPDATE sessions SET cutoff_at=clock_timestamp()-interval '1 second';",
				"version":      "UPDATE sessions SET schedule_version=schedule_version+1;",
				"mfa":          "UPDATE auth_sessions SET mfa_verified_at=NULL;",
				"epoch":        "UPDATE auth_staff_credentials SET credential_epoch=credential_epoch+1;",
				"seed":         "UPDATE auth_staff_factors SET encrypted_seed=decode(repeat('00',60),'hex');",
				"outbox-fault": "RAISE EXCEPTION 'synthetic bounded downstream failure';",
			}
			persist(t, f.store, "CREATE FUNCTION staff_target_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "+statements[mode]+" RETURN NEW; END $$; CREATE TRIGGER staff_target_fault AFTER INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION staff_target_fault();")
			_, err := targetSubmit(t, f, person, input(f, "final-boundary"))
			if err == nil {
				t.Fatal("late persisted-state change committed selected intake")
			}
			if mode == "cutoff" && !errors.Is(err, core.ErrReviewRequired) {
				t.Fatal("final cutoff not checked")
			}
			if mode == "version" && !errors.Is(err, core.ErrConflict) {
				t.Fatal("final schedule version not checked")
			}
			if mode == "mfa" && !errors.Is(err, auth.ErrForbidden) {
				t.Fatal("final current MFA not checked")
			}
			if before != intakeEffects(t, f) {
				t.Fatal("late failure left person/binding/registration/receipt/audit/outbox effects")
			}
			if count(t, f, "select count(*) from participants where id=$1 and display_name='Existing Person'", person) != 1 {
				t.Fatal("rollback lost the selected existing person")
			}
		})
	}
}
func TestStaffTargetReceiptCurrentSourceOnly(t *testing.T) {
	f := testFixture(t, core.RoleAdmin)
	person := selectedPerson(t, f)
	in := input(f, "receipt-scope")
	targetAccepted(t, f, person, in)
	f.proof(t, func(ctx context.Context) {
		for _, ref := range []string{"missing-event", " bad-ref"} {
			if _, err := f.service.Receipt(ctx, ref); !errors.Is(err, core.ErrInvalidInput) {
				t.Fatalf("missing/invalid receipt did not fail closed: %v", err)
			}
		}
		persist(t, f.store, "update auth_sessions set mfa_verified_at=NULL where principal_id=$1", f.actor.UserID)
		if _, err := f.service.Receipt(ctx, in.EventReference); !errors.Is(err, auth.ErrForbidden) {
			t.Fatal("receipt used earlier MFA proof")
		}
	})
	if _, err := f.service.Receipt(context.Background(), in.EventReference); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal("unprotected receipt lookup allowed")
	}
}
