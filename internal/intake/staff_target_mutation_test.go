package intake

import (
	"osee-testops-lite/internal/core"
	"testing"
)

func TestStaffTargetFinalStoredPersonAndAttempt(t *testing.T) {
	for _, mode := range []string{"profile", "attempt"} {
		t.Run(mode, func(t *testing.T) {
			f := testFixture(t, core.RoleAdmin)
			person, other := selectedPerson(t, f), selectedPerson(t, f)
			before := intakeEffects(t, f)
			statement := "UPDATE participants SET display_name='Mutated profile';"
			if mode == "attempt" {
				statement = "UPDATE registrations SET participant_id='" + string(other) + "';"
			}
			persist(t, f.store, "CREATE FUNCTION mutate_staff_target() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "+statement+" RETURN NEW; END $$; CREATE TRIGGER mutate_staff_target AFTER INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION mutate_staff_target();")
			if _, err := targetSubmit(t, f, person, input(f, "stored-boundary")); err == nil {
				t.Fatal("selected-person command adopted downstream profile/attempt mutation")
			}
			if before != intakeEffects(t, f) || count(t, f, "select count(*) from participants where id=$1 and display_name='Existing Person'", person) != 1 {
				t.Fatal("downstream target mutation did not fully roll back")
			}
		})
	}
}
