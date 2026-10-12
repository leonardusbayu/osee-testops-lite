package sessions

import (
	"context"
	"osee-testops-lite/internal/core"
	"testing"
)

func assignedOwner(t *testing.T, f *fixture) core.ID {
	t.Helper()
	var owner core.ID
	if err := f.store.Pool.QueryRow(context.Background(), "select id::text from auth_principals where role='owner' and enabled").Scan(&owner); err != nil {
		t.Fatal("genuine assignee fixture unavailable")
	}
	return owner
}
func TestStaffSessionAssignmentRejectsInvalidFactor(t *testing.T) {
	for _, mode := range []string{"revoked", "future", "corrupt", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := testFixture(t)
			owner := assignedOwner(t, f)
			switch mode {
			case "revoked":
				exec(t, f.store, "update auth_staff_factors set revoked_at=clock_timestamp() where principal_id=$1", owner)
			case "future":
				exec(t, f.store, "update auth_staff_factors set enrolled_at=clock_timestamp()+interval '1 day' where principal_id=$1", owner)
			case "corrupt":
				exec(t, f.store, "update auth_staff_factors set encrypted_seed=decode(repeat('00',60),'hex') where principal_id=$1", owner)
			default:
				exec(t, f.store, "update auth_staff_credentials set factor_version=null where principal_id=$1", owner)
			}
			f.authorized(t, func(ctx context.Context) {
				in := command(f)
				in.AssignedStaffID = owner
				if _, err := f.service.Create(ctx, f.actor, in); err == nil {
					t.Fatal("invalid current factor was assigned")
				}
			})
			if count(t, f, "select count(*) from sessions") != 0 || count(t, f, "select count(*) from session_schedule_history") != 0 || count(t, f, "select count(*) from outbox") != 0 {
				t.Fatal("invalid factor assignment left effects")
			}
		})
	}
}
func TestStaffSessionAssignmentRechecksDownstream(t *testing.T) {
	f := testFixture(t)
	owner := assignedOwner(t, f)
	exec(t, f.store, "CREATE FUNCTION disable_assigned_staff() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE auth_principals SET enabled=false WHERE role='owner'; RETURN NEW; END $$; CREATE TRIGGER disable_assigned_staff AFTER INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION disable_assigned_staff();")
	f.authorized(t, func(ctx context.Context) {
		in := command(f)
		in.AssignedStaffID = owner
		if _, err := f.service.Create(ctx, f.actor, in); err == nil {
			t.Fatal("late disabled assignee was committed")
		}
	})
	if count(t, f, "select count(*) from sessions") != 0 || count(t, f, "select count(*) from outbox") != 0 || count(t, f, "select count(*) from auth_principals where id=$1 and enabled", owner) != 1 {
		t.Fatal("late assignee failure did not roll back")
	}
}
