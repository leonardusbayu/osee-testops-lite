package intake

import (
	"context"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
	"testing"
)

func TestStaffTargetReviewedBindingsPrepare(t *testing.T) {
	f := testFixture(t, core.RolePartner)
	ctx := context.Background()
	conn, err := f.store.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	statements := map[string]string{"IntakeSourceLock": queries.IntakeSourceLock, "IntakeReceipt": queries.IntakeReceipt, "IntakeOrder": queries.IntakeOrder, "IntakeConflict": queries.IntakeConflict, "IntakeSession": queries.IntakeSession, "IntakePerson": queries.IntakePerson, "IntakeSelectedPerson": queries.IntakeSelectedPerson, "IntakeSelectedOutcome": queries.IntakeSelectedOutcome, "IntakeNewPerson": queries.IntakeNewPerson, "IntakeBindPerson": queries.IntakeBindPerson, "IntakeNewRegistration": queries.IntakeNewRegistration, "IntakeNewReceipt": queries.IntakeNewReceipt, "IntakeRecord": queries.IntakeRecord, "IntakeAudit": queries.IntakeAudit, "IntakeOutbox": queries.IntakeOutbox, "SessionAssignedStaff": queries.SessionAssignedStaff}
	for name, statement := range statements {
		if _, err := conn.Conn().Prepare(ctx, name, statement); err != nil {
			t.Fatalf("reviewed named query %s failed actual preparation", name)
		}
	}
}
