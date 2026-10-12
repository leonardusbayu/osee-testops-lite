package auth

import (
	"context"
	"testing"

	"osee-testops-lite/internal/core"
)

func legacySyntheticStaff(t *testing.T, role core.Role) (staffIdentityTestFixture, StaffSession, core.Principal) {
	t.Helper()
	f := staffIdentityFixture(t)
	owner := staffConfirmSynthetic(t, f, staffBeginOwner(t, f, "owner.legacy", staffCryptoPassword(t)))
	session := owner.Session
	if role == core.RoleAdmin {
		capability := staffAdminCapability(t, f, owner.Session)
		pending, err := f.identity.BeginEnrollment(context.Background(), capability.Token, "admin.fixture", staffCryptoPassword(t))
		if err != nil {
			t.Fatal("synthetic admin credential protocol failed")
		}
		session = staffConfirmSynthetic(t, f, pending).Session
	} else if role != core.RoleOwner {
		t.Fatal("synthetic staff role is not valid")
	}
	principal, err := f.service.Resolve(context.Background(), testRequest(session.Token))
	if err != nil || principal.Role != role || !principal.MFA {
		t.Fatal("real synthetic factor did not resolve requested staff authority")
	}
	return f, session, principal
}
