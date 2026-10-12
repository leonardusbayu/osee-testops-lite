package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"osee-testops-lite/internal/core"
)

func TestStaffEnrollmentFinalizationAtomic(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	pending := staffBeginOwner(t, f, "owner.fixture", staffCryptoPassword(t))
	view, err := f.identity.EnrollmentView(ctx, pending.Token)
	if err != nil {
		t.Fatal("pending factor unavailable")
	}
	code := staffSyntheticCode(t, view, f.identity.now())
	var before int
	if err := f.store.Pool.QueryRow(ctx, "select count(*) from audit_events").Scan(&before); err != nil {
		t.Fatal("initial audit census failed")
	}
	testExec(t, f.store, `create function fail_staff_attestation() returns trigger language plpgsql as $$
begin raise exception 'synthetic attestation fault'; end $$;
create trigger fail_staff_attestation before insert on auth_staff_attestations
for each row execute function fail_staff_attestation();`)
	if result, err := f.identity.ConfirmEnrollment(ctx, pending.Token, code); err == nil || result.Session.Token != "" || len(result.RecoveryCodes) != 0 {
		t.Fatal("failed attestation returned authority or private recovery material")
	}
	if got := staffEnrollmentCounts(t, f); got != [5]int{} {
		t.Fatal("failed enrollment committed credentials/factor/session/attestation")
	}
	var after, consumed, recovery int
	statement := `select (select count(*) from audit_events),
(select count(*) from auth_staff_challenges where consumed_at is not null),
(select count(*) from auth_staff_recovery)`
	if err := f.store.Pool.QueryRow(ctx, statement).Scan(&after, &consumed, &recovery); err != nil || before != after || consumed != 0 || recovery != 0 {
		t.Fatal("failed enrollment leaked audit/challenge/recovery effects")
	}
	testExec(t, f.store, "drop trigger fail_staff_attestation on auth_staff_attestations; drop function fail_staff_attestation()")
	if result, err := f.identity.ConfirmEnrollment(ctx, pending.Token, code); err != nil || result.Session.Token == "" {
		t.Fatal("rolled-back factor/counter could not be retried")
	}
	if got := staffEnrollmentCounts(t, f); got != [5]int{1, 1, 1, 1, 1} {
		t.Fatal("successful retry did not produce exact single authority")
	}
}

func TestStaffAdminCapabilityCannotGrantOwner(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	ownerPending := staffBeginOwner(t, f, "owner.fixture", staffCryptoPassword(t))
	owner := staffConfirmSynthetic(t, f, ownerPending)
	invite := staffAdminCapability(t, f, owner.Session)
	password := staffCryptoPassword(t)
	if result, err := f.identity.BeginEnrollment(ctx, invite.Token, "owner.fixture", password); err == nil || result.Token != "" {
		t.Fatal("admin capability retargeted another staff identity")
	}
	pending, err := f.identity.BeginEnrollment(ctx, invite.Token, "ADMIN.fixture", password)
	if err != nil {
		t.Fatal("bound admin recipient could not set their own password")
	}
	if result, err := f.identity.BeginEnrollment(ctx, invite.Token, "admin.fixture", password); err == nil || result.Token != "" {
		t.Fatal("admin capability was reused")
	}
	result := staffConfirmSynthetic(t, f, pending)
	hash, err := tokenDigest(result.Session.Token)
	if err != nil {
		t.Fatal("admin session token invalid")
	}
	var role string
	var owners int
	statement := `select p.role,(select count(*) from auth_principals where role='owner' and enabled)
from auth_sessions s join auth_principals p on p.id=s.principal_id where s.token_hash=$1`
	if err := f.store.Pool.QueryRow(ctx, statement, hash[:]).Scan(&role, &owners); err != nil || role != "admin" || owners != 1 {
		t.Fatal("admin capability changed owner count or granted owner authority")
	}
}

func TestStaffEnrollmentSensitiveTransportRedacted(t *testing.T) {
	f := staffIdentityFixture(t)
	token, _ := testSecret(t)
	other, _ := testSecret(t)
	secret := staffCryptoPassword(t)
	values := []any{
		StaffChallenge{Token: token}, StaffEnrollmentView{Secret: secret},
		StaffSession{Token: token}, StaffEnrollmentResult{Session: StaffSession{Token: token}, RecoveryCodes: []string{other}},
		f.identity,
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal("safe metadata serialization failed")
		}
		for _, rendered := range []string{string(encoded), fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			if strings.Contains(rendered, token) || strings.Contains(rendered, secret) || strings.Contains(rendered, other) {
				t.Fatal("authentication transport leaked private material to ordinary evidence/log serialization")
			}
		}
	}
}

func TestStaffEnrollmentConstructorRefusesInvalidContext(t *testing.T) {
	f := staffIdentityFixture(t)
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := NewStaffIdentity(NewService(f.store, nil), key, f.instance); err == nil {
			t.Fatal("invalid master key accepted")
		}
	}
	if _, err := NewStaffIdentity(nil, f.key, f.instance); err == nil {
		t.Fatal("missing shared authority accepted")
	}
	if _, err := NewStaffIdentity(f.service, f.key, core.ID("claimed-instance")); err == nil {
		t.Fatal("malformed logical instance accepted")
	}
}
