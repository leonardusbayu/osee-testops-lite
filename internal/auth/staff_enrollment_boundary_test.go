package auth

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"osee-testops-lite/db/queries"
)

func TestStaffEnrollmentIssuerRevocationDeniesConfirmation(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	owner := staffConfirmSynthetic(t, f, staffBeginOwner(t, f, "owner.fixture", staffCryptoPassword(t)))
	invite := staffAdminCapability(t, f, owner.Session)
	pending, err := f.identity.BeginEnrollment(ctx, invite.Token, "admin.fixture", staffCryptoPassword(t))
	if err != nil {
		t.Fatal("synthetic bound admin setup failed")
	}
	view, err := f.identity.EnrollmentView(ctx, pending.Token)
	if err != nil {
		t.Fatal("pending admin factor unavailable")
	}
	hash, err := tokenDigest(owner.Session.Token)
	if err != nil {
		t.Fatal("synthetic owner session invalid")
	}
	testExec(t, f.store, "update auth_sessions set revoked_at=$2 where token_hash=$1", hash[:], f.identity.now())
	if _, err = f.identity.EnrollmentView(ctx, pending.Token); err == nil {
		t.Fatal("revoked issuer left recipient factor visible")
	}
	if result, err := f.identity.ConfirmEnrollment(ctx, pending.Token, staffSyntheticCode(t, view, f.identity.now())); err == nil || result.Session.Token != "" || len(result.RecoveryCodes) != 0 {
		t.Fatal("revoked issuer allowed enrollment")
	}
	if got := staffEnrollmentCounts(t, f); got != [5]int{1, 1, 1, 0, 1} {
		t.Fatal("issuer revocation produced extra credentials or sessions")
	}
}

func TestStaffEnrollmentRechecksLockedExpiry(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	pending := staffBeginOwner(t, f, "owner.fixture", staffCryptoPassword(t))
	view, err := f.identity.EnrollmentView(ctx, pending.Token)
	if err != nil {
		t.Fatal("pending factor unavailable")
	}
	base := time.Now().UTC()
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	f.identity.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	code := staffSyntheticCode(t, view, base)
	tx, err := f.store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal("synthetic lock fixture unavailable")
	}
	defer tx.Rollback(ctx)
	var instance string
	if err = tx.QueryRow(ctx, queries.LockLogicalInstance).Scan(&instance); err != nil {
		t.Fatal("synthetic instance lock failed")
	}
	done := make(chan error, 1)
	go func() {
		result, err := f.identity.ConfirmEnrollment(ctx, pending.Token, code)
		if err == nil && result.Session.Token != "" {
			done <- nil
			return
		}
		done <- err
	}()
	deadline := time.Now().Add(3 * time.Second)
	waited := false
	for time.Now().Before(deadline) {
		var blocked bool
		if err = f.store.Pool.QueryRow(ctx, "select exists(select 1 from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%app_instance%' and pid<>pg_backend_pid())").Scan(&blocked); err != nil {
			t.Fatal("actual waiting-query observation failed")
		}
		if blocked {
			waited = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waited {
		t.Fatal("confirmation did not wait on the actual persisted instance lock")
	}
	clock.Store(base.Add(6 * time.Minute).UnixNano())
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal("synthetic lock release failed")
	}
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("expired confirmation authorized after waiting")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirmation did not leave bounded lock wait")
	}
	if got := staffEnrollmentCounts(t, f); got != [5]int{} {
		t.Fatal("expired locked enrollment committed authority")
	}
}

func TestStaffEnrollmentPendingMutationRollsBack(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	pending := staffBeginOwner(t, f, "owner.fixture", staffCryptoPassword(t))
	view, err := f.identity.EnrollmentView(ctx, pending.Token)
	if err != nil {
		t.Fatal("pending factor unavailable")
	}
	testExec(t, f.store, `create function corrupt_pending_enrollment() returns trigger language plpgsql as $$
begin
if NEW.action='staff_enrolled' then
update auth_staff_challenges set encrypted_seed=decode(repeat('00',60),'hex') where kind='owner_enroll';
end if;
return NEW;
end $$;
create trigger corrupt_pending_enrollment after insert on audit_events for each row execute function corrupt_pending_enrollment();`)
	if result, err := f.identity.ConfirmEnrollment(ctx, pending.Token, staffSyntheticCode(t, view, f.identity.now())); err == nil || result.Session.Token != "" || len(result.RecoveryCodes) != 0 {
		t.Fatal("downstream pending-seed mutation was accepted")
	}
	if got := staffEnrollmentCounts(t, f); got != [5]int{} {
		t.Fatal("changed pending seed did not roll back authority")
	}
}

func TestStaffEnrollmentConstructorBindsOneSharedService(t *testing.T) {
	f := staffIdentityFixture(t)
	if f.service.staff != f.identity || f.identity.service != f.service {
		t.Fatal("genuine identity did not attach to the shared authority service")
	}
	if _, err := NewStaffIdentity(f.service, f.key, f.instance); err == nil {
		t.Fatal("shared service silently rebound genuine identity")
	}
}
