package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestStaffLifecycleChallengeMutationRollback(t *testing.T) {
	for _, kind := range []string{"replacement", "recovery", "admin_invite"} {
		t.Run(kind, func(t *testing.T) {
			f := lifecycleOwner(t)
			ctx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
			statement := `create function mutate_lifecycle_pending() returns trigger language plpgsql as $$ begin if NEW.action in ('staff_factor_replacement_begun','staff_recovery_begun') then update auth_staff_challenges set encrypted_seed=decode(repeat('11',60),'hex') where consumed_at is null and revoked_at is null and kind in ('replacement','recovery');elsif NEW.action='staff_admin_provisioned' then update auth_staff_challenges set expires_at=created_at+interval '1 microsecond' where kind='admin_invite' and consumed_at is null and revoked_at is null;end if;return NEW;end $$;create trigger mutate_lifecycle_pending before insert on audit_events for each row execute function mutate_lifecycle_pending()`
			testExec(t, f.store, statement)
			var err error
			switch kind {
			case "replacement":
				_, err = f.identity.BeginReplacement(ctx, f.password, staffSyntheticCode(t, f.view, f.at))
			case "recovery":
				_, err = f.identity.BeginRecovery(context.Background(), f.username, f.password, f.recovery[0], "198.51.100.10")
			case "admin_invite":
				_, err = f.identity.ProvisionAdmin(ctx, "admin.mutation", f.password, staffSyntheticCode(t, f.view, f.at))
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("downstream trigger changed immutable pending binding without rollback")
			}
			if lifecycleValue(t, f, "select count(*) from auth_staff_challenges where kind=$1", kind) != 0 {
				t.Fatal("changed pending challenge was committed")
			}
			if p, e := f.service.Resolve(context.Background(), staffCookieRequest(SessionCookieName, f.session.Token)); e != nil || !p.MFA {
				t.Fatal("failed pending mutation revoked original authority")
			}
		})
	}
}
func TestStaffRecoveryRatesPersistAcrossRestart(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, e := f.identity.BeginRecovery(ctx, f.username, staffCryptoPassword(t), f.recovery[0], "198.51.100.11"); !errors.Is(e, ErrUnauthenticated) {
			t.Fatal("wrong recovery password was not uniformly denied")
		}
	}
	service := NewService(f.store, nil)
	identity, e := NewStaffIdentity(service, f.key, f.instance)
	if e != nil {
		t.Fatal("synthetic restart failed")
	}
	identity.now = f.identity.now
	if _, e = identity.BeginRecovery(ctx, f.username, f.password, f.recovery[0], "198.51.100.12"); !errors.Is(e, ErrRateLimited) {
		t.Fatal("restart reset persisted recovery budget")
	}
	if lifecycleValue(t, f, "select count(*) from auth_staff_recovery where consumed_at is not null") != 0 {
		t.Fatal("failure budget consumed valid recovery material")
	}
}
func TestStaffRecoveryConcurrentOwnerDisable(t *testing.T) {
	f := lifecycleOwner(t)
	ownerCtx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	invite, e := f.identity.ProvisionAdmin(ownerCtx, "admin.race", f.password, staffSyntheticCode(t, f.view, f.at))
	if e != nil {
		t.Fatal("owner provisioning setup failed")
	}
	adminPassword := staffCryptoPassword(t)
	pending, e := f.identity.BeginEnrollment(context.Background(), invite.Token, "admin.race", adminPassword)
	if e != nil {
		t.Fatal("admin recipient setup failed")
	}
	admin := staffConfirmSynthetic(t, f.staffIdentityTestFixture, pending)
	principal, e := f.service.Resolve(context.Background(), staffCookieRequest(SessionCookieName, admin.Session.Token))
	if e != nil {
		t.Fatal("admin authority setup failed")
	}
	f.advance()
	start := make(chan struct{})
	var wg sync.WaitGroup
	var recovery StaffChallenge
	var recoveryErr, disableErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		recovery, recoveryErr = f.identity.BeginRecovery(context.Background(), "admin.race", adminPassword, admin.RecoveryCodes[0], "198.51.100.13")
	}()
	go func() {
		defer wg.Done()
		<-start
		disableErr = f.identity.SetAdminEnabled(ownerCtx, principal.UserID, false, f.password, staffSyntheticCode(t, f.view, f.at))
	}()
	close(start)
	wg.Wait()
	if disableErr != nil || recoveryErr != nil && !errors.Is(recoveryErr, ErrUnauthenticated) {
		t.Fatal("concurrent disable/recovery failed outside its expected decision")
	}
	if recoveryErr == nil {
		if _, e = f.identity.EnrollmentView(context.Background(), recovery.Token); !errors.Is(e, ErrUnauthenticated) {
			t.Fatal("disabled admin kept live recovery capability")
		}
	}
	if lifecycleValue(t, f, "select count(*) from auth_principals where id=$1 and enabled", principal.UserID) != 0 || lifecycleValue(t, f, "select count(*) from auth_sessions where principal_id=$1 and revoked_at is null", principal.UserID) != 0 {
		t.Fatal("concurrent recovery re-enabled disabled authority")
	}
}
func TestStaffLifecycleInsertedChallengeBindingRollback(t *testing.T) {
	for _, kind := range []string{"replacement", "recovery", "admin_invite"} {
		t.Run(kind, func(t *testing.T) {
			f := lifecycleOwner(t)
			ctx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
			testExec(t, f.store, `create function change_lifecycle_insert() returns trigger language plpgsql as $$ begin if NEW.kind in ('replacement','recovery','admin_invite') then NEW.expires_at:=NEW.created_at+interval '1 minute';end if;return NEW;end $$;create trigger change_lifecycle_insert before insert on auth_staff_challenges for each row execute function change_lifecycle_insert()`)
			var err error
			switch kind {
			case "replacement":
				_, err = f.identity.BeginReplacement(ctx, f.password, staffSyntheticCode(t, f.view, f.at))
			case "recovery":
				_, err = f.identity.BeginRecovery(context.Background(), f.username, f.password, f.recovery[0], "198.51.100.14")
			case "admin_invite":
				_, err = f.identity.ProvisionAdmin(ctx, "admin.insert-mutated", f.password, staffSyntheticCode(t, f.view, f.at))
			}
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("insert trigger rewrote declared pending binding without rollback")
			}
			if lifecycleValue(t, f, "select count(*) from auth_staff_challenges where kind=$1", kind) != 0 {
				t.Fatal("altered inserted challenge committed")
			}
		})
	}
}

func TestStaffReplacementExpiryRefusesNewSeed(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	pending, e := f.identity.BeginReplacement(ctx, f.password, staffSyntheticCode(t, f.view, f.at))
	if e != nil {
		t.Fatal("real replacement setup failed")
	}
	f.at = f.at.Add(5 * time.Minute)
	if _, e = f.identity.EnrollmentView(context.Background(), pending.Token); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("expired pending replacement seed disclosed")
	}
	if _, e = f.identity.ConfirmEnrollment(context.Background(), pending.Token, "123456"); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("expired replacement activated")
	}
	if lifecycleValue(t, f, "select count(*) from auth_staff_factors where factor_version>1") != 0 {
		t.Fatal("expired replacement created a factor")
	}
}
