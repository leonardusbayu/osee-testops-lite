package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"osee-testops-lite/internal/core"
)

type lifecycleFixture struct {
	staffLoginTestFixture
	recovery []string
}

func lifecycleOwner(t *testing.T) *lifecycleFixture {
	t.Helper()
	f := staffIdentityFixture(t)
	at := time.Now().UTC()
	f.identity.now = func() time.Time { return at }
	password := staffCryptoPassword(t)
	pending := staffBeginOwner(t, f, "owner.lifecycle", password)
	view, err := f.identity.EnrollmentView(context.Background(), pending.Token)
	if err != nil {
		t.Fatal("new synthetic factor unavailable")
	}
	enrolled, err := f.identity.ConfirmEnrollment(context.Background(), pending.Token, staffSyntheticCode(t, view, at))
	if err != nil {
		t.Fatal("genuine synthetic owner enrollment failed")
	}
	result := &lifecycleFixture{staffLoginTestFixture: staffLoginTestFixture{f, "owner.lifecycle", password, view, enrolled.Session, at.Add(30 * time.Second)}, recovery: enrolled.RecoveryCodes}
	f.identity.now = func() time.Time { return result.at }
	return result
}
func (f *lifecycleFixture) advance() { f.at = f.at.Add(30 * time.Second) }
func lifecyclePrincipal(t *testing.T, f *lifecycleFixture) core.Principal {
	t.Helper()
	p, e := f.service.CurrentPrincipal(staffLoginContext(t, f.staffIdentityTestFixture, f.session))
	if e != nil {
		t.Fatal("real synthetic authority unavailable")
	}
	return p
}
func lifecycleValue(t *testing.T, f *lifecycleFixture, query string, args ...any) int {
	t.Helper()
	var count int
	if e := f.store.Pool.QueryRow(context.Background(), query, args...).Scan(&count); e != nil {
		t.Fatal("synthetic lifecycle census failed")
	}
	return count
}

func TestStaffRecoveryOnlyReenrollment(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := context.Background()
	pending, err := f.identity.BeginRecovery(ctx, f.username, f.password, f.recovery[0], "198.51.100.1")
	if err != nil || pending.Token == "" {
		t.Fatal("password and recovery code did not start narrow reenrollment")
	}
	if lifecycleValue(t, f, "select count(*) from auth_sessions where revoked_at is null") != 0 {
		t.Fatal("recovery retained or granted session authority before new-factor proof")
	}
	if _, e := f.service.Resolve(ctx, staffCookieRequest(SessionCookieName, f.session.Token)); e == nil {
		t.Fatal("old session survived recovery start")
	}
	if _, e := f.identity.BeginRecovery(ctx, f.username, f.password, f.recovery[0], "198.51.100.2"); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("consumed recovery code reused")
	}
	view, e := f.identity.EnrollmentView(ctx, pending.Token)
	if e != nil || view.Secret == f.view.Secret {
		t.Fatal("recovery did not expose a distinct pending factor only")
	}
	if _, e = f.identity.ConfirmEnrollment(ctx, pending.Token, " 123456"); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("malformed new-factor proof was accepted")
	}
	if lifecycleValue(t, f, "select count(*) from auth_sessions where revoked_at is null") != 0 {
		t.Fatal("malformed proof created a session")
	}
	result, e := f.identity.ConfirmEnrollment(ctx, pending.Token, staffSyntheticCode(t, view, f.at))
	if e != nil || result.Session.Token == "" || len(result.RecoveryCodes) != 10 {
		t.Fatal("new authenticator did not finalize recovery")
	}
	p, e := f.service.Resolve(ctx, staffCookieRequest(SessionCookieName, result.Session.Token))
	if e != nil || !p.MFA || p.Role != core.RoleOwner {
		t.Fatal("confirmed recovery did not preserve original owner identity")
	}
	if _, e = f.identity.EnrollmentView(ctx, pending.Token); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("consumed new seed remained available")
	}
}
func TestStaffRecoveryConcurrentSingleUse(t *testing.T) {
	f := lifecycleOwner(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			p, e := f.identity.BeginRecovery(context.Background(), f.username, f.password, f.recovery[0], "198.51.100.3")
			if e == nil && p.Token == "" {
				e = ErrUnavailable
			}
			results <- e
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for e := range results {
		if e == nil {
			successes++
		} else if !errors.Is(e, ErrUnauthenticated) {
			t.Fatal("unexpected concurrent recovery outcome")
		}
	}
	if successes != 1 || lifecycleValue(t, f, "select count(*) from auth_staff_recovery where consumed_at is not null") != 1 || lifecycleValue(t, f, "select count(*) from auth_staff_challenges where kind='recovery' and consumed_at is null and revoked_at is null") != 1 {
		t.Fatal("one recovery code did not produce exactly one narrow challenge")
	}
}
func TestStaffReplacementRequiresExistingAndNewFactor(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	if _, e := f.identity.BeginReplacement(ctx, staffCryptoPassword(t), staffSyntheticCode(t, f.view, f.at)); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("wrong old password permitted replacement")
	}
	if _, e := f.identity.BeginReplacement(ctx, f.password, "12345"); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("invalid old factor permitted replacement")
	}
	pending, e := f.identity.BeginReplacement(ctx, f.password, staffSyntheticCode(t, f.view, f.at))
	if e != nil || pending.Token == "" {
		t.Fatal("real current password/factor did not start replacement")
	}
	if _, e = f.identity.BeginReplacement(ctx, f.password, staffSyntheticCode(t, f.view, f.at)); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("accepted old-factor counter was reusable")
	}
	view, e := f.identity.EnrollmentView(context.Background(), pending.Token)
	if e != nil || view.Secret == f.view.Secret {
		t.Fatal("replacement did not create a new pending seed")
	}
	if lifecycleValue(t, f, "select count(*) from auth_staff_factors where revoked_at is null") != 1 {
		t.Fatal("pending factor activated before proof")
	}
	confirmed, e := f.identity.ConfirmEnrollment(context.Background(), pending.Token, staffSyntheticCode(t, view, f.at))
	if e != nil || len(confirmed.RecoveryCodes) != 10 {
		t.Fatal("new authenticator proof did not activate replacement")
	}
	if _, e = f.service.Resolve(context.Background(), staffCookieRequest(SessionCookieName, f.session.Token)); e == nil {
		t.Fatal("old session survived factor replacement")
	}
	var principal core.ID
	var version int64
	var sealed []byte
	if e = f.store.Pool.QueryRow(context.Background(), "select principal_id::text,factor_version,encrypted_seed from auth_staff_factors where revoked_at is null").Scan(&principal, &version, &sealed); e != nil || version != 2 {
		t.Fatal("replacement version was not persisted")
	}
	if _, e = openStaffSeed(f.key, sealed, f.identity.seedAAD(principal, version)); e != nil {
		t.Fatal("new factor was not sealed under its new version")
	}
	if _, e = openStaffSeed(f.key, sealed, f.identity.seedAAD(principal, version-1)); e == nil {
		t.Fatal("replacement retained old encryption context")
	}
}
func TestStaffPasswordChangeExactAndRevoke(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	next := "  " + staffCryptoPassword(t) + " 界  "
	if e := f.identity.ChangePassword(ctx, staffCryptoPassword(t), next, staffSyntheticCode(t, f.view, f.at)); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("wrong old password accepted")
	}
	if e := f.identity.ChangePassword(ctx, f.password, "short", staffSyntheticCode(t, f.view, f.at)); !errors.Is(e, core.ErrInvalidInput) {
		t.Fatal("invalid new password accepted")
	}
	if e := f.identity.ChangePassword(ctx, f.password, next, staffSyntheticCode(t, f.view, f.at)); e != nil {
		t.Fatal("valid exact Unicode password change failed")
	}
	var encoded string
	if e := f.store.Pool.QueryRow(context.Background(), "select password_hash from auth_staff_credentials where lower(username)=lower($1)", f.username).Scan(&encoded); e != nil || !verifyStaffPassword(encoded, next) || verifyStaffPassword(encoded, strings.TrimSpace(next)) {
		t.Fatal("new password was normalized or not persisted")
	}
	if _, e := f.service.Resolve(context.Background(), staffCookieRequest(SessionCookieName, f.session.Token)); e == nil {
		t.Fatal("old session survived password change")
	}
	if _, e := f.identity.BeginLogin(context.Background(), f.username, f.password, "198.51.100.4"); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("old password still logs in")
	}
	f.advance()
	p, e := f.identity.BeginLogin(context.Background(), f.username, next, "198.51.100.4")
	if e != nil {
		t.Fatal("new password rejected at login")
	}
	if _, e = f.identity.ConfirmLogin(context.Background(), p.Token, staffSyntheticCode(t, f.view, f.at), ""); e != nil {
		t.Fatal("new password plus current factor cannot log in")
	}
}
func TestStaffAdminEnrollmentAndDisable(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	invite, e := f.identity.ProvisionAdmin(ctx, "admin.own-password", f.password, staffSyntheticCode(t, f.view, f.at))
	if e != nil || invite.Token == "" {
		t.Fatal("current owner did not provision narrow admin capability")
	}
	var id core.ID
	if e = f.store.Pool.QueryRow(context.Background(), "select principal_id::text from auth_staff_credentials where username='admin.own-password'").Scan(&id); e != nil {
		t.Fatal("pending admin credential absent")
	}
	if lifecycleValue(t, f, "select count(*) from auth_staff_credentials c join auth_principals p on p.id=c.principal_id where c.principal_id=$1 and (c.password_hash is not null or c.factor_version is not null or p.enabled)", id) != 0 {
		t.Fatal("owner chose admin credentials or activated an unenrolled admin")
	}
	f.advance()
	if e = f.identity.SetAdminEnabled(ctx, id, true, f.password, staffSyntheticCode(t, f.view, f.at)); !errors.Is(e, ErrForbidden) {
		t.Fatal("unenrolled admin was enabled")
	}
	ownPassword := staffCryptoPassword(t)
	pending, e := f.identity.BeginEnrollment(context.Background(), invite.Token, "admin.own-password", ownPassword)
	if e != nil {
		t.Fatal("admin could not choose own password")
	}
	admin := staffConfirmSynthetic(t, f.staffIdentityTestFixture, pending)
	f.advance()
	if e = f.identity.SetAdminEnabled(ctx, id, false, f.password, staffSyntheticCode(t, f.view, f.at)); e != nil {
		t.Fatal("owner could not disable enrolled admin")
	}
	if _, e = f.service.Resolve(context.Background(), staffCookieRequest(SessionCookieName, admin.Session.Token)); e == nil {
		t.Fatal("disabled admin retained authority")
	}
	f.advance()
	if e = f.identity.SetAdminEnabled(ctx, id, true, f.password, staffSyntheticCode(t, f.view, f.at)); e != nil {
		t.Fatal("enrolled admin could not be re-enabled")
	}
	if _, e = f.service.Resolve(context.Background(), staffCookieRequest(SessionCookieName, admin.Session.Token)); e == nil {
		t.Fatal("re-enable revived revoked admin cookie")
	}
}
func TestStaffLastOwnerProtected(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	p := lifecyclePrincipal(t, f)
	if e := f.identity.SetAdminEnabled(ctx, p.UserID, false, f.password, staffSyntheticCode(t, f.view, f.at)); !errors.Is(e, ErrForbidden) {
		t.Fatal("admin-control API disabled the last owner")
	}
	if lifecycleValue(t, f, "select count(*) from auth_principals where role='owner' and enabled") != 1 {
		t.Fatal("last active owner was removed")
	}
}
func TestStaffSupersededCodesAndChallengesRevoked(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := context.Background()
	login, e := f.identity.BeginLogin(ctx, f.username, f.password, "198.51.100.5")
	if e != nil {
		t.Fatal("real pending login setup failed")
	}
	pending, e := f.identity.BeginRecovery(ctx, f.username, f.password, f.recovery[0], "198.51.100.5")
	if e != nil {
		t.Fatal("valid recovery refused")
	}
	view, e := f.identity.EnrollmentView(ctx, pending.Token)
	if e != nil {
		t.Fatal("pending recovery seed unavailable")
	}
	result, e := f.identity.ConfirmEnrollment(ctx, pending.Token, staffSyntheticCode(t, view, f.at))
	if e != nil {
		t.Fatal("new recovery factor could not confirm")
	}
	if _, e = f.identity.ConfirmLogin(ctx, login.Token, staffSyntheticCode(t, f.view, f.at), ""); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("superseded login challenge survived")
	}
	if lifecycleValue(t, f, "select count(*) from auth_staff_recovery where factor_version=1 and revoked_at is null") != 0 {
		t.Fatal("superseded recovery codes remained active")
	}
	if _, e = f.identity.BeginRecovery(ctx, f.username, f.password, f.recovery[1], "198.51.100.6"); !errors.Is(e, ErrUnauthenticated) {
		t.Fatal("old recovery code remained usable")
	}
	if p, e := f.identity.BeginRecovery(ctx, f.username, f.password, result.RecoveryCodes[0], "198.51.100.6"); e != nil || p.Token == "" {
		t.Fatal("current recovery material unusable after version rotation")
	}
}
func TestStaffLifecycleAuditFailureRollsBack(t *testing.T) {
	f := lifecycleOwner(t)
	ctx := staffLoginContext(t, f.staffIdentityTestFixture, f.session)
	testExec(t, f.store, `create function lifecycle_audit_fail() returns trigger language plpgsql as $$ begin if NEW.action='staff_password_changed' then raise exception 'synthetic audit fault';end if;return NEW;end $$;create trigger lifecycle_audit_fail before insert on audit_events for each row execute function lifecycle_audit_fail()`)
	var before string
	if e := f.store.Pool.QueryRow(context.Background(), "select password_hash from auth_staff_credentials where username=$1", f.username).Scan(&before); e != nil {
		t.Fatal("prior credential unavailable")
	}
	if e := f.identity.ChangePassword(ctx, f.password, staffCryptoPassword(t), staffSyntheticCode(t, f.view, f.at)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("audit failure was not surfaced")
	}
	var after string
	if e := f.store.Pool.QueryRow(context.Background(), "select password_hash from auth_staff_credentials where username=$1", f.username).Scan(&after); e != nil || before != after {
		t.Fatal("failed audit committed credential mutation")
	}
	if p, e := f.service.Resolve(context.Background(), staffCookieRequest(SessionCookieName, f.session.Token)); e != nil || !p.MFA {
		t.Fatal("failed lifecycle write revoked valid authority")
	}
}
