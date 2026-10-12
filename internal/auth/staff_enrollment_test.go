package auth

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"sync"
	"testing"
	"time"

	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

func TestStaffBootstrapCapabilityRequired(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	password := staffCryptoPassword(t)
	for _, capability := range []string{"", "claimed-owner", "{\"role\":\"owner\"}"} {
		if result, err := f.identity.BeginEnrollment(ctx, capability, "owner.fixture", password); err == nil || result.Token != "" {
			t.Fatal("missing or claimed bootstrap capability granted enrollment")
		}
	}
	capability, err := f.identity.EnsureBootstrap(ctx)
	if err != nil || capability.Token == "" {
		t.Fatal("empty trusted instance did not create a private capability")
	}
	for _, username := range []string{"ab", " leading", "owner@example.invalid", "bad_é"} {
		if result, err := f.identity.BeginEnrollment(ctx, capability.Token, username, password); err == nil || result.Token != "" {
			t.Fatal("invalid username was silently repaired or enrolled")
		}
	}
	if result, err := f.identity.BeginEnrollment(ctx, capability.Token, "owner.fixture", "short"); err == nil || result.Token != "" {
		t.Fatal("invalid password enrolled")
	}
	pending, err := f.identity.BeginEnrollment(ctx, capability.Token, "owner.fixture", password)
	if err != nil || pending.Token == "" || pending.Token == capability.Token {
		t.Fatal("valid capability did not create a distinct pending challenge")
	}
	if result, err := f.identity.BeginEnrollment(ctx, capability.Token, "second.owner", password); err == nil || result.Token != "" {
		t.Fatal("consumed bootstrap capability was reused")
	}
	if got := staffEnrollmentCounts(t, f); got != [5]int{} {
		t.Fatal("pending bootstrap granted active staff or session authority")
	}
}

func TestStaffBootstrapConcurrentOneOwner(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	capability, err := f.identity.EnsureBootstrap(ctx)
	if err != nil {
		t.Fatal("empty trusted bootstrap failed")
	}
	password := staffCryptoPassword(t)
	pending := make(chan StaffChallenge, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, username := range []string{"owner.one", "owner.two"} {
		wg.Add(1)
		go func(username string) {
			defer wg.Done()
			<-start
			result, failure := f.identity.BeginEnrollment(ctx, capability.Token, username, password)
			if failure == nil {
				pending <- result
			}
		}(username)
	}
	close(start)
	wg.Wait()
	close(pending)
	if len(pending) != 1 {
		t.Fatal("concurrent bootstrap did not produce exactly one pending owner")
	}
	challenge := <-pending
	view, err := f.identity.EnrollmentView(ctx, challenge.Token)
	if err != nil {
		t.Fatal("winning pending factor unavailable")
	}
	code := staffSyntheticCode(t, view, f.identity.now())
	results := make(chan StaffEnrollmentResult, 2)
	start = make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, failure := f.identity.ConfirmEnrollment(ctx, challenge.Token, code)
			if failure == nil {
				results <- result
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	if len(results) != 1 || staffEnrollmentCounts(t, f) != [5]int{1, 1, 1, 1, 1} {
		t.Fatal("concurrent confirmation created multiple owner credentials/sessions/attestations")
	}
}

func TestStaffEnrollmentNoAuthorityUntilConfirmed(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	pending := staffBeginOwner(t, f, "owner.fixture", staffCryptoPassword(t))
	if got := staffEnrollmentCounts(t, f); got != [5]int{} {
		t.Fatal("password-only enrollment granted staff authority")
	}
	if _, err := f.service.Resolve(ctx, testRequest(pending.Token)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("pending challenge was accepted as an operational session")
	}
	view, err := f.identity.EnrollmentView(ctx, pending.Token)
	if err != nil {
		t.Fatal("pending new factor unavailable")
	}
	for _, code := range []string{"", "12345", "1234567", " 123456", "１２３４５６"} {
		if result, err := f.identity.ConfirmEnrollment(ctx, pending.Token, code); err == nil || result.Session.Token != "" || len(result.RecoveryCodes) != 0 {
			t.Fatal("malformed factor returned authority or recovery material")
		}
	}
	result := staffConfirmSynthetic(t, f, pending)
	if got := staffEnrollmentCounts(t, f); got != [5]int{1, 1, 1, 1, 1} {
		t.Fatal("verified enrollment did not persist exact active authority")
	}
	var recovery, audit int
	if err := f.store.Pool.QueryRow(ctx, `select (select count(*) from auth_staff_recovery where consumed_at is null and revoked_at is null),
(select count(*) from audit_events where action='staff_enrolled' and actor_id=object_id)`).Scan(&recovery, &audit); err != nil || recovery != 10 || audit != 1 {
		t.Fatal("enrollment recovery/audit transaction incomplete")
	}
	if _, err := f.identity.EnrollmentView(ctx, pending.Token); err == nil {
		t.Fatal("active seed remained retrievable from consumed pending capability")
	}
	if repeat, err := f.identity.ConfirmEnrollment(ctx, pending.Token, staffSyntheticCode(t, view, f.identity.now())); err == nil || repeat.Session.Token != "" || len(repeat.RecoveryCodes) != 0 {
		t.Fatal("confirmed enrollment or recovery material was replayed")
	}
	if result.Session.Token == pending.Token {
		t.Fatal("pending token was reused as session token")
	}
	if err := f.identity.ValidateStoredSecrets(ctx); err != nil {
		t.Fatal("stored encrypted seed did not validate under its actual key/context")
	}
	wrongKey := make([]byte, 32)
	wrong, err := NewStaffIdentity(NewService(f.store, nil), wrongKey, f.instance)
	if err != nil {
		t.Fatal("wrong-key validation fixture construction failed")
	}
	if err = wrong.ValidateStoredSecrets(ctx); err == nil {
		t.Fatal("wrong restore/master key was accepted")
	}
}

func TestStaffEnrollmentRestartExpiryAndReset(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	original, err := f.identity.EnsureBootstrap(ctx)
	if err != nil {
		t.Fatal("initial bootstrap failed")
	}
	restarted, err := NewStaffIdentity(NewService(f.store, nil), f.key, f.instance)
	if err != nil {
		t.Fatal("restart construction failed")
	}
	if result, err := restarted.EnsureBootstrap(ctx); err == nil || result.Token != "" {
		t.Fatal("restart recovered or silently rotated a digest-only capability")
	}
	f.identity = restarted
	base := time.Now().UTC()
	f.identity.now = func() time.Time { return base.Add(11 * time.Minute) }
	if result, err := f.identity.BeginEnrollment(ctx, original.Token, "owner.fixture", staffCryptoPassword(t)); err == nil || result.Token != "" {
		t.Fatal("expired bootstrap accepted")
	}
	if result, err := f.identity.EnsureBootstrap(ctx); err == nil || result.Token != "" {
		t.Fatal("expired bootstrap silently reopened")
	}
	reset, err := f.identity.ResetEmptyBootstrap(ctx)
	if err != nil || reset.Token == "" || reset.Token == original.Token {
		t.Fatal("explicit empty reset did not create a fresh capability")
	}
	pending, err := f.identity.BeginEnrollment(ctx, reset.Token, "owner.fixture", staffCryptoPassword(t))
	if err != nil {
		t.Fatal("reset capability enrollment failed")
	}
	f.identity.now = func() time.Time { return base.Add(17 * time.Minute) }
	if _, err := f.identity.EnrollmentView(ctx, pending.Token); err == nil {
		t.Fatal("expired incomplete factor stayed visible")
	}
	reset, err = f.identity.ResetEmptyBootstrap(ctx)
	if err != nil {
		t.Fatal("expired incomplete enrollment could not be explicitly reset")
	}
	if _, err := f.identity.EnrollmentView(ctx, pending.Token); err == nil {
		t.Fatal("old pending factor survived reset")
	}
	newPending, err := f.identity.BeginEnrollment(ctx, reset.Token, "owner.after_reset", staffCryptoPassword(t))
	if err != nil {
		t.Fatal("reset did not reuse the disabled pending identity safely")
	}
	staffConfirmSynthetic(t, f, newPending)
	if result, err := f.identity.ResetEmptyBootstrap(ctx); err == nil || result.Token != "" {
		t.Fatal("active owner bootstrap was reopened")
	}
	testExec(t, f.store, "update auth_principals set enabled=false where role='owner'")
	if result, err := f.identity.ResetEmptyBootstrap(ctx); err == nil || result.Token != "" {
		t.Fatal("finalized bootstrap reopened after direct fixture disable")
	}
}

func TestStaffQRNewPendingOnly(t *testing.T) {
	f := staffIdentityFixture(t)
	ctx := context.Background()
	pending := staffBeginOwner(t, f, "owner.fixture", staffCryptoPassword(t))
	image, err := f.identity.EnrollmentQR(ctx, pending.Token)
	if err != nil {
		t.Fatal("new pending factor QR unavailable")
	}
	decoded, err := png.Decode(bytes.NewReader(image))
	if err != nil || decoded.Bounds().Dx() != 256 || decoded.Bounds().Dy() != 256 {
		t.Fatal("pending QR was not rendered locally as the actual PNG")
	}
	var principal core.ID
	if err := f.store.Pool.QueryRow(ctx, "select principal_id::text from auth_staff_credentials").Scan(&principal); err != nil {
		t.Fatal("pending principal lookup failed")
	}
	passwordOnly, digest := testSecret(t)
	now := f.identity.now()
	testExec(t, f.store, queries.CreateStaffChallenge, testID(t), f.instance, principal, "owner", "login", digest, int64(1), int64(1), nil, nil, nil, nil, now, now.Add(5*time.Minute))
	if _, err := f.identity.EnrollmentView(ctx, passwordOnly); err == nil {
		t.Fatal("password-only login exposed an existing or pending factor")
	}
	if _, err := f.identity.EnrollmentQR(ctx, passwordOnly); err == nil {
		t.Fatal("password-only login rendered factor QR")
	}
	staffConfirmSynthetic(t, f, pending)
	if _, err := f.identity.EnrollmentQR(ctx, pending.Token); err == nil {
		t.Fatal("activated factor remained available as QR")
	}
}
