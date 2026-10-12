package integrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"osee-testops-lite/internal/integrations"
)

func TestDartSyncConcurrentSameExceptionCreatesOnce(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	provider.blockCreate = make(chan struct{})
	provider.entered = make(chan struct{})
	finished := make(chan error, 1)
	go func() { _, err := service.Sync(context.Background(), input); finished <- err }()
	select {
	case <-provider.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("first call did not reach provider")
	}
	errorsOut := make(chan error, 12)
	for i := 0; i < 12; i++ {
		go func() { _, err := service.Sync(context.Background(), input); errorsOut <- err }()
	}
	for i := 0; i < 12; i++ {
		if err := <-errorsOut; !errors.Is(err, integrations.ErrDartSyncBusy) {
			t.Fatal("active lease did not serialize concurrent replay")
		}
	}
	close(provider.blockCreate)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	c, u, _, _ := provider.calls()
	if c != 1 || u != 0 {
		t.Fatal("duplicate mutation reached provider")
	}
	var records int
	if err := store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM dart_exception_sync`).Scan(&records); err != nil || records != 1 {
		t.Fatal("exception mapping is not unique")
	}
}

func TestDartSyncVersionUpdateStaleAndConflict(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	first, err := service.Sync(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	changed := input
	changed.SourceVersion = 2
	changed.State = "in_progress"
	next, err := service.Sync(context.Background(), changed)
	if err != nil || next.TaskID != first.TaskID || next.SourceVersion != 2 {
		t.Fatal("new source version did not update mapped task")
	}
	c, u, r, l := provider.calls()
	if _, err = service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncStale) {
		t.Fatal("stale version accepted")
	}
	changed.Urgency = "normal"
	if _, err = service.Sync(context.Background(), changed); !errors.Is(err, integrations.ErrDartSyncConflict) {
		t.Fatal("same version altered payload accepted")
	}
	ac, au, ar, al := provider.calls()
	if c != ac || u != au || r != ar || l != al || c != 1 || u != 1 {
		t.Fatal("rejected versions invoked remote provider")
	}
}

func TestDartSyncAmbiguousAcceptedCreateReconcilesWithoutCreate(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	provider.createErr = integrations.ErrDartAmbiguous
	provider.acceptFailure = true
	receipt, err := service.Sync(context.Background(), input)
	if !errors.Is(err, integrations.ErrDartSyncUncertain) || receipt.State != "UNCERTAIN" {
		t.Fatal("unknown create was not held for reconciliation")
	}
	provider.mu.Lock()
	provider.createErr = nil
	provider.mu.Unlock()
	reconciled, err := service.Reconcile(context.Background(), input.ExceptionID)
	if err != nil || reconciled.State != "SYNCED" || reconciled.TaskID == "" {
		t.Fatal("accepted uncertain create did not recover mapping")
	}
	replay, err := service.Sync(context.Background(), input)
	if err != nil || !replay.Replayed {
		t.Fatal("reconciled mapping did not suppress replay")
	}
	c, u, _, _ := provider.calls()
	if c != 1 || u != 0 {
		t.Fatal("reconciliation repeated remote mutation")
	}
	var history int
	if err := store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM dart_exception_sync_history WHERE exception_id=$1`, input.ExceptionID).Scan(&history); err != nil || history < 4 {
		t.Fatal("durable reconciliation history missing")
	}
}

func TestDartSyncUnknownCreateWithEmptySearchNeverRetries(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	provider.createErr = integrations.ErrDartAmbiguous
	if _, err := service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("ambiguous outcome accepted")
	}
	provider.mu.Lock()
	provider.createErr = nil
	provider.mu.Unlock()
	for i := 0; i < 2; i++ {
		receipt, err := service.Sync(context.Background(), input)
		if !errors.Is(err, integrations.ErrDartSyncUncertain) || receipt.State != "UNCERTAIN" {
			t.Fatal("empty search incorrectly proved unknown mutation absent")
		}
	}
	changed := input
	changed.SourceVersion = 2
	if _, err := service.Sync(context.Background(), changed); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("new version overwrote unresolved mutation")
	}
	c, _, _, _ := provider.calls()
	if c != 1 {
		t.Fatal("uncertain remote create was retried")
	}
}

func TestDartSyncPredispatchUnavailableCanRetry(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	provider.createErr = integrations.ErrDartUnavailable
	receipt, err := service.Sync(context.Background(), input)
	if !errors.Is(err, integrations.ErrDartUnavailable) || receipt.State != "PENDING" {
		t.Fatal("definite predispatch failure did not remain pending")
	}
	provider.mu.Lock()
	provider.createErr = nil
	provider.mu.Unlock()
	if receipt, err = service.Sync(context.Background(), input); err != nil || receipt.State != "SYNCED" {
		t.Fatal("safe predispatch retry failed")
	}
	c, _, _, _ := provider.calls()
	if c != 2 {
		t.Fatal("safe retry not attempted")
	}
}

func TestDartSyncAmbiguousUpdateReconcilesExactVersion(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	first, err := service.Sync(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	input.SourceVersion = 2
	input.State = "done"
	provider.updateErr = integrations.ErrDartAmbiguous
	provider.acceptFailure = true
	receipt, err := service.Sync(context.Background(), input)
	if !errors.Is(err, integrations.ErrDartSyncUncertain) || receipt.TaskID != first.TaskID {
		t.Fatal("unknown update lost mapping")
	}
	provider.mu.Lock()
	provider.updateErr = nil
	provider.mu.Unlock()
	receipt, err = service.Reconcile(context.Background(), input.ExceptionID)
	if err != nil || receipt.State != "SYNCED" || receipt.SourceVersion != 2 {
		t.Fatal("exact accepted update not reconciled")
	}
	c, u, _, _ := provider.calls()
	if c != 1 || u != 1 {
		t.Fatal("reconciliation repeated update")
	}
}

func TestDartSyncAmbiguousUnappliedUpdateRemainsUncertain(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	if _, err := service.Sync(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.SourceVersion = 2
	input.State = "done"
	provider.updateErr = integrations.ErrDartAmbiguous
	if _, err := service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("unknown update accepted")
	}
	if _, err := service.Reconcile(context.Background(), input.ExceptionID); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("old remote version was mistaken for exact desired version")
	}
	_, u, _, _ := provider.calls()
	if u != 1 {
		t.Fatal("unresolved update retried")
	}
}

func TestDartSyncCrashAfterMutationIntentReconcilesOnly(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	first, err := service.Sync(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	eventExec(t, store, `UPDATE dart_exception_sync SET external_task_id=NULL,state='SYNCING',mutation_kind='create',lease_token=$2,lease_until=clock_timestamp()-interval '1 second' WHERE exception_id=$1`, input.ExceptionID, eventID(t))
	receipt, err := service.Sync(context.Background(), input)
	if err != nil || receipt.State != "SYNCED" || receipt.TaskID != first.TaskID {
		t.Fatal("crash window did not recover via marker search")
	}
	c, _, _, _ := provider.calls()
	if c != 1 {
		t.Fatal("crashed create retried blindly")
	}
}

func TestDartSyncLeaseExpiredBeforeFinishFailsClosed(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	provider.blockCreate = make(chan struct{})
	provider.entered = make(chan struct{})
	finished := make(chan error, 1)
	go func() { _, err := service.Sync(context.Background(), input); finished <- err }()
	select {
	case <-provider.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("provider did not receive operation")
	}
	eventExec(t, store, `UPDATE dart_exception_sync SET lease_until=clock_timestamp()-interval '1 second' WHERE exception_id=$1`, input.ExceptionID)
	close(provider.blockCreate)
	if err := <-finished; !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("expired worker committed synchronization")
	}
	receipt, err := service.Sync(context.Background(), input)
	if err != nil || receipt.State != "SYNCED" {
		t.Fatal("expired mutation did not reconcile")
	}
	c, _, _, _ := provider.calls()
	if c != 1 {
		t.Fatal("expired worker caused duplicate create")
	}
}

func TestDartSyncRemoteMarkerRemovalBlocksUpdate(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	first, err := service.Sync(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	task := provider.tasks[first.TaskID]
	task.Description = "edited remote task"
	provider.tasks[first.TaskID] = task
	provider.mu.Unlock()
	input.SourceVersion = 2
	if _, err = service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("mapping without ownership marker updated")
	}
	_, u, _, _ := provider.calls()
	if u != 0 {
		t.Fatal("unowned remote task mutated")
	}
}

func TestDartSyncDoneCannotChangePaymentOrResult(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	participant := eventID(t)
	eventExec(t, store, `INSERT INTO participants(id) VALUES($1)`, participant)
	eventExec(t, store, `INSERT INTO registrations(id,participant_id) VALUES($1,$2)`, input.ExceptionID, participant)
	eventExec(t, store, `INSERT INTO payments(id,minor_units,currency) VALUES($1,100,'IDR')`, input.ExceptionID)
	input.State = "done"
	if _, err := service.Sync(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"payment_allocations", "artifacts", "outbox"} {
		var count int
		if err := store.Pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("operational task changed protected domain table %s", table)
		}
	}
	var payment, result string
	if err := store.Pool.QueryRow(context.Background(), `SELECT payment_state FROM payments WHERE id=$1`, input.ExceptionID).Scan(&payment); err != nil || payment != "PENDING" {
		t.Fatal("task completion altered payment evidence")
	}
	if err := store.Pool.QueryRow(context.Background(), `SELECT result_state FROM registrations WHERE id=$1`, input.ExceptionID).Scan(&result); err != nil || result != "NOT_RECEIVED" {
		t.Fatal("task completion altered result release state")
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	for _, task := range provider.tasks {
		if task.Status != "Done" || len(task.Assignees) != 0 || !strings.Contains(task.Description, "does not verify payment or release results") {
			t.Fatal("task did not retain narrow operational scope")
		}
	}
}

func TestDartSyncReadonlyReconcileKeepsDefinitePendingRetryable(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	provider.listErr = integrations.ErrDartUnavailable
	if receipt, err := service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartUnavailable) || receipt.State != "PENDING" {
		t.Fatal("read failure lost pending operation")
	}
	provider.mu.Lock()
	provider.listErr = nil
	provider.mu.Unlock()
	if receipt, err := service.Reconcile(context.Background(), input.ExceptionID); !errors.Is(err, integrations.ErrDartUnavailable) || receipt.State != "PENDING" {
		t.Fatal("readonly empty search invented an uncertain mutation")
	}
	if receipt, err := service.Sync(context.Background(), input); err != nil || receipt.State != "SYNCED" {
		t.Fatal("definite pending operation could not resume")
	}
	c, _, _, _ := provider.calls()
	if c != 1 {
		t.Fatal("readonly reconciliation invoked create")
	}
}

func TestDartSyncExpiredScanAcceptsNewerVersionSafely(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	provider.listErr = integrations.ErrDartUnavailable
	if _, err := service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartUnavailable) {
		t.Fatal("read failure expected")
	}
	eventExec(t, store, `UPDATE dart_exception_sync SET state='SYNCING',mutation_kind='scan',lease_token=$2,lease_until=clock_timestamp()-interval '1 second' WHERE exception_id=$1`, input.ExceptionID, eventID(t))
	provider.mu.Lock()
	provider.listErr = nil
	provider.mu.Unlock()
	input.SourceVersion = 2
	if receipt, err := service.Sync(context.Background(), input); err != nil || receipt.State != "SYNCED" || receipt.SourceVersion != 2 {
		t.Fatal("expired readonly lease prevented safe newer version")
	}
	c, _, _, _ := provider.calls()
	if c != 1 {
		t.Fatal("expired scan produced duplicate create")
	}
}
