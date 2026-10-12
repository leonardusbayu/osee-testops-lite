package integrations_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"osee-testops-lite/internal/integrations"
)

func TestDartSyncNativeEscapedDescriptionAllowsVersionUpdate(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	first, err := service.Sync(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	provider.escapeDescriptions = true
	input.SourceVersion = 2
	input.State = "in_progress"
	receipt, err := service.Sync(context.Background(), input)
	if err != nil || receipt.State != "SYNCED" || receipt.TaskID != first.TaskID {
		t.Fatal("documented native underscore escapes blocked mapped version update")
	}
	c, u, _, _ := provider.calls()
	if c != 1 || u != 1 {
		t.Fatal("escaped description changed mutation identity")
	}
}

func TestDartSyncEscapedExactVersionDescriptionReconcilesUnknownCreate(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	provider.createErr = integrations.ErrDartAmbiguous
	provider.acceptFailure = true
	provider.escapeDescriptions = true
	if _, err := service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("unknown create expected")
	}
	receipt, err := service.Reconcile(context.Background(), input.ExceptionID)
	if err != nil || receipt.State != "SYNCED" || receipt.TaskID == "" {
		t.Fatal("escaped exact source description did not reconcile")
	}
	c, _, _, _ := provider.calls()
	if c != 1 {
		t.Fatal("escaped task reconciliation retried create")
	}
}

func TestDartSyncReadFailureWithoutVersionIntentRecoversExactAppliedHash(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	first, err := service.Sync(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	prior := provider.tasks[first.TaskID]
	bad := prior
	bad.Description = "temporarily missing ownership marker"
	provider.tasks[first.TaskID] = bad
	input.SourceVersion = 2
	input.State = "in_progress"
	if _, err = service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("invalid read should hold update")
	}
	var intents int
	if err = store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE object_id=$1 AND action='dart_exception_update_intent:2'`, input.ExceptionID).Scan(&intents); err != nil || intents != 0 {
		t.Fatal("read-only failure wrote mutation intent")
	}
	provider.tasks[first.TaskID] = prior
	provider.escapeDescriptions = true
	receipt, err := service.Reconcile(context.Background(), input.ExceptionID)
	if err != nil || receipt.State != "PENDING" || receipt.SourceVersion != 2 {
		t.Fatal("exact applied hash and absent version intent did not safely recover pending")
	}
	_, u, _, _ := provider.calls()
	if u != 0 {
		t.Fatal("reconciliation itself invoked update")
	}
	receipt, err = service.Sync(context.Background(), input)
	if err != nil || receipt.State != "SYNCED" || receipt.SourceVersion != 2 {
		t.Fatal("proved pending version could not resume")
	}
	c, updates, _, _ := provider.calls()
	if c != 1 || updates != 1 {
		t.Fatal("recovery duplicated operational task")
	}
}

func TestDartSyncActualUpdateIntentCannotRecoverFromOldEscapedVersion(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	if _, err := service.Sync(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	provider.escapeDescriptions = true
	provider.updateErr = integrations.ErrDartAmbiguous
	input.SourceVersion = 2
	input.State = "in_progress"
	if _, err := service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("unknown update expected")
	}
	_, u, _, _ := provider.calls()
	if u != 1 {
		t.Fatal("fixture did not dispatch one real uncertain update")
	}
	if receipt, err := service.Reconcile(context.Background(), input.ExceptionID); !errors.Is(err, integrations.ErrDartSyncUncertain) || receipt.State != "UNCERTAIN" {
		t.Fatal("old applied version falsely proved uncertain update absent")
	}
	_, after, _, _ := provider.calls()
	if after != 1 {
		t.Fatal("unknown update retried during reconciliation")
	}
}

func TestDartSyncNoIntentRecoveryRejectsChangedPriorRemoteContent(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	first, err := service.Sync(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	prior := provider.tasks[first.TaskID]
	bad := prior
	bad.Description = "temporarily missing marker"
	provider.tasks[first.TaskID] = bad
	input.SourceVersion = 2
	input.State = "in_progress"
	if _, err = service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncUncertain) {
		t.Fatal("invalid marker expected")
	}
	prior.Status = "Done"
	provider.tasks[first.TaskID] = prior
	provider.escapeDescriptions = true
	if receipt, err := service.Reconcile(context.Background(), input.ExceptionID); !errors.Is(err, integrations.ErrDartSyncUncertain) || receipt.State != "UNCERTAIN" {
		t.Fatal("changed prior content bypassed applied hash proof")
	}
	_, u, _, _ := provider.calls()
	if u != 0 {
		t.Fatal("unproved prior content allowed update")
	}
}

func TestDartSyncEscapedOrSpoofedMarkerDuplicatesRemainBlocked(t *testing.T) {
	for _, kind := range []string{"mixed_duplicate", "literal_backslash_duplicate", "different_uuid", "literal_backslash_only", "prefixed_marker"} {
		t.Run(kind, func(t *testing.T) {
			service, provider, _, input := syncFixture(t)
			first, err := service.Sync(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			task := provider.tasks[first.TaskID]
			line := strings.Split(task.Description, "\n")[0]
			switch kind {
			case "mixed_duplicate":
				task.Description += "\n" + strings.ReplaceAll(line, "_", `\_`)
			case "literal_backslash_duplicate":
				task.Description += "\n" + strings.ReplaceAll(line, "_", `\\_`)
			case "different_uuid":
				task.Description += "\nOSEE_EXCEPTION_ID=" + string(eventID(t))
			case "literal_backslash_only":
				task.Description = strings.Replace(task.Description, line, strings.ReplaceAll(line, "_", `\\_`), 1)
			case "prefixed_marker":
				task.Description = strings.Replace(task.Description, line, "copied "+strings.ReplaceAll(line, "_", `\_`), 1)
			}
			provider.tasks[first.TaskID] = task
			input.SourceVersion = 2
			if _, err = service.Sync(context.Background(), input); !errors.Is(err, integrations.ErrDartSyncUncertain) {
				t.Fatal("ambiguous marker authorized update")
			}
			_, u, _, _ := provider.calls()
			if u != 0 {
				t.Fatal("ambiguous ownership reached provider update")
			}
		})
	}
}
