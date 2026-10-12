package integrations_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/integrations"
)

func TestDartSyncUnvalidatedFieldsRejectedBeforeProvider(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	cases := map[string]func(*integrations.DartSyncInput){
		"missing ID":          func(i *integrations.DartSyncInput) { i.ExceptionID = "" },
		"noncanonical ID":     func(i *integrations.DartSyncInput) { i.ExceptionID = core.ID(strings.ToUpper(string(i.ExceptionID))) },
		"zero ID":             func(i *integrations.DartSyncInput) { i.ExceptionID = "00000000-0000-0000-0000-000000000000" },
		"zero source version": func(i *integrations.DartSyncInput) { i.SourceVersion = 0 },
		"personal category":   func(i *integrations.DartSyncInput) { i.Category = "student@example.invalid" },
		"personal action":     func(i *integrations.DartSyncInput) { i.Action = "call +620000000" },
		"unknown urgency":     func(i *integrations.DartSyncInput) { i.Urgency = "send immediately" },
		"unknown state":       func(i *integrations.DartSyncInput) { i.State = "paid" },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			changed := input
			modify(&changed)
			if _, err := service.Sync(context.Background(), changed); !errors.Is(err, integrations.ErrDartSyncInvalid) {
				t.Fatal("invalid exception reached synchronization")
			}
		})
	}
	c, u, r, l := provider.calls()
	if c+u+r+l != 0 {
		t.Fatal("invalid input called provider")
	}
	var count int
	if err := store.Pool.QueryRow(context.Background(), `SELECT count(*) FROM dart_exception_sync`).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid exception persisted")
	}
}

func TestDartSyncIncompleteOrContradictoryListBlocksCreate(t *testing.T) {
	cases := map[string]string{
		"missing completion":      `{"results":[]}`,
		"next page":               `{"results":[],"nextToolCall":{"name":"list_tasks"}}`,
		"contradictory next page": `{"results":[],"nextToolCall":{"name":"list_tasks"},"has_more":false,"total":0}`,
		"contradictory total":     `{"results":[],"nextToolCall":null,"total":1}`,
		"contradictory more":      `{"results":[],"nextToolCall":null,"has_more":true}`,
		"cursor":                  `{"results":[],"nextToolCall":null,"next_cursor":"later"}`,
		"malformed task":          `{"results":[{"id":"invalid"}],"nextToolCall":null}`,
		"negative total":          `{"results":[],"total":-1}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			service, provider, _, input := syncFixture(t)
			provider.listRaw = json.RawMessage(raw)
			receipt, err := service.Sync(context.Background(), input)
			if !errors.Is(err, integrations.ErrDartUnavailable) || receipt.State != "PENDING" {
				t.Fatal("incomplete provider search did not remain pending")
			}
			c, u, _, _ := provider.calls()
			if c+u != 0 {
				t.Fatal("incomplete search permitted mutation")
			}
		})
	}
}

func TestDartSyncDocumentedNativeEmptyListAccepted(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	provider.listRaw = json.RawMessage(`{"count":0,"nextToolCall":null,"previousToolCall":null,"results":[],"meta":{"defaultsApplied":false}}`)
	receipt, err := service.Sync(context.Background(), input)
	if err != nil || receipt.State != "SYNCED" {
		t.Fatal("native observed list shape was not accepted")
	}
}

func TestDartSyncDuplicateRemoteMarkerBlocksAdoption(t *testing.T) {
	service, provider, store, input := syncFixture(t)
	receipt, err := service.Sync(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	provider.tasks["second000001"] = provider.tasks[receipt.TaskID]
	provider.mu.Unlock()
	eventExec(t, store, `UPDATE dart_exception_sync SET external_task_id=NULL,state='UNCERTAIN',mutation_kind='create' WHERE exception_id=$1`, input.ExceptionID)
	receipt, err = service.Reconcile(context.Background(), input.ExceptionID)
	if !errors.Is(err, integrations.ErrDartSyncConflict) || receipt.State != "UNCERTAIN" || receipt.TaskID != "" {
		t.Fatal("multiple matching tasks were arbitrarily adopted")
	}
	c, u, _, _ := provider.calls()
	if c != 1 || u != 0 {
		t.Fatal("duplicate marker search mutated remote tasks")
	}
}

func TestDartSyncMalformedCreateAcknowledgementReconciles(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	provider.createRaw = json.RawMessage(`{"success":true}`)
	receipt, err := service.Sync(context.Background(), input)
	if !errors.Is(err, integrations.ErrDartSyncUncertain) || receipt.State != "UNCERTAIN" {
		t.Fatal("create without immutable remote ID accepted")
	}
	receipt, err = service.Reconcile(context.Background(), input.ExceptionID)
	if err != nil || receipt.State != "SYNCED" {
		t.Fatal("accepted malformed response did not recover by marker")
	}
	c, _, _, _ := provider.calls()
	if c != 1 {
		t.Fatal("malformed acknowledgement caused repeated create")
	}
}

func TestDartSyncHistoryImmutable(t *testing.T) {
	service, _, store, input := syncFixture(t)
	if _, err := service.Sync(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(context.Background(), `UPDATE dart_exception_sync_history SET state='forged' WHERE exception_id=$1`, input.ExceptionID); err == nil {
		t.Fatal("audit history allowed forged update")
	}
	if _, err := store.Pool.Exec(context.Background(), `DELETE FROM dart_exception_sync_history WHERE exception_id=$1`, input.ExceptionID); err == nil {
		t.Fatal("audit history allowed deletion")
	}
}

func TestDartSyncMalformedUpdateAcknowledgementReconciles(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	if _, err := service.Sync(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.SourceVersion = 2
	input.State = "in_progress"
	provider.updateRaw = json.RawMessage(`{"success":true}`)
	receipt, err := service.Sync(context.Background(), input)
	if !errors.Is(err, integrations.ErrDartSyncUncertain) || receipt.State != "UNCERTAIN" {
		t.Fatal("update without matching remote ID accepted")
	}
	receipt, err = service.Reconcile(context.Background(), input.ExceptionID)
	if err != nil || receipt.State != "SYNCED" {
		t.Fatal("accepted update did not reconcile after malformed acknowledgement")
	}
	_, u, _, _ := provider.calls()
	if u != 1 {
		t.Fatal("malformed update acknowledgement caused repeated mutation")
	}
}
