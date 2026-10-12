package integrations_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"osee-testops-lite/db/migrations"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/integrations"
)

type syncProvider struct {
	escapeDescriptions                     bool
	mu                                     sync.Mutex
	tasks                                  map[string]integrations.DartTask
	creates, updates, lists, reads         int
	createErr, updateErr, readErr, listErr error
	acceptFailure                          bool
	createRaw, updateRaw, listRaw          json.RawMessage
	blockCreate, entered                   chan struct{}
}

func (p *syncProvider) CreateTask(ctx context.Context, task integrations.DartTask) (json.RawMessage, error) {
	p.mu.Lock()
	p.creates++
	id := fmt.Sprintf("%012d", p.creates)
	block, entered := p.blockCreate, p.entered
	p.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, integrations.ErrDartAmbiguous
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.createErr == nil || p.acceptFailure {
		p.tasks[id] = task
	}
	if p.createErr != nil {
		return nil, p.createErr
	}
	if p.createRaw != nil {
		return p.createRaw, nil
	}
	return json.Marshal(map[string]string{"id": id})
}

func (p *syncProvider) UpdateTask(ctx context.Context, id string, task integrations.DartTask) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updates++
	if p.updateErr == nil || p.acceptFailure {
		p.tasks[id] = task
	}
	if p.updateErr != nil {
		return nil, p.updateErr
	}
	if p.updateRaw != nil {
		return p.updateRaw, nil
	}
	return json.Marshal(map[string]string{"id": id})
}
func (p *syncProvider) Task(ctx context.Context, id string) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads++
	if p.readErr != nil {
		return nil, p.readErr
	}
	task, ok := p.tasks[id]
	if !ok {
		return nil, integrations.ErrDartUnavailable
	}
	if p.escapeDescriptions {
		task.Description = strings.ReplaceAll(task.Description, "_", `\_`)
		return json.Marshal(map[string]any{"item": struct {
			ID string `json:"id"`
			integrations.DartTask
		}{id, task}})
	}
	return json.Marshal(struct {
		ID string `json:"id"`
		integrations.DartTask
	}{id, task})
}
func (p *syncProvider) Tasks(ctx context.Context, board string) (json.RawMessage, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lists++
	if p.listErr != nil {
		return nil, p.listErr
	}
	if p.listRaw != nil {
		return p.listRaw, nil
	}
	tasks := []any{}
	for id, task := range p.tasks {
		if p.escapeDescriptions {
			task.Description = strings.ReplaceAll(task.Description, "_", `\_`)
		}
		tasks = append(tasks, struct {
			ID string `json:"id"`
			integrations.DartTask
		}{id, task})
	}
	return json.Marshal(map[string]any{"results": tasks, "total": len(tasks)})
}
func (p *syncProvider) calls() (creates, updates, reads, lists int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.creates, p.updates, p.reads, p.lists
}

func syncFixture(t *testing.T) (*integrations.DartSynchronizer, *syncProvider, *db.Store, integrations.DartSyncInput) {
	t.Helper()
	_, store := eventFixture(t)
	eventExec(t, store, migrations.DartSync)
	provider := &syncProvider{tasks: map[string]integrations.DartTask{}}
	service, err := integrations.NewDartSynchronizer(store, provider, integrations.DartSyncConfig{Dartboard: "synthetic board", Statuses: map[string]string{"open": "Todo", "in_progress": "Doing", "done": "Done"}})
	if err != nil {
		t.Fatal(err)
	}
	input := integrations.DartSyncInput{ExceptionID: eventID(t), SourceVersion: 1, Category: "payment_review", Action: "review_payment", Urgency: "high", State: "open"}
	return service, provider, store, input
}

func TestDartSyncExactVersionReplayMakesNoRemoteCall(t *testing.T) {
	service, provider, _, input := syncFixture(t)
	first, err := service.Sync(context.Background(), input)
	if err != nil || first.State != "SYNCED" || first.TaskID == "" {
		t.Fatal("operational exception was not durably synchronized")
	}
	c, u, r, l := provider.calls()
	repeated, err := service.Sync(context.Background(), input)
	ac, au, ar, al := provider.calls()
	if err != nil || !repeated.Replayed || repeated.TaskID != first.TaskID || ac != c || au != u || ar != r || al != l {
		t.Fatal("same version replay performed another remote call")
	}
}
