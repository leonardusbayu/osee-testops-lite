package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"osee-testops-lite/internal/core"
)

type fixtureQueue struct {
	rows      []TinyRow
	acks      []TinyAcknowledgment
	failAck   bool
	noPersist bool
	mutateAck bool
}

func (q *fixtureQueue) Rows(_ context.Context, offset, limit int) (TinyRowsPage, error) {
	end := offset + limit
	if end > len(q.rows) {
		end = len(q.rows)
	}
	return TinyRowsPage{Rows: q.rows[offset:end], Total: len(q.rows), Limit: limit, Offset: offset}, nil
}
func (q *fixtureQueue) Ack(_ context.Context, id string, ack TinyAcknowledgment) error {
	q.acks = append(q.acks, ack)
	if q.failAck {
		return ErrTinyOutcomeUnknown
	}
	if !q.noPersist {
		for i := range q.rows {
			if q.rows[i].ID == id {
				q.rows[i].Fields["queue_status"], _ = json.Marshal(ack.Status)
				q.rows[i].Fields["receipt_id"], _ = json.Marshal(ack.ReceiptID)
				q.rows[i].Fields["last_error"], _ = json.Marshal(ack.LastError)
				if q.mutateAck {
					q.rows[i].Fields["source_version"] = json.RawMessage(`"99"`)
				}
			}
		}
	}
	return nil
}
func TestQueueAcknowledgmentIsReadBackBeforeReportingCompletion(t *testing.T) {
	for _, mutated := range []bool{false, true} {
		t.Run(map[bool]string{false: "not_persisted", true: "identity_changed"}[mutated], func(t *testing.T) {
			q := &fixtureQueue{rows: []TinyRow{fixtureQueueRow(t, "PENDING")}, noPersist: !mutated, mutateAck: mutated}
			s := &fixtureSync{}
			_, err := newFixturePoller(t, q, &fixtureReceiver{}, s).Poll(context.Background())
			if !errors.Is(err, ErrQueueUnavailable) || s.mutations != 1 {
				t.Fatal("lost or changed cloud acknowledgment reported complete")
			}
		})
	}
}

type fixtureReceiver struct {
	calls int
	err   error
	empty bool
}

func (r *fixtureReceiver) Receive(_ context.Context, source, ts, signature string, body []byte) (EventReceipt, error) {
	r.calls++
	if r.empty {
		return EventReceipt{}, nil
	}
	if source != "tinycommand" || len(signature) != 67 || ts == "" {
		panic("invalid normalized hop")
	}
	return EventReceipt{ReceiptID: core.ID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"), Replayed: r.calls > 1}, r.err
}

type fixtureSync struct {
	calls, reconciles int
	uncertain         bool
	seen              map[core.ID]bool
	mutations         int
	result            *DartSyncReceipt
}

func (s *fixtureSync) Sync(_ context.Context, in DartSyncInput) (DartSyncReceipt, error) {
	s.calls++
	if s.uncertain {
		return DartSyncReceipt{State: "UNCERTAIN"}, ErrDartSyncUncertain
	}
	if s.seen == nil {
		s.seen = map[core.ID]bool{}
	}
	if !s.seen[in.ExceptionID] {
		s.mutations++
		s.seen[in.ExceptionID] = true
	}
	if s.result != nil {
		return *s.result, nil
	}
	return DartSyncReceipt{State: "SYNCED", ExceptionID: in.ExceptionID, SourceVersion: in.SourceVersion, TaskID: "validTask123", Replayed: s.calls > 1}, nil
}
func (s *fixtureSync) Reconcile(_ context.Context, id core.ID) (DartSyncReceipt, error) {
	s.reconciles++
	if s.result != nil {
		return *s.result, nil
	}
	return DartSyncReceipt{State: "SYNCED", ExceptionID: id, SourceVersion: 1, TaskID: "validTask123"}, nil
}
func TestQueueReconcileMustMatchExactSourceVersionAndIdentity(t *testing.T) {
	for _, check := range []string{"older", "newer", "identity", "task"} {
		t.Run(check, func(t *testing.T) {
			row := fixtureQueueRow(t, "NEEDS_REVIEW")
			row.Fields["last_error"] = json.RawMessage(`"DART_UNCERTAIN"`)
			var body map[string]any
			_ = json.Unmarshal([]byte(queueString(row.Fields["envelope_json"])), &body)
			body["payload"].(map[string]any)["source_version"] = float64(2)
			data, _ := json.Marshal(body)
			row.Fields["envelope_json"], _ = json.Marshal(string(data))
			row.Fields["source_version"] = json.RawMessage(`"2"`)
			result := DartSyncReceipt{State: "SYNCED", ExceptionID: core.ID("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"), SourceVersion: 2, TaskID: "validTask123"}
			switch check {
			case "older":
				result.SourceVersion = 1
			case "newer":
				result.SourceVersion = 3
			case "identity":
				result.ExceptionID = core.ID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
			case "task":
				result.TaskID = ""
			}
			q := &fixtureQueue{rows: []TinyRow{row}}
			s := &fixtureSync{result: &result}
			summary, e := newFixturePoller(t, q, &fixtureReceiver{}, s).Poll(context.Background())
			if e != nil || summary.Acknowledged != 0 || s.calls != 0 || s.reconciles != 1 {
				t.Fatal("wrong-version reconciliation acknowledged or mutated")
			}
			if check == "older" {
				if q.acks[0].Status != "RETRY_PENDING" {
					t.Fatal("resolved earlier version must allow next-version sync on later pass")
				}
			} else if q.acks[0].Status != "NEEDS_REVIEW" {
				t.Fatal("invalid mapping must be quarantined")
			}
		})
	}
}
func TestQueueMissingDurableReceiptDoesNotDispatchTask(t *testing.T) {
	q := &fixtureQueue{rows: []TinyRow{fixtureQueueRow(t, "PENDING")}}
	s := &fixtureSync{}
	summary, e := newFixturePoller(t, q, &fixtureReceiver{empty: true}, s).Poll(context.Background())
	if e != nil || summary.RetryPending != 1 || s.calls != 0 || s.reconciles != 0 {
		t.Fatal("task dispatched without durable event receipt")
	}
}
func fixtureQueueRow(t *testing.T, status string) TinyRow {
	t.Helper()
	body := `{"source":"tinycommand","event_id":"fixture-event-1","kind":"task.requested","object_id":"bbbbbbbb-cccc-4ddd-8eee-ffffffffffff","payload":{"source_version":1,"category":"automation_failure","action":"restore_integration","urgency":"normal","state":"open"}}`
	fields := map[string]json.RawMessage{}
	for k, v := range map[string]string{"source": "tinycommand", "event_id": "fixture-event-1", "kind": "task.requested", "object_id": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "source_version": "1", "queue_status": status, "envelope_json": body} {
		fields[k], _ = json.Marshal(v)
	}
	return TinyRow{ID: "fixture-row", Fields: fields}
}
func newFixturePoller(t *testing.T, q *fixtureQueue, r *fixtureReceiver, s *fixtureSync) *QueuePoller {
	t.Helper()
	p, e := NewQueuePoller(q, r, s, []byte("synthetic-shared-secret-thirty-two-bytes"))
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestQueueAckLostAfterDartSyncReplaysWithoutSecondMutation(t *testing.T) {
	q := &fixtureQueue{rows: []TinyRow{fixtureQueueRow(t, "PENDING")}, failAck: true}
	r := &fixtureReceiver{}
	s := &fixtureSync{}
	p := newFixturePoller(t, q, r, s)
	if _, e := p.Poll(context.Background()); !errors.Is(e, ErrQueueUnavailable) {
		t.Fatal("lost acknowledgment hidden")
	}
	q.failAck = false
	summary, e := p.Poll(context.Background())
	if e != nil || summary.Acknowledged != 1 || s.calls != 2 || s.mutations != 1 || q.acks[1].ReceiptID == "" {
		t.Fatal("unsafe replay after ack loss")
	}
}
func TestQueueUnverifiedTrafftObservationsDoNotDispatch(t *testing.T) {
	row := fixtureQueueRow(t, "UNVERIFIED")
	row.Fields["source"] = json.RawMessage(`"trafft"`)
	q := &fixtureQueue{rows: []TinyRow{row}}
	r := &fixtureReceiver{}
	s := &fixtureSync{}
	summary, e := newFixturePoller(t, q, r, s).Poll(context.Background())
	if e != nil || summary.Skipped != 1 || r.calls != 0 || s.calls != 0 || len(q.acks) != 0 {
		t.Fatal("unverified provider observation dispatched")
	}
}
func TestQueueUnknownDartOutcomeOnlyReconciles(t *testing.T) {
	row := fixtureQueueRow(t, "NEEDS_REVIEW")
	row.Fields["last_error"] = json.RawMessage(`"DART_UNCERTAIN"`)
	q := &fixtureQueue{rows: []TinyRow{row}}
	r := &fixtureReceiver{}
	s := &fixtureSync{}
	summary, e := newFixturePoller(t, q, r, s).Poll(context.Background())
	if e != nil || summary.Acknowledged != 1 || s.calls != 0 || s.reconciles != 1 {
		t.Fatal("uncertain mutation retried")
	}
}
func TestQueueInvalidIdentityOrPayloadIsQuarantinedBeforePersistence(t *testing.T) {
	for _, change := range []string{"object_id", "source_version", "category", "extra"} {
		t.Run(change, func(t *testing.T) {
			row := fixtureQueueRow(t, "PENDING")
			if change == "object_id" || change == "source_version" {
				row.Fields[change] = json.RawMessage(`"changed"`)
			} else {
				var body map[string]any
				_ = json.Unmarshal([]byte(queueString(row.Fields["envelope_json"])), &body)
				payload := body["payload"].(map[string]any)
				payload[change] = "private-person@example.invalid"
				data, _ := json.Marshal(body)
				row.Fields["envelope_json"], _ = json.Marshal(string(data))
			}
			q := &fixtureQueue{rows: []TinyRow{row}}
			r := &fixtureReceiver{}
			s := &fixtureSync{}
			summary, e := newFixturePoller(t, q, r, s).Poll(context.Background())
			if e != nil || summary.NeedsReview != 1 || r.calls != 0 || s.calls != 0 || q.acks[0].LastError != "EVENT_INVALID" {
				t.Fatal("hostile payload persisted or dispatched")
			}
		})
	}
}
func TestQueueEventConflictNeverSynchronizesTask(t *testing.T) {
	q := &fixtureQueue{rows: []TinyRow{fixtureQueueRow(t, "PENDING")}}
	r := &fixtureReceiver{err: ErrEventConflict}
	s := &fixtureSync{}
	summary, e := newFixturePoller(t, q, r, s).Poll(context.Background())
	if e != nil || summary.NeedsReview != 1 || s.calls != 0 || q.acks[0].LastError != "EVENT_CONFLICT" {
		t.Fatal("conflicting event acted upon")
	}
}
