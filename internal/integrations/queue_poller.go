package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"osee-testops-lite/internal/core"
)

// QueueSource is scoped to one preconfigured table. Acknowledgments change
// delivery bookkeeping only, never payment, booking, score or release fields.
type QueueSource interface {
	Rows(context.Context, int, int) (TinyRowsPage, error)
	Ack(context.Context, string, TinyAcknowledgment) error
}
type QueueEventReceiver interface {
	Receive(context.Context, string, string, string, []byte) (EventReceipt, error)
}
type QueueTaskSynchronizer interface {
	Sync(context.Context, DartSyncInput) (DartSyncReceipt, error)
	Reconcile(context.Context, core.ID) (DartSyncReceipt, error)
}
type QueuePollSummary struct {
	Examined     int `json:"examined"`
	Acknowledged int `json:"acknowledgments_submitted"`
	NeedsReview  int `json:"review_acknowledgments_submitted"`
	RetryPending int `json:"retry_acknowledgments_submitted"`
	Skipped      int `json:"skipped"`
}
type QueuePoller struct {
	mu       sync.Mutex
	queue    QueueSource
	receiver QueueEventReceiver
	tasks    QueueTaskSynchronizer
	secret   []byte
	now      func() time.Time
}

var ErrQueueUnavailable = errors.New("cloud queue unavailable; retain pending rows")

func NewQueuePoller(queue QueueSource, receiver QueueEventReceiver, tasks QueueTaskSynchronizer, secret []byte) (*QueuePoller, error) {
	if queue == nil || receiver == nil || tasks == nil || len(secret) < 32 || len(secret) > 256 {
		return nil, ErrQueueUnavailable
	}
	return &QueuePoller{queue: queue, receiver: receiver, tasks: tasks, secret: append([]byte(nil), secret...), now: time.Now}, nil
}

// Poll reads bounded pages without a mutable status filter. Cloud acknowledgment
// can fail after successful Dart synchronization; the durable event/exception
// identities make the next read safe. A 2xx PATCH means accepted, not fulfilled.
func (p *QueuePoller) Poll(ctx context.Context) (QueuePollSummary, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	summary := QueuePollSummary{}
	for offset := 0; offset < 10000; {
		page, err := p.queue.Rows(ctx, offset, 100)
		if err != nil || page.Offset != offset || page.Limit != 100 || page.Total < 0 || page.Total > 10000 || len(page.Rows) > 100 || (offset < page.Total && len(page.Rows) == 0) {
			return summary, ErrQueueUnavailable
		}
		for _, row := range page.Rows {
			summary.Examined++
			status := queueString(row.Fields["queue_status"])
			if status != "PENDING" && status != "RETRY_PENDING" && !(status == "NEEDS_REVIEW" && queueString(row.Fields["last_error"]) == "DART_UNCERTAIN") {
				summary.Skipped++
				continue
			}
			identity := map[string]string{}
			for _, name := range []string{"event_id", "source", "kind", "object_id", "source_version", "envelope_json"} {
				identity[name] = queueString(row.Fields[name])
			}
			ack := p.process(ctx, row, status)
			if err = p.queue.Ack(ctx, row.ID, ack); err != nil {
				return summary, ErrQueueUnavailable
			}
			switch ack.Status {
			case "ACKNOWLEDGED":
				summary.Acknowledged++
			case "NEEDS_REVIEW":
				summary.NeedsReview++
			case "RETRY_PENDING":
				summary.RetryPending++
			}
			if !p.ackReadBack(ctx, offset, row.ID, identity, ack) {
				return summary, ErrQueueUnavailable
			}
		}
		offset += len(page.Rows)
		if offset >= page.Total {
			return summary, nil
		}
	}
	return summary, ErrQueueUnavailable
}

// Readback establishes only an observed bookkeeping state. The source must
// still enforce append-only identity: this read and PATCH are not atomic.
func (p *QueuePoller) ackReadBack(ctx context.Context, offset int, rowID string, identity map[string]string, ack TinyAcknowledgment) bool {
	page, err := p.queue.Rows(ctx, offset, 100)
	if err != nil || page.Offset != offset || page.Limit != 100 || page.Total < 0 || page.Total > 10000 || len(page.Rows) > 100 {
		return false
	}
	found := 0
	for _, row := range page.Rows {
		if row.ID == rowID {
			found++
			if queueString(row.Fields["queue_status"]) != ack.Status || queueString(row.Fields["receipt_id"]) != ack.ReceiptID || queueString(row.Fields["last_error"]) != ack.LastError {
				return false
			}
			for name, value := range identity {
				if queueString(row.Fields[name]) != value {
					return false
				}
			}
		}
	}
	return found == 1
}

func queueString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func (p *QueuePoller) process(ctx context.Context, row TinyRow, status string) TinyAcknowledgment {
	invalid := TinyAcknowledgment{Status: "NEEDS_REVIEW", LastError: "EVENT_INVALID"}
	body := []byte(queueString(row.Fields["envelope_json"]))
	if len(body) > MaxEventBytes {
		return invalid
	}
	event, _, err := decodeEvent("tinycommand", body)
	if err != nil || event.Kind != "task.requested" || event.EventID != queueString(row.Fields["event_id"]) || string(event.ObjectID) != queueString(row.Fields["object_id"]) || event.Source != queueString(row.Fields["source"]) || event.Kind != queueString(row.Fields["kind"]) {
		return invalid
	}
	var payload struct {
		SourceVersion int64     `json:"source_version"`
		Category      string    `json:"category"`
		Action        string    `json:"action"`
		Urgency       string    `json:"urgency"`
		State         string    `json:"state"`
		DueAt         time.Time `json:"due_at,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF || payload.SourceVersion < 1 || queueString(row.Fields["source_version"]) != strconv.FormatInt(payload.SourceVersion, 10) {
		return invalid
	}
	input := DartSyncInput{ExceptionID: event.ObjectID, SourceVersion: payload.SourceVersion, Category: payload.Category, Action: payload.Action, Urgency: payload.Urgency, State: payload.State, DueAt: payload.DueAt}
	if ValidateDartSyncInput(input) != nil {
		return invalid
	}
	timestamp := strconv.FormatInt(p.now().Unix(), 10)
	mac := hmac.New(sha256.New, p.secret)
	_, _ = mac.Write([]byte("tinycommand\n" + timestamp + "\n"))
	_, _ = mac.Write(body)
	// This authenticates the internal normalized hop. It never establishes native
	// provider authenticity or proves a financial or exam-domain transition.
	receipt, err := p.receiver.Receive(ctx, "tinycommand", timestamp, "v1="+hex.EncodeToString(mac.Sum(nil)), body)
	if err != nil {
		if errors.Is(err, ErrEventConflict) {
			return TinyAcknowledgment{Status: "NEEDS_REVIEW", LastError: "EVENT_CONFLICT"}
		}
		if errors.Is(err, ErrEventInvalid) || errors.Is(err, ErrEventUnauthorized) {
			return invalid
		}
		return TinyAcknowledgment{Status: "RETRY_PENDING", LastError: "SYNC_FAILED"}
	}
	if _, err := core.ParseID(string(receipt.ReceiptID)); err != nil || string(receipt.ReceiptID) == "00000000-0000-0000-0000-000000000000" {
		return TinyAcknowledgment{Status: "RETRY_PENDING", LastError: "SYNC_FAILED"}
	}
	ack := TinyAcknowledgment{Status: "ACKNOWLEDGED", ReceiptID: string(receipt.ReceiptID)}
	var result DartSyncReceipt
	if status == "NEEDS_REVIEW" {
		result, err = p.tasks.Reconcile(ctx, event.ObjectID)
	} else {
		result, err = p.tasks.Sync(ctx, input)
	}
	if err != nil || result.State != "SYNCED" {
		ack.Status = "RETRY_PENDING"
		ack.LastError = "SYNC_FAILED"
		if errors.Is(err, ErrDartSyncUncertain) || errors.Is(err, ErrDartAmbiguous) || result.State == "UNCERTAIN" {
			ack.Status = "NEEDS_REVIEW"
			ack.LastError = "DART_UNCERTAIN"
		}
		if errors.Is(err, ErrDartSyncInvalid) || errors.Is(err, ErrDartSyncStale) || errors.Is(err, ErrDartSyncConflict) {
			ack.Status = "NEEDS_REVIEW"
			ack.LastError = "EVENT_CONFLICT"
		}
	}
	if err == nil && result.State == "SYNCED" {
		if result.ExceptionID != input.ExceptionID || !dartID(result.TaskID) || result.SourceVersion < 1 {
			ack.Status = "NEEDS_REVIEW"
			ack.LastError = "EVENT_CONFLICT"
		} else if result.SourceVersion < input.SourceVersion {
			ack.Status = "RETRY_PENDING"
			ack.LastError = "SYNC_FAILED"
		} else if result.SourceVersion > input.SourceVersion {
			ack.Status = "NEEDS_REVIEW"
			ack.LastError = "EVENT_CONFLICT"
		}
	}
	return ack
}
