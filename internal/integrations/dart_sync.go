package integrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

// DartTaskProvider must reserve ErrDartUnavailable on mutations for failures
// before dispatch. All outcomes that may have reached Dart must be ambiguous.
type DartTaskProvider interface {
	CreateTask(context.Context, DartTask) (json.RawMessage, error)
	UpdateTask(context.Context, string, DartTask) (json.RawMessage, error)
	Task(context.Context, string) (json.RawMessage, error)
	Tasks(context.Context, string) (json.RawMessage, error)
}

var (
	ErrDartSyncInvalid   = errors.New("invalid operational exception")
	ErrDartSyncBusy      = errors.New("exception synchronization leased")
	ErrDartSyncStale     = errors.New("stale exception source version")
	ErrDartSyncConflict  = errors.New("exception synchronization conflict")
	ErrDartSyncUncertain = errors.New("exception synchronization uncertain; reconcile without mutation")
)

type DartSyncConfig struct {
	Dartboard string
	Statuses  map[string]string
	Staging   bool
}
type DartSyncInput struct {
	ExceptionID   core.ID   `json:"exception_id"`
	SourceVersion int64     `json:"source_version"`
	Category      string    `json:"category"`
	Action        string    `json:"action"`
	Urgency       string    `json:"urgency"`
	State         string    `json:"state"`
	DueAt         time.Time `json:"due_at,omitempty"`
}
type DartSyncReceipt struct {
	ExceptionID   core.ID `json:"exception_id"`
	SourceVersion int64   `json:"source_version"`
	TaskID        string  `json:"task_id,omitempty"`
	State         string  `json:"state"`
	Replayed      bool    `json:"replayed"`
}
type DartSynchronizer struct {
	store    *db.Store
	provider DartTaskProvider
	board    string
	statuses map[string]string
	staging  bool
}

func NewDartSynchronizer(store *db.Store, provider DartTaskProvider, config DartSyncConfig) (*DartSynchronizer, error) {
	if store == nil || store.Pool == nil || provider == nil || !syncLabel(config.Dartboard, 120) {
		return nil, ErrDartSyncInvalid
	}
	service := &DartSynchronizer{store: store, provider: provider, board: config.Dartboard, statuses: map[string]string{}, staging: config.Staging}
	for _, state := range []string{"open", "in_progress", "done"} {
		label := config.Statuses[state]
		if !syncLabel(label, 64) {
			return nil, ErrDartSyncInvalid
		}
		service.statuses[state] = label
	}
	return service, nil
}

func syncLabel(value string, max int) bool {
	if value == "" || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func (s *DartSynchronizer) task(input DartSyncInput) (DartTask, string, error) {
	if err := ValidateDartSyncInput(input); err != nil {
		return DartTask{}, "", err
	}
	status := s.statuses[input.State]
	task := DartTask{Title: "OSEE " + input.Category + " [" + string(input.ExceptionID) + "]", Dartboard: s.board, Status: status, Assignees: []string{}, Description: syncMarker(input.ExceptionID) + "\nOSEE_SOURCE_VERSION=" + strconv.FormatInt(input.SourceVersion, 10) + "\nCategory: " + input.Category + "\nNext action: " + input.Action + "\nUrgency: " + input.Urgency + "\nTask completion records operational progress only and does not verify payment or release results."}
	if s.staging {
		task.Title = "STAGING " + task.Title
		task.Description += "\nSTAGING integration acceptance fixture with synthetic operational data."
	}
	if !input.DueAt.IsZero() {
		task.DueAt = input.DueAt.UTC().Format(time.RFC3339)
	}
	encoded, err := json.Marshal(task)
	if err != nil {
		return DartTask{}, "", ErrDartSyncInvalid
	}
	hash := sha256.Sum256(encoded)
	return task, hex.EncodeToString(hash[:]), nil
}

// ValidateDartSyncInput restricts operational queue data before persistence or
// provider access. Free text and participant data are not accepted task fields.
func ValidateDartSyncInput(input DartSyncInput) error {
	categories := map[string]string{"payment_review": "review_payment", "booking_review": "review_booking", "identity_review": "verify_identity", "result_review": "review_result", "document_review": "verify_documents", "shipment_review": "review_shipment", "support_incident": "resolve_support", "automation_failure": "restore_integration"}
	if _, err := core.ParseID(string(input.ExceptionID)); err != nil || input.ExceptionID == "00000000-0000-0000-0000-000000000000" || input.SourceVersion < 1 || categories[input.Category] != input.Action || input.Action == "" {
		return ErrDartSyncInvalid
	}
	if input.Urgency != "low" && input.Urgency != "normal" && input.Urgency != "high" && input.Urgency != "critical" {
		return ErrDartSyncInvalid
	}
	if input.State != "open" && input.State != "in_progress" && input.State != "done" {
		return ErrDartSyncInvalid
	}
	if !input.DueAt.IsZero() {
		if input.DueAt.UTC().Year() < 2020 || input.DueAt.UTC().Year() > 2100 {
			return ErrDartSyncInvalid
		}
	}
	return nil
}

func syncMarker(id core.ID) string { return "OSEE_EXCEPTION_ID=" + string(id) }

func (s *DartSynchronizer) Sync(ctx context.Context, input DartSyncInput) (DartSyncReceipt, error) {
	if s == nil {
		return DartSyncReceipt{}, ErrDartUnavailable
	}
	task, hash, err := s.task(input)
	if err != nil {
		return DartSyncReceipt{}, err
	}
	claim, err := s.claim(ctx, input.ExceptionID, input.SourceVersion, hash, &task, false)
	if err != nil {
		return claim.receipt(), err
	}
	if claim.replayed {
		return claim.receipt(), nil
	}
	return s.run(ctx, claim)
}

func (s *DartSynchronizer) Reconcile(ctx context.Context, id core.ID) (DartSyncReceipt, error) {
	if s == nil {
		return DartSyncReceipt{}, ErrDartUnavailable
	}
	claim, err := s.claim(ctx, id, 0, "", nil, true)
	if err != nil {
		return claim.receipt(), err
	}
	if claim.replayed {
		return claim.receipt(), nil
	}
	return s.run(ctx, claim)
}

func (s *DartSynchronizer) Read(ctx context.Context, id core.ID) (DartSyncReceipt, error) {
	if s == nil {
		return DartSyncReceipt{}, ErrDartUnavailable
	}
	row, err := readSync(ctx, s.store.Pool, id, false)
	if err != nil {
		return DartSyncReceipt{}, ErrDartUnavailable
	}
	return row.receipt(), nil
}

func (s *DartSynchronizer) run(ctx context.Context, row syncRow) (DartSyncReceipt, error) {
	callctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if row.external != "" {
		raw, err := s.provider.Task(callctx, row.external)
		if err != nil {
			return s.finish(ctx, row, pendingOrUncertain(row), row.external, ErrDartUnavailable)
		}
		remote, err := decodeSyncTask(raw)
		if err != nil || remote.ID != row.external || !hasSyncMarker(remote.Description, row.id) {
			return s.finish(ctx, row, "UNCERTAIN", row.external, ErrDartSyncUncertain)
		}
		if row.reconcile {
			if !sameSyncTask(remote.DartTask, row.task) {
				// A prior exact applied hash plus absence of this version's
				// durable intent proves a held read did not dispatch an update.
				if canResumeReadOnlyHold(row, remote.DartTask) {
					return s.finish(ctx, row, "PENDING", row.external, nil)
				}
				return s.finish(ctx, row, "UNCERTAIN", row.external, ErrDartSyncUncertain)
			}
			return s.finish(ctx, row, "SYNCED", row.external, nil)
		}
		if err := s.mutationIntent(ctx, row, "update"); err != nil {
			return row.receipt(), err
		}
		updated, err := s.provider.UpdateTask(callctx, row.external, row.task)
		if err != nil {
			state := "UNCERTAIN"
			if errors.Is(err, ErrDartUnavailable) {
				state = "PENDING"
			}
			return s.finish(ctx, row, state, row.external, mutationFailure(err))
		}
		id, err := decodeSyncID(updated)
		if err != nil || id != row.external {
			return s.finish(ctx, row, "UNCERTAIN", row.external, ErrDartSyncUncertain)
		}
		return s.finish(ctx, row, "SYNCED", row.external, nil)
	}
	raw, err := s.provider.Tasks(callctx, s.board)
	if err != nil {
		return s.finish(ctx, row, pendingOrUncertain(row), "", ErrDartUnavailable)
	}
	matches, complete, err := decodeSyncList(raw, row.id)
	if err != nil || !complete {
		return s.finish(ctx, row, pendingOrUncertain(row), "", ErrDartUnavailable)
	}
	if len(matches) > 1 {
		return s.finish(ctx, row, "UNCERTAIN", "", ErrDartSyncConflict)
	}
	if len(matches) == 1 {
		if !sameSyncTask(matches[0].DartTask, row.task) {
			return s.finish(ctx, row, "UNCERTAIN", matches[0].ID, ErrDartSyncUncertain)
		}
		return s.finish(ctx, row, "SYNCED", matches[0].ID, nil)
	}
	// A zero-match read cannot prove a prior uncertain create was never accepted.
	if row.reconcile {
		if row.unresolved {
			return s.finish(ctx, row, "UNCERTAIN", "", ErrDartSyncUncertain)
		}
		return s.finish(ctx, row, "PENDING", "", ErrDartUnavailable)
	}
	if err := s.mutationIntent(ctx, row, "create"); err != nil {
		return row.receipt(), err
	}
	raw, err = s.provider.CreateTask(callctx, row.task)
	if err != nil {
		state := "UNCERTAIN"
		if errors.Is(err, ErrDartUnavailable) {
			state = "PENDING"
		}
		return s.finish(ctx, row, state, "", mutationFailure(err))
	}
	id, err := decodeSyncID(raw)
	if err != nil {
		return s.finish(ctx, row, "UNCERTAIN", "", ErrDartSyncUncertain)
	}
	return s.finish(ctx, row, "SYNCED", id, nil)
}

func pendingOrUncertain(row syncRow) string {
	if row.unresolved {
		return "UNCERTAIN"
	}
	return "PENDING"
}
func mutationFailure(err error) error {
	if errors.Is(err, ErrDartUnavailable) {
		return ErrDartUnavailable
	}
	return ErrDartSyncUncertain
}

func hasSyncMarker(description string, id core.ID) bool {
	marker := syncMarker(id)
	found := 0
	for _, line := range strings.Split(normalizeDartMarkdown(description), "\n") {
		// Backslash removal is only a rejection test for additional or spoofed
		// ownership lines. It never makes a noncanonical line authoritative.
		if strings.HasPrefix(strings.ReplaceAll(line, `\`, ""), "OSEE_EXCEPTION_ID=") {
			if line != marker {
				return false
			}
			found++
		}
	}
	return found == 1
}
func sameSyncTask(actual, desired DartTask) bool {
	return actual.Title == desired.Title && normalizeDartMarkdown(actual.Description) == desired.Description && actual.Status == desired.Status && actual.Dartboard == desired.Dartboard && actual.DueAt == desired.DueAt
}
