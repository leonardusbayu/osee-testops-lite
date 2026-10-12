package integrations

// Documented contract: https://tinycommand.com/docs/tables/api
// The documented API host did not resolve during the 2026-10-09 preflight.
// This adapter must remain disabled until the vendor host, account entitlement,
// existing scoped credential, and a synthetic round trip are verified.
// No table/row creation, deletion, business-field writes, or endpoint override.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const tinyEndpoint = "https://api.tinycommand.com/v1"
const tinyMaxResponseBytes = 1 << 20
const tinyMaximumRows = 10000 // OSEE bound, not a claimed vendor quota.

var (
	ErrTinyConfig         = errors.New("invalid TinyCommand client configuration")
	ErrTinyInput          = errors.New("invalid TinyCommand request parameters")
	ErrTinyResponse       = errors.New("invalid TinyCommand response")
	ErrTinyScope          = errors.New("TinyCommand reference outside configured table")
	ErrTinyUnavailable    = errors.New("TinyCommand request unavailable")
	ErrTinyUnauthorized   = errors.New("TinyCommand authentication failed")
	ErrTinyOutcomeUnknown = errors.New("TinyCommand acknowledgment outcome unknown; reconcile before retry")
)

type TinyConfig struct {
	APIKey     string
	TableID    string
	HTTPClient *http.Client
}

func (TinyConfig) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "TinyConfig{credential:[REDACTED]}")
}

type TinyClient struct {
	apiKey, tableID string
	http            *http.Client
}

func (*TinyClient) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "TinyClient{credential:[REDACTED]}")
}

func NewTinyClient(config TinyConfig) (*TinyClient, error) {
	if !tinyIdentifier(config.TableID) || !tinyCredential(config.APIKey) {
		return nil, ErrTinyConfig
	}
	h := http.Client{Timeout: 15 * time.Second}
	if config.HTTPClient != nil {
		h = *config.HTTPClient
		if h.Timeout <= 0 || h.Timeout > 30*time.Second {
			h.Timeout = 15 * time.Second
		}
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &TinyClient{apiKey: config.APIKey, tableID: config.TableID, http: &h}, nil
}

func tinyCredential(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func tinyIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

type TinyHTTPError struct {
	StatusCode     int
	RetryAfter     time.Duration
	OutcomeUnknown bool
}

func (e *TinyHTTPError) Error() string {
	return fmt.Sprintf("TinyCommand HTTP status %d", e.StatusCode)
}
func (e *TinyHTTPError) Is(target error) bool {
	if e.OutcomeUnknown && target == ErrTinyOutcomeUnknown {
		return true
	}
	if e.StatusCode == 401 || e.StatusCode == 403 {
		return target == ErrTinyUnauthorized
	}
	return target == ErrTinyUnavailable
}

func (c *TinyClient) request(ctx context.Context, method, path string, body []byte, destination any) error {
	if c == nil || c.http == nil {
		return ErrTinyConfig
	}
	req, err := http.NewRequestWithContext(ctx, method, tinyEndpoint+path, bytes.NewReader(body))
	if err != nil {
		return ErrTinyInput
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if method == http.MethodPatch {
			return ErrTinyOutcomeUnknown
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrTinyUnavailable
	}
	defer resp.Body.Close()
	good := resp.StatusCode == http.StatusOK
	if method == http.MethodPatch {
		good = resp.StatusCode >= 200 && resp.StatusCode < 300
	}
	if !good {
		e := &TinyHTTPError{StatusCode: resp.StatusCode, OutcomeUnknown: method == http.MethodPatch && (resp.StatusCode >= 500 || resp.StatusCode == 408 || resp.StatusCode >= 300 && resp.StatusCode < 400)}
		if sec, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && sec > 0 && sec <= 86400 {
			e.RetryAfter = time.Duration(sec) * time.Second
		}
		return e
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, tinyMaxResponseBytes+1))
	if err != nil || len(data) > tinyMaxResponseBytes {
		if method == http.MethodPatch {
			return ErrTinyOutcomeUnknown
		}
		return ErrTinyResponse
	}
	if destination == nil {
		return nil
	} // PATCH response schema is not documented.
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (contentType != "application/json" && !strings.HasSuffix(contentType, "+json")) || json.Unmarshal(data, destination) != nil {
		return ErrTinyResponse
	}
	return nil
}

type TinyColumn struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Options  []string `json:"options,omitempty"`
}
type TinyTable struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Columns []TinyColumn `json:"columns"`
}

// Table uses the configured exact table path; it never lists other tables.
// Vendor schema contains no workspace ID, so workspace entitlement is a
// deployment preflight requirement, not something this response authenticates.
func (c *TinyClient) Table(ctx context.Context) (TinyTable, error) {
	if c == nil {
		return TinyTable{}, ErrTinyConfig
	}
	var table TinyTable
	if err := c.request(ctx, http.MethodGet, "/tables/"+c.tableID, nil, &table); err != nil {
		return TinyTable{}, err
	}
	if table.ID != c.tableID {
		return TinyTable{}, ErrTinyScope
	}
	if table.Columns == nil || len(table.Columns) > 1000 || len(table.Name) > 512 {
		return TinyTable{}, ErrTinyResponse
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, col := range table.Columns {
		if !tinyIdentifier(col.ID) || col.Name == "" || len(col.Name) > 512 || col.Type == "" || len(col.Type) > 100 || ids[col.ID] || names[col.Name] || len(col.Options) > 1000 {
			return TinyTable{}, ErrTinyResponse
		}
		ids[col.ID] = true
		names[col.Name] = true
	}
	return table, nil
}

type TinyRow struct {
	ID        string                     `json:"id"`
	Fields    map[string]json.RawMessage `json:"fields"`
	CreatedAt string                     `json:"created_at"`
	UpdatedAt string                     `json:"updated_at"`
}
type TinyRowsPage struct {
	Rows   []TinyRow `json:"rows"`
	Total  int       `json:"total"`
	Limit  int       `json:"limit"`
	Offset int       `json:"offset"`
}

func (TinyRow) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "TinyRow{fields:[REDACTED]}")
}

func (TinyRowsPage) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "TinyRowsPage{rows:[REDACTED]}")
}

// Rows is bounded to 100 rows per call and a 10,000-row OSEE ceiling. It does
// not use the documented filter examples because their key/name mapping needs
// live validation. Offset pagination is not a snapshot: callers deduplicate by
// event ID, reconcile/re-scan, and do not mutate filtered page membership.
func (c *TinyClient) Rows(ctx context.Context, offset, limit int) (TinyRowsPage, error) {
	if offset < 0 || limit < 1 || limit > 100 || offset > tinyMaximumRows || limit > tinyMaximumRows-offset {
		return TinyRowsPage{}, ErrTinyInput
	}
	if _, err := c.Table(ctx); err != nil {
		return TinyRowsPage{}, err
	}
	query := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {strconv.Itoa(limit)}, "sort": {"created_at"}, "order": {"asc"}}
	var wire struct {
		Rows   []TinyRow `json:"rows"`
		Total  *int      `json:"total"`
		Limit  *int      `json:"limit"`
		Offset *int      `json:"offset"`
	}
	if err := c.request(ctx, http.MethodGet, "/tables/"+c.tableID+"/rows?"+query.Encode(), nil, &wire); err != nil {
		return TinyRowsPage{}, err
	}
	if wire.Rows == nil || wire.Total == nil || wire.Limit == nil || wire.Offset == nil || *wire.Total < 0 || *wire.Total > tinyMaximumRows || *wire.Offset != offset || *wire.Limit != limit || len(wire.Rows) > limit || len(wire.Rows) > *wire.Total {
		return TinyRowsPage{}, ErrTinyResponse
	}
	if offset < *wire.Total && len(wire.Rows) > *wire.Total-offset {
		return TinyRowsPage{}, ErrTinyResponse
	}
	if offset >= *wire.Total && len(wire.Rows) > 0 {
		return TinyRowsPage{}, ErrTinyResponse
	}
	ids := map[string]bool{}
	for _, row := range wire.Rows {
		if !tinyIdentifier(row.ID) || row.Fields == nil || len(row.Fields) > 1000 || ids[row.ID] {
			return TinyRowsPage{}, ErrTinyResponse
		}
		ids[row.ID] = true
	}
	return TinyRowsPage{Rows: wire.Rows, Total: *wire.Total, Limit: *wire.Limit, Offset: *wire.Offset}, nil
}

type TinyAcknowledgment struct{ Status, ReceiptID, LastError string }

func tinyAckValid(ack TinyAcknowledgment) bool {
	if ack.ReceiptID != "" && !tinyIdentifier(ack.ReceiptID) {
		return false
	}
	switch ack.Status {
	case "ACKNOWLEDGED":
		return ack.ReceiptID != "" && ack.LastError == ""
	case "RETRY_PENDING", "NEEDS_REVIEW":
		switch ack.LastError {
		case "EVENT_INVALID", "EVENT_CONFLICT", "DART_UNCERTAIN", "SYNC_FAILED":
			return true
		}
	}
	return false
}

// Ack writes only queue bookkeeping. nil means the HTTP request was accepted,
// not that the queue fields persisted or the business operation completed. The
// worker must read back the row and compare all three fields before confirming.
// It must persist its local receipt before this call; ambiguous writes require
// reconciliation, never repeating the downstream business operation.
func (c *TinyClient) Ack(ctx context.Context, rowID string, ack TinyAcknowledgment) error {
	if !tinyIdentifier(rowID) || !tinyAckValid(ack) {
		return ErrTinyInput
	}
	table, err := c.Table(ctx)
	if err != nil {
		return err
	}
	names := map[string]bool{}
	for _, col := range table.Columns {
		names[col.Name] = true
	}
	if !names["queue_status"] || !names["receipt_id"] || !names["last_error"] {
		return ErrTinyScope
	}
	body, _ := json.Marshal(struct {
		Fields map[string]string `json:"fields"`
	}{Fields: map[string]string{"queue_status": ack.Status, "receipt_id": ack.ReceiptID, "last_error": ack.LastError}})
	return c.request(ctx, http.MethodPatch, "/tables/"+c.tableID+"/rows/"+rowID, body, nil)
}
