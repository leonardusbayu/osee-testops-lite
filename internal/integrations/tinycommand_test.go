package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type tinyTestTransport func(*http.Request) (*http.Response, error)

func (t tinyTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }
func tinyResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

const tinyFixtureTable = `{"id":"test_table","name":"osee.co.id staging outbox","columns":[{"id":"col_status","name":"queue_status","type":"text"},{"id":"col_receipt","name":"receipt_id","type":"text"},{"id":"col_error","name":"last_error","type":"text"}]}`

func tinyConfig(t tinyTestTransport) TinyConfig {
	return TinyConfig{APIKey: "synthetic-key", TableID: "test_table", HTTPClient: &http.Client{Transport: t}}
}

func TestTinyDocumentedRowsAndAcknowledgment(t *testing.T) {
	var paths []string
	client, err := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "api.tinycommand.com" || r.Header.Get("Authorization") != "Bearer synthetic-key" {
			t.Fatal("credential endpoint contract changed")
		}
		paths = append(paths, r.Method+" "+r.URL.RequestURI())
		switch r.URL.Path {
		case "/v1/tables/test_table":
			return tinyResponse(r, 200, tinyFixtureTable), nil
		case "/v1/tables/test_table/rows":
			if r.URL.Query().Get("limit") != "100" || r.URL.Query().Get("offset") != "100" || r.URL.Query().Get("sort") != "created_at" || r.URL.Query().Get("order") != "asc" {
				t.Fatal("pagination contract changed")
			}
			return tinyResponse(r, 200, `{"rows":[{"id":"row_1","fields":{"queue_status":"PENDING","envelope_json":"{}"},"created_at":"2026-10-09T00:00:00Z","updated_at":"2026-10-09T00:00:00Z"}],"total":101,"limit":100,"offset":100}`), nil
		case "/v1/tables/test_table/rows/row_1":
			if r.Method != "PATCH" || r.Header.Get("Content-Type") != "application/json" {
				t.Fatal("write contract changed")
			}
			var body struct {
				Fields map[string]string `json:"fields"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Fields) != 3 || body.Fields["queue_status"] != "ACKNOWLEDGED" || body.Fields["receipt_id"] != "receipt_1" || body.Fields["last_error"] != "" {
				t.Fatal("acknowledgment exceeded allowed fields")
			}
			return tinyResponse(r, 204, ""), nil
		default:
			t.Fatal("unexpected endpoint")
			return nil, errors.New("unexpected endpoint")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	table, err := client.Table(context.Background())
	if err != nil || len(table.Columns) != 3 {
		t.Fatalf("schema: %v", err)
	}
	page, err := client.Rows(context.Background(), 100, 100)
	if err != nil || page.Total != 101 || len(page.Rows) != 1 || string(page.Rows[0].Fields["queue_status"]) != `"PENDING"` {
		t.Fatalf("rows: %v", err)
	}
	if err := client.Ack(context.Background(), "row_1", TinyAcknowledgment{Status: "ACKNOWLEDGED", ReceiptID: "receipt_1"}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 5 {
		t.Fatalf("scope preflight count: %d", len(paths))
	}
}

func TestTinyRejectsInvalidInputsBeforeRequests(t *testing.T) {
	calls := 0
	client, _ := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
		calls++
		return tinyResponse(r, 200, tinyFixtureTable), nil
	}))
	for _, p := range [][2]int{{-1, 100}, {0, 0}, {0, 101}, {10001, 100}, {9999, 2}} {
		if _, err := client.Rows(context.Background(), p[0], p[1]); !errors.Is(err, ErrTinyInput) {
			t.Fatal("invalid pagination accepted")
		}
	}
	for _, ack := range []TinyAcknowledgment{{Status: "VERIFIED"}, {Status: "ACKNOWLEDGED"}, {Status: "ACKNOWLEDGED", ReceiptID: "r", LastError: "SYNC_FAILED"}, {Status: "RETRY_PENDING", LastError: "raw provider text"}, {Status: "NEEDS_REVIEW", LastError: ""}} {
		if err := client.Ack(context.Background(), "row_1", ack); !errors.Is(err, ErrTinyInput) {
			t.Fatal("invalid ack accepted")
		}
	}
	if err := client.Ack(context.Background(), "../row", TinyAcknowledgment{Status: "ACKNOWLEDGED", ReceiptID: "r"}); !errors.Is(err, ErrTinyInput) {
		t.Fatal("path injection accepted")
	}
	if calls != 0 {
		t.Fatal("invalid inputs caused network call")
	}
	for _, id := range []string{"", "../x", "a/b", "x?token", strings.Repeat("a", 129)} {
		cfg := tinyConfig(nil)
		cfg.TableID = id
		if _, err := NewTinyClient(cfg); !errors.Is(err, ErrTinyConfig) {
			t.Fatal("invalid table scope accepted")
		}
	}
}

func TestTinyRowsFailClosed(t *testing.T) {
	cases := []struct{ name, table, rows string }{
		{"wrong table", `{"id":"other_table","columns":[]}`, `{}`},
		{"missing columns", `{"id":"test_table"}`, `{}`},
		{"duplicate column", `{"id":"test_table","columns":[{"id":"col_a","name":"a","type":"text"},{"id":"col_a","name":"b","type":"text"}]}`, `{}`},
		{"bad row", tinyFixtureTable, `{"rows":[{"id":"../x","fields":{}}],"total":1,"offset":0,"limit":100}`},
		{"missing rows", tinyFixtureTable, `{"total":0,"offset":0,"limit":100}`},
		{"bad offset", tinyFixtureTable, `{"rows":[],"total":1,"offset":100,"limit":100}`},
		{"wrong limit", tinyFixtureTable, `{"rows":[],"total":0,"offset":0,"limit":101}`},
		{"excessive total", tinyFixtureTable, `{"rows":[],"total":10001,"offset":0,"limit":100}`},
		{"duplicate row", tinyFixtureTable, `{"rows":[{"id":"row_a","fields":{}},{"id":"row_a","fields":{}}],"total":2,"offset":0,"limit":100}`},
		{"trailing JSON", tinyFixtureTable, `{"rows":[],"total":0,"offset":0,"limit":100}{}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, _ := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
				body := c.table
				if strings.HasSuffix(r.URL.Path, "/rows") {
					body = c.rows
				}
				return tinyResponse(r, 200, body), nil
			}))
			if _, err := client.Rows(context.Background(), 0, 100); err == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
}

func TestTinyTransportLimitsRedactionAndUnknownAck(t *testing.T) {
	for _, status := range []int{301, 401, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, _ := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
				response := tinyResponse(r, status, `{"error":"synthetic-key"}`)
				response.Header.Set("Location", "https://other.test/?token=synthetic-key")
				return response, nil
			}))
			_, err := client.Table(context.Background())
			if err == nil || strings.Contains(err.Error(), "synthetic-key") {
				t.Fatal("bad status not redacted")
			}
		})
	}
	for _, body := range []string{"bad-json", strings.Repeat("x", tinyMaxResponseBytes+1)} {
		client, _ := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) { return tinyResponse(r, 200, body), nil }))
		if _, err := client.Table(context.Background()); !errors.Is(err, ErrTinyResponse) {
			t.Fatal("unbounded/malformed response accepted")
		}
	}
	client, _ := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPatch {
			return nil, errors.New("synthetic-key upstream secret")
		}
		return tinyResponse(r, 200, tinyFixtureTable), nil
	}))
	err := client.Ack(context.Background(), "row_1", TinyAcknowledgment{Status: "RETRY_PENDING", LastError: "SYNC_FAILED"})
	if !errors.Is(err, ErrTinyOutcomeUnknown) || strings.Contains(err.Error(), "synthetic-key") {
		t.Fatal("uncertain ack not quarantined")
	}
	if strings.Contains(fmt.Sprintf("%#v %+v", client, tinyConfig(nil)), "synthetic-key") {
		t.Fatal("credential formatting exposed")
	}
	redirects := 0
	cfg := tinyConfig(func(r *http.Request) (*http.Response, error) {
		redirects++
		resp := tinyResponse(r, 302, "")
		resp.Header.Set("Location", "https://other.test/")
		return resp, nil
	})
	client, _ = NewTinyClient(cfg)
	_, _ = client.Table(context.Background())
	if redirects != 1 {
		t.Fatal("redirect followed")
	}
}

func TestTinyAcknowledgmentRequiresReconciliation(t *testing.T) {
	for _, status := range []int{408, 503} {
		client, _ := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodPatch {
				return tinyResponse(r, status, "provider-body"), nil
			}
			return tinyResponse(r, 200, tinyFixtureTable), nil
		}))
		if err := client.Ack(context.Background(), "row_1", TinyAcknowledgment{Status: "NEEDS_REVIEW", LastError: "DART_UNCERTAIN"}); !errors.Is(err, ErrTinyOutcomeUnknown) {
			t.Fatal("ambiguous acknowledgment was not marked unknown")
		}
	}
	client, _ := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPatch {
			return tinyResponse(r, 202, "response-schema-not-documented"), nil
		}
		return tinyResponse(r, 200, tinyFixtureTable), nil
	}))
	if err := client.Ack(context.Background(), "row_1", TinyAcknowledgment{Status: "RETRY_PENDING", LastError: "SYNC_FAILED"}); err != nil {
		t.Fatal("documented protocol transport acceptance rejected")
	}
	// Transport acceptance returns no asserted persisted fields; the worker must
	// perform the next Rows read and compare its own durable receipt.
	if strings.Contains(fmt.Sprintf("%#v", TinyRow{Fields: map[string]json.RawMessage{"payload": json.RawMessage(`"private-value"`)}}), "private-value") {
		t.Fatal("row formatting leaked an envelope")
	}
}

func TestTinyRejectsWrongContentTypeAndMissingAckSchema(t *testing.T) {
	client, _ := NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
		resp := tinyResponse(r, 200, tinyFixtureTable)
		resp.Header.Set("Content-Type", "text/html")
		return resp, nil
	}))
	if _, err := client.Table(context.Background()); !errors.Is(err, ErrTinyResponse) {
		t.Fatal("non-JSON schema accepted")
	}
	writes := 0
	client, _ = NewTinyClient(tinyConfig(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPatch {
			writes++
		}
		return tinyResponse(r, 200, `{"id":"test_table","columns":[]}`), nil
	}))
	if err := client.Ack(context.Background(), "row_1", TinyAcknowledgment{Status: "ACKNOWLEDGED", ReceiptID: "receipt_1"}); !errors.Is(err, ErrTinyScope) || writes != 0 {
		t.Fatal("acknowledgment sent before exact schema check")
	}
}
