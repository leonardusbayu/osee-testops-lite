package integrations_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"osee-testops-lite/internal/integrations"
)

func TestEventHTTPRejectsAmbiguousEnvelope(t *testing.T) {
	gateway, err := integrations.NewEventGateway(nil, integrations.EventConfig{Secrets: map[string][]byte{"tinycommand": eventTestSecret}, Clock: func() time.Time { return eventTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	valid := string(eventBody("tinycommand", "bounded-event", "30b3c57e-f91f-4615-b21b-ad31c998fc6d", `{}`))
	tests := []struct{ name, body string }{
		{"case_variant", strings.Replace(valid, `"source"`, `"Source"`, 1)},
		{"unknown_field", strings.TrimSuffix(valid, "}") + `,"verified":true}`},
		{"duplicate_field", strings.TrimSuffix(valid, "}") + `,"event_id":"different"}`},
		{"duplicate_nested_field", strings.Replace(valid, `"payload":{}`, `"payload":{"a":1,"a":2}`, 1)},
		{"trailing_document", valid + ` {}`},
		{"source_mismatch", strings.Replace(valid, `"tinycommand"`, `"trafft"`, 1)},
		{"payment_transition_kind", strings.Replace(valid, `"registration.submitted"`, `"payment.verified"`, 1)},
		{"result_transition_kind", strings.Replace(valid, `"registration.submitted"`, `"result.released"`, 1)},
		{"missing_event_id", strings.Replace(valid, `"bounded-event"`, `""`, 1)},
		{"invalid_object_id", strings.Replace(valid, `"30b3c57e-f91f-4615-b21b-ad31c998fc6d"`, `"someone-else"`, 1)},
		{"null_object_id", strings.Replace(valid, `"30b3c57e-f91f-4615-b21b-ad31c998fc6d"`, `"00000000-0000-0000-0000-000000000000"`, 1)},
		{"null_payload", strings.Replace(valid, `"payload":{}`, `"payload":null`, 1)},
		{"array_payload", strings.Replace(valid, `"payload":{}`, `"payload":[]`, 1)},
		{"deep_payload", strings.Replace(valid, `"payload":{}`, `"payload":{"a":`+strings.Repeat("[", 17)+`0`+strings.Repeat("]", 17)+`}`, 1)},
		{"large_payload", strings.Replace(valid, `"payload":{}`, `"payload":{"a":"`+strings.Repeat("a", 25*1024)+`"}`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := eventPost(gateway, "tinycommand", []byte(test.body))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("invalid envelope status=%d, want 400", response.Code)
			}
			if strings.Contains(response.Body.String(), "someone-else") || strings.Contains(response.Body.String(), "bounded-event") {
				t.Fatal("response echoed private request data")
			}
		})
	}
}

func TestEventHTTPRejectsBadAuthenticationAndProtocol(t *testing.T) {
	gateway, err := integrations.NewEventGateway(nil, integrations.EventConfig{Secrets: map[string][]byte{"tinycommand": eventTestSecret}, Clock: func() time.Time { return eventTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	body := eventBody("tinycommand", "authentication-event", "30b3c57e-f91f-4615-b21b-ad31c998fc6d", `{}`)
	tests := []struct {
		name    string
		request func() *http.Request
		status  int
	}{
		{"expired", func() *http.Request { return eventRequest("tinycommand", eventTestNow.Add(-301*time.Second), body) }, 401},
		{"future", func() *http.Request { return eventRequest("tinycommand", eventTestNow.Add(301*time.Second), body) }, 401},
		{"unsupported_source", func() *http.Request { return eventRequest("lynk", eventTestNow, body) }, 401},
		{"tampered_signature", func() *http.Request {
			r := eventRequest("tinycommand", eventTestNow, body)
			r.Header.Set("X-OSEE-Signature", "v1="+strings.Repeat("0", 64))
			return r
		}, 401},
		{"duplicate_header", func() *http.Request {
			r := eventRequest("tinycommand", eventTestNow, body)
			r.Header.Add("X-OSEE-Source", "tinycommand")
			return r
		}, 401},
		{"invalid_timestamp", func() *http.Request {
			r := eventRequest("tinycommand", eventTestNow, body)
			r.Header.Set("X-OSEE-Timestamp", "+1791522000")
			return r
		}, 401},
		{"non_json", func() *http.Request {
			r := eventRequest("tinycommand", eventTestNow, body)
			r.Header.Set("Content-Type", "text/plain")
			return r
		}, 415},
		{"encoded_body", func() *http.Request {
			r := eventRequest("tinycommand", eventTestNow, body)
			r.Header.Set("Content-Encoding", "gzip")
			return r
		}, 415},
		{"wrong_method", func() *http.Request {
			r := eventRequest("tinycommand", eventTestNow, body)
			r.Method = http.MethodGet
			return r
		}, 405},
		{"oversized", func() *http.Request {
			return eventRequest("tinycommand", eventTestNow, []byte(strings.Repeat("a", integrations.MaxEventBytes+1)))
		}, 413},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			gateway.ServeHTTP(response, test.request())
			if response.Code != test.status {
				t.Fatalf("protocol status=%d, want %d", response.Code, test.status)
			}
		})
	}
	disabled, err := integrations.NewEventGateway(nil, integrations.EventConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if response := eventPost(disabled, "tinycommand", body); response.Code != http.StatusServiceUnavailable {
		t.Fatal("unconfigured gateway must remain disabled")
	}
}
