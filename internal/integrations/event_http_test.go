package integrations_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"osee-testops-lite/internal/integrations"
)

func TestEventHTTPRequiresAuthentication(t *testing.T) {
	gateway, err := integrations.NewEventGateway(nil, integrations.EventConfig{Secrets: map[string][]byte{"tinycommand": []byte(strings.Repeat("s", 32))}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/integrations/events", strings.NewReader(`{"source":"tinycommand","event_id":"synthetic-event-1","kind":"registration.submitted","object_id":"30b3c57e-f91f-4615-b21b-ad31c998fc6d","payload":{}}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned event status=%d, want 401", recorder.Code)
	}
}

func TestEventHTTPDurableReceiptReplaysAndRejectsConflict(t *testing.T) {
	gateway, _ := eventFixture(t)
	object := string(eventID(t))
	body := eventBody("tinycommand", "synthetic-event-1", object, `{"status":"created","count":1}`)
	first := eventPost(gateway, "tinycommand", body)
	if first.Code != http.StatusAccepted {
		t.Fatalf("authenticated observation status=%d, want 202", first.Code)
	}
	var accepted integrations.EventReceipt
	if err := json.Unmarshal(first.Body.Bytes(), &accepted); err != nil || accepted.Status != "received" || accepted.ReceiptID == "" || accepted.Replayed {
		t.Fatal("missing durable received receipt")
	}
	reordered := eventBody("tinycommand", "synthetic-event-1", object, `{ "count": 1, "status": "created" }`)
	replay := eventPost(gateway, "tinycommand", reordered)
	var repeated integrations.EventReceipt
	if err := json.Unmarshal(replay.Body.Bytes(), &repeated); err != nil || replay.Code != http.StatusOK || repeated.ReceiptID != accepted.ReceiptID || !repeated.Replayed {
		t.Fatal("semantic replay did not retain the original receipt")
	}
	changed := eventBody("tinycommand", "synthetic-event-1", object, `{"status":"changed","count":1}`)
	conflict := eventPost(gateway, "tinycommand", changed)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("changed event identity status=%d, want 409", conflict.Code)
	}
}
