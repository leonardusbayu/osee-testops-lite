package integrations_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/integrations"
)

func eventExec(t *testing.T, store *db.Store, statement string, args ...any) {
	t.Helper()
	if _, err := store.Pool.Exec(context.Background(), statement, args...); err != nil {
		t.Fatal("isolated event fixture operation failed")
	}
}

func eventCount(t *testing.T, store *db.Store, statement string, args ...any) int {
	t.Helper()
	var count int
	if err := store.Pool.QueryRow(context.Background(), statement, args...).Scan(&count); err != nil {
		t.Fatal("isolated event observation failed")
	}
	return count
}

func TestEventConcurrentReplayPersistsOneSignal(t *testing.T) {
	gateway, store := eventFixture(t)
	body := eventBody("tinycommand", "concurrent-event", string(eventID(t)), `{"email":"private@example.invalid"}`)
	type observed struct {
		status  int
		receipt integrations.EventReceipt
	}
	observations := make(chan observed, 12)
	var workers sync.WaitGroup
	for range 12 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			response := eventPost(gateway, "tinycommand", body)
			var receipt integrations.EventReceipt
			_ = json.Unmarshal(response.Body.Bytes(), &receipt)
			observations <- observed{response.Code, receipt}
		}()
	}
	workers.Wait()
	close(observations)
	var receipt core.ID
	created := 0
	for result := range observations {
		if result.status != http.StatusAccepted && result.status != http.StatusOK {
			t.Fatalf("concurrent status=%d", result.status)
		}
		if result.status == http.StatusAccepted {
			created++
		}
		if receipt == "" {
			receipt = result.receipt.ReceiptID
		}
		if receipt == "" || result.receipt.ReceiptID != receipt {
			t.Fatal("concurrent replay produced different durable receipts")
		}
	}
	if created != 1 {
		t.Fatalf("new receipt acknowledgments=%d, want one", created)
	}
	for _, statement := range []string{
		"select count(*) from inbound_receipts where provider='gateway:tinycommand'",
		"select count(*) from integration_events",
		"select count(*) from audit_events where action='integration_event_received'",
		"select count(*) from outbox where event_kind='integration.event.received'",
	} {
		if eventCount(t, store, statement) != 1 {
			t.Fatal("receipt event audit and outbound intent must each persist exactly once")
		}
	}
	var signal string
	if err := store.Pool.QueryRow(context.Background(), "select payload::text from outbox where event_kind='integration.event.received'").Scan(&signal); err != nil || strings.Contains(signal, "private@example.invalid") {
		t.Fatal("outbox must reference the private receipt without copying contact payload")
	}
}

func TestEventConflictIsAuditedWithoutReplacingOriginal(t *testing.T) {
	gateway, store := eventFixture(t)
	object := string(eventID(t))
	original := eventBody("tinycommand", "conflict-event", object, `{"status":"original"}`)
	if response := eventPost(gateway, "tinycommand", original); response.Code != 202 {
		t.Fatal("original not received")
	}
	changed := eventBody("tinycommand", "conflict-event", object, `{"status":"changed"}`)
	for range 3 {
		if response := eventPost(gateway, "tinycommand", changed); response.Code != 409 {
			t.Fatal("changed identity not held as conflict")
		}
	}
	if response := eventPost(gateway, "tinycommand", original); response.Code != 200 {
		t.Fatal("conflict overwrote original event")
	}
	for _, statement := range []string{"select count(*) from integration_event_conflicts", "select count(*) from audit_events where action='integration_event_conflict'", "select count(*) from outbox where event_kind='integration.event.conflict'"} {
		if eventCount(t, store, statement) != 1 {
			t.Fatal("repeated conflict must record one audit and exception intent")
		}
	}
	if _, err := store.Pool.Exec(context.Background(), "update integration_events set payload='{}'::jsonb"); err == nil {
		t.Fatal("received observations must remain immutable")
	}
}

func TestEventOutboxFailureRollsBackAndRetryRemainsNew(t *testing.T) {
	gateway, store := eventFixture(t)
	eventExec(t, store, `CREATE FUNCTION reject_event_signal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic signal failure'; END $$; CREATE TRIGGER reject_event_signal BEFORE INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION reject_event_signal();`)
	body := eventBody("tinycommand", "rollback-event", string(eventID(t)), `{}`)
	if response := eventPost(gateway, "tinycommand", body); response.Code != 503 {
		t.Fatal("failed durable intent must not be acknowledged")
	}
	for _, statement := range []string{"select count(*) from integration_events", "select count(*) from inbound_receipts where provider='gateway:tinycommand'", "select count(*) from audit_events where action='integration_event_received'"} {
		if eventCount(t, store, statement) != 0 {
			t.Fatal("failed event retained partial transactional effects")
		}
	}
	eventExec(t, store, "DROP TRIGGER reject_event_signal ON outbox")
	if response := eventPost(gateway, "tinycommand", body); response.Code != 202 {
		t.Fatal("rolled back input must be accepted as new after recovery")
	}
}

func TestEventObservationCannotVerifyPaymentOrReleaseResult(t *testing.T) {
	gateway, store := eventFixture(t)
	participant, registration, payment := eventID(t), eventID(t), eventID(t)
	eventExec(t, store, "insert into participants(id) values($1)", participant)
	eventExec(t, store, "insert into registrations(id,participant_id) values($1,$2)", registration, participant)
	eventExec(t, store, "insert into payments(id,minor_units,currency) values($1,10000,'IDR')", payment)
	body := eventBody("tinycommand", "observation-only", string(registration), `{"payment_state":"VERIFIED","result_state":"RELEASED","score":900}`)
	body = []byte(strings.Replace(string(body), `"registration.submitted"`, `"result.imported"`, 1))
	if response := eventPost(gateway, "tinycommand", body); response.Code != 202 {
		t.Fatal("authenticated observation was not received")
	}
	if eventCount(t, store, "select count(*) from payments where id=$1 and payment_state='PENDING'", payment) != 1 || eventCount(t, store, "select count(*) from registrations where id=$1 and result_state='NOT_RECEIVED' and registration_state='DRAFT'", registration) != 1 || eventCount(t, store, "select count(*) from payment_allocations") != 0 {
		t.Fatal("transport receipt changed unverified business state")
	}
}

func TestEventServiceCancellationAndSourceNamespace(t *testing.T) {
	gateway, store := eventFixture(t)
	object := string(eventID(t))
	body := eventBody("tinycommand", "shared-event-key", object, `{}`)
	request := eventRequest("tinycommand", eventTestNow, body)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := gateway.Receive(ctx, "tinycommand", request.Header.Get("X-OSEE-Timestamp"), request.Header.Get("X-OSEE-Signature"), body)
	if !errors.Is(err, integrations.ErrEventUnavailable) {
		t.Fatal("cancelled service call must not be acknowledged")
	}
	if response := eventPost(gateway, "tinycommand", body); response.Code != 202 {
		t.Fatal("cancelled event did not remain new")
	}
	partner := eventBody("partner", "shared-event-key", object, `{}`)
	if response := eventPost(gateway, "partner", partner); response.Code != 202 {
		t.Fatal("source namespaces must be independent")
	}
	if eventCount(t, store, "select count(*) from integration_events") != 2 {
		t.Fatal("independent source observations collided")
	}
	request = eventRequest("tinycommand", eventTestNow, body)
	_, err = gateway.Receive(context.Background(), "tinycommand", strconv.FormatInt(eventTestNow.Add(-6*time.Minute).Unix(), 10), request.Header.Get("X-OSEE-Signature"), body)
	if !errors.Is(err, integrations.ErrEventUnauthorized) {
		t.Fatal("expired service authentication must be rejected")
	}
}
