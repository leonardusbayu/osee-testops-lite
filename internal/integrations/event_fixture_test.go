package integrations_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"osee-testops-lite/db/migrations"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/integrations"
)

var eventTestNow = time.Date(2026, 10, 9, 5, 0, 0, 0, time.UTC)
var eventTestSecret = []byte(strings.Repeat("synthetic-only-", 3))

func eventID(t *testing.T) core.ID {
	t.Helper()
	id, err := core.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func eventFixture(t *testing.T) (*integrations.EventGateway, *db.Store) {
	t.Helper()
	dsn := os.Getenv("OSEE_TEST_DATABASE_URL")
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/osee_testops_test" || u.RawQuery != "sslmode=disable" {
		t.Fatal("explicit owned isolated test database required")
	}
	base, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal("isolated test database unavailable")
	}
	schema := "test_integrations_" + strings.ReplaceAll(string(eventID(t)), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = base.Exec(context.Background(), "CREATE SCHEMA "+quoted); err != nil {
		base.Close()
		t.Fatal("isolated schema unavailable")
	}
	cfg := base.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.RuntimeParams["application_name"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("isolated pool unavailable")
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := base.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("exact integration schema teardown failed")
		}
		base.Close()
	})
	store := &db.Store{Pool: pool}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal("isolated migration failed")
	}
	if _, err := store.Pool.Exec(context.Background(), migrations.Integrations); err != nil {
		t.Fatal("isolated event migration failed")
	}
	gateway, err := integrations.NewEventGateway(store, integrations.EventConfig{Secrets: map[string][]byte{"tinycommand": eventTestSecret, "trafft": eventTestSecret, "anychat": eventTestSecret, "partner": eventTestSecret}, Clock: func() time.Time { return eventTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	return gateway, store
}

func eventBody(source, event, object, payload string) []byte {
	return []byte(fmt.Sprintf(`{"source":%q,"event_id":%q,"kind":"registration.submitted","object_id":%q,"payload":%s}`, source, event, object, payload))
}

func eventRequest(source string, when time.Time, body []byte) *http.Request {
	timestamp := strconv.FormatInt(when.Unix(), 10)
	mac := hmac.New(sha256.New, eventTestSecret)
	_, _ = mac.Write([]byte(source + "\n" + timestamp + "\n"))
	_, _ = mac.Write(body)
	r := httptest.NewRequest(http.MethodPost, "/integrations/events", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-OSEE-Source", source)
	r.Header.Set("X-OSEE-Timestamp", timestamp)
	r.Header.Set("X-OSEE-Signature", "v1="+hex.EncodeToString(mac.Sum(nil)))
	return r
}

func eventPost(gateway *integrations.EventGateway, source string, body []byte) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, eventRequest(source, eventTestNow, body))
	return recorder
}
