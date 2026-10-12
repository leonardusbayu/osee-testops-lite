package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func request(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}
func TestFoundationPageLabelsUnavailableFeatures(t *testing.T) {
	w := request(FoundationRouter(nil), "/")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, label := range []string{"Local development foundation", "Outbound disabled", "Live providers unverified", "Participant/admin workflows not yet implemented", "T04–T28", "<main", "<h1", `lang="en"`} {
		if !strings.Contains(w.Body.String(), label) {
			t.Errorf("missing %q", label)
		}
	}
}
func TestLivenessDoesNotClaimWorkerHealth(t *testing.T) {
	w := request(FoundationRouter(nil), "/health/live")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"web":"live"}` {
		t.Fatal("liveness must report only web process")
	}
}
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("OSEE_TEST_DATABASE_URL")
	u, e := url.Parse(dsn)
	if e != nil || u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/osee_testops_test" || u.RawQuery != "sslmode=disable" {
		t.Fatal("isolated test database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal("test pool setup failed")
	}
	if e = p.Ping(ctx); e != nil {
		t.Fatal("test database unreachable")
	}
	return p
}
func TestReadinessRequiresDatabase(t *testing.T) {
	p := testPool(t)
	h := FoundationRouter(p)
	if w := request(h, "/health/ready"); w.Code != 200 {
		t.Error("connected database should be ready")
	}
	p.Close()
	if w := request(h, "/health/ready"); w.Code != 503 {
		t.Error("closed database must not be ready")
	}
	if w := request(FoundationRouter(nil), "/health/ready"); w.Code != 503 {
		t.Error("nil database must not be ready")
	}
}
func TestHTTPErrorRedactsSecrets(t *testing.T) {
	p := testPool(t)
	p.Close()
	w := request(FoundationRouter(p), "/health/ready")
	if w.Code != 503 || strings.TrimSpace(w.Body.String()) != `{"database":"unavailable"}` {
		t.Fatal("readiness error must be fixed non-sensitive response")
	}
	for _, s := range []string{"osee_dev", "synthetic_dev_only", "postgres:", "pool closed"} {
		if strings.Contains(w.Body.String(), s) {
			t.Error("internal detail exposed")
		}
	}
}
func TestHTTPServerTimeouts(t *testing.T) {
	s := NewServer("127.0.0.1:0", FoundationRouter(nil))
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes <= 0 {
		t.Fatal("HTTP server must set explicit finite timeouts and header bound")
	}
}
