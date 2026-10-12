package web

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"osee-testops-lite/internal/db"
	"strings"
	"testing"
	"time"
)

const localOrigin = "http://127.0.0.1:8090"

func localRequest(handler http.Handler, path string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", localOrigin+path, nil)
	handler.ServeHTTP(response, request)
	return response
}
func localTestStore(t *testing.T) *db.Store {
	t.Helper()
	pool := testPool(t)
	t.Cleanup(pool.Close)
	store := &db.Store{Pool: pool}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal("synthetic migration failed")
	}
	return store
}
func TestLocalRouterComposesAuthWithoutMaskingSecurityHeaders(t *testing.T) {
	store := localTestStore(t)
	handler, err := LocalRouter(store, localOrigin)
	if err != nil {
		t.Fatal("local composition failed")
	}
	response := localRequest(handler, "/auth/login")
	if response.Code != 200 || !strings.Contains(response.Body.String(), "Participant invitation sign-in") {
		t.Error("reviewed login route not composed")
	}
	if response.Header().Get("Cache-Control") != "no-store" || !strings.Contains(response.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Error("authentication security headers were lost/masked")
	}
	response = localRequest(handler, "/auth/me")
	if response.Code != 401 {
		t.Error("missing session did not fail closed")
	}
	response = localRequest(handler, "/")
	if response.Code != 200 || !strings.Contains(response.Body.String(), `href="/auth/login"`) || !strings.Contains(response.Body.String(), "Invite delivery is not configured") {
		t.Error("root lacks honest local sign-in link/boundary")
	}
	response = localRequest(handler, "/health/ready")
	if response.Code != 200 {
		t.Error("migrated synthetic auth should be ready")
	}
}
func TestLocalRouterRejectsInvalidStoreAndOrigin(t *testing.T) {
	if _, err := LocalRouter(nil, localOrigin); err == nil {
		t.Error("nil store accepted")
	}
	store := localTestStore(t)
	if _, err := LocalRouter(store, "http://192.0.2.1:8090"); err == nil {
		t.Error("public origin accepted")
	}
}
func TestLocalReadinessRequiresAuthRelations(t *testing.T) {
	original := localTestStore(t)
	config := original.Pool.Config()
	config.ConnConfig.RuntimeParams["search_path"] = "pg_catalog"
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal("synthetic pool setup failed")
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatal("database ping should work independently of auth relations")
	}
	handler, err := LocalRouter(&db.Store{Pool: pool}, localOrigin)
	if err != nil {
		t.Fatal("local handler setup failed")
	}
	if response := localRequest(handler, "/health/ready"); response.Code != 503 {
		t.Error("readiness claims auth-ready when schema is inaccessible")
	}
	if response := localRequest(handler, "/health/live"); response.Code != 200 {
		t.Error("schema absence changed process liveness")
	}
}
