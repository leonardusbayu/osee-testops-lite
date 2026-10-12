package intake

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"osee-testops-lite/internal/testfixtures"
)

const testOrigin = "http://127.0.0.1:8090"

type fixture struct {
	store     *db.Store
	authority *auth.Service
	service   *Service
	actor     core.Principal
	token     string
	session   core.ID
}

func newID(t *testing.T) core.ID {
	t.Helper()
	value, err := core.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func persist(t *testing.T, store *db.Store, statement string, args ...any) {
	t.Helper()
	if _, err := store.Pool.Exec(context.Background(), statement, args...); err != nil {
		t.Fatal("isolated fixture persistence failed", err)
	}
}
func testFixture(t *testing.T, role core.Role) *fixture {
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
	schema := "test_intake_" + strings.ReplaceAll(string(newID(t)), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = base.Exec(context.Background(), "CREATE SCHEMA "+quoted); err != nil {
		base.Close()
		t.Fatal(err)
	}
	cfg := base.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.RuntimeParams["application_name"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := base.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error("exact schema teardown failed")
		}
		base.Close()
	})
	store := &db.Store{Pool: pool}
	if err = store.Migrate(context.Background()); err != nil {
		t.Fatal("isolated migration failed", err)
	}
	f := &fixture{store: store, actor: core.Principal{UserID: newID(t), Role: role}, session: newID(t)}
	switch role {
	case core.RoleParticipant:
		f.actor.ParticipantID = newID(t)
		persist(t, store, "insert into participants(id,email,phone) values($1,'original@example.invalid','shared-phone')", f.actor.ParticipantID)
		persist(t, store, "insert into auth_principals(id,role,participant_id) values($1,'participant',$2)", f.actor.UserID, f.actor.ParticipantID)
	case core.RolePartner:
		f.actor.PartnerID = newID(t)
		persist(t, store, "insert into auth_principals(id,role,partner_id) values($1,'partner',$2)", f.actor.UserID, f.actor.PartnerID)
	default:
		genuine := testfixtures.NewStaff(t, store, role)
		f.actor = genuine.Principal
		f.token = genuine.Session.Token
		f.authority = genuine.Authority
	}
	if f.authority == nil {
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			t.Fatal("synthetic participant session material unavailable")
		}
		f.token = base64.RawURLEncoding.EncodeToString(secret[:])
		hash := sha256.Sum256([]byte(f.token))
		persist(t, store, "insert into auth_sessions(id,principal_id,token_hash,created_at,expires_at) values($1,$2,$3,now()-interval '10 minutes',now()+interval '20 minutes')", newID(t), f.actor.UserID, hash[:])
		f.authority = auth.NewService(store, nil)
	}
	persist(t, store, "insert into sessions(id,starts_at,cutoff_at,capacity) values($1,now()+interval '2 days',now()+interval '1 day',20)", f.session)
	f.service = NewService(f.authority)
	return f
}

// Private staff fixtures confirm actual passwords/factors; claimed identities are never proofs.
func (f *fixture) proof(t *testing.T, fn func(context.Context)) {
	t.Helper()
	req := httptest.NewRequest("POST", testOrigin+"/internal-intake-test", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: f.token})
	req.Header.Set("Origin", testOrigin)
	csrf, err := f.authority.RequestCSRF(req)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-CSRF-Token", csrf)
	called := false
	out := httptest.NewRecorder()
	f.authority.RequireIntake(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; fn(r.Context()); w.WriteHeader(204) })).ServeHTTP(out, req)
	if !called || out.Code != 204 {
		t.Fatalf("synthetic proof boundary denied: %d", out.Code)
	}
}
func (f *fixture) submit(t *testing.T, in core.IntakeCommand) (core.Registration, error) {
	t.Helper()
	var registration core.Registration
	var err error
	f.proof(t, func(ctx context.Context) { registration, err = f.service.Submit(ctx, in) })
	return registration, err
}
func input(f *fixture, suffix string) core.IntakeCommand {
	consent := true
	return core.IntakeCommand{EventReference: "event-" + suffix, OrderReference: "order-" + suffix, SessionID: f.session, ScheduleVersion: 1, ProductReference: "synthetic-test", PersonReference: "person-" + suffix, Name: "Synthetic Participant", Email: "new@example.invalid", Phone: "shared-phone", CommunicationConsent: &consent, ConsentVersion: "synthetic-consent-v1", ConsentedAt: time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)}
}
func count(t *testing.T, f *fixture, statement string, args ...any) int {
	t.Helper()
	var result int
	if err := f.store.Pool.QueryRow(context.Background(), statement, args...).Scan(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
func accepted(t *testing.T, f *fixture, in core.IntakeCommand) core.Registration {
	t.Helper()
	registration, err := f.submit(t, in)
	if err != nil {
		t.Fatalf("expected persisted intake: %v", err)
	}
	if _, err = core.ParseID(string(registration.ID)); err != nil {
		t.Fatal("registration ID missing")
	}
	return registration
}
