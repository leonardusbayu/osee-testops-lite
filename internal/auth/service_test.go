package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

func testStore(t *testing.T) *db.Store {
	t.Helper()
	dsn := os.Getenv("OSEE_TEST_DATABASE_URL")
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "osee-testops-db" || u.Port() != "5432" || u.Path != "/osee_testops_test" || u.RawQuery != "sslmode=disable" {
		t.Fatal("explicit isolated test database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal("isolated test database unavailable")
	}
	t.Cleanup(store.Close)
	if err = store.Migrate(ctx); err != nil {
		t.Fatal("migration failed", err)
	}
	return store
}
func testID(t *testing.T) core.ID {
	t.Helper()
	v, err := core.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func testExec(t *testing.T, s *db.Store, sql string, args ...any) {
	t.Helper()
	if _, err := s.Pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal("fixture persistence failed", err)
	}
}
func testSecret(t *testing.T) (string, []byte) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	return token, h[:]
}
func testPrincipal(t *testing.T, s *db.Store, role core.Role) core.Principal {
	t.Helper()
	p := core.Principal{UserID: testID(t), Role: role}
	if role == core.RoleParticipant {
		p.ParticipantID = testID(t)
		testExec(t, s, "insert into participants(id,email,phone) values($1,'shared@example.invalid','synthetic-shared')", p.ParticipantID)
	}
	if role == core.RolePartner {
		p.PartnerID = testID(t)
	}
	var participant, partner any
	if p.ParticipantID != "" {
		participant = p.ParticipantID
	}
	if p.PartnerID != "" {
		partner = p.PartnerID
	}
	testExec(t, s, "insert into auth_principals(id,role,participant_id,partner_id) values($1,$2,$3,$4)", p.UserID, p.Role, participant, partner)
	t.Cleanup(func() {
		for _, q := range []string{"delete from auth_sessions where principal_id=$1", "delete from auth_invites where principal_id=$1", "delete from auth_principals where id=$1"} {
			testExec(t, s, q, p.UserID)
		}
		if p.ParticipantID != "" {
			testExec(t, s, "delete from participants where id=$1", p.ParticipantID)
		}
	})
	return p
}
func testInvite(t *testing.T, s *db.Store, p core.Principal, expired bool) (core.ID, string) {
	t.Helper()
	id, token := testID(t), ""
	var digest []byte
	token, digest = testSecret(t)
	expires := time.Now().UTC().Add(5 * time.Minute)
	if expired {
		expires = time.Now().UTC().Add(-time.Minute)
	}
	testExec(t, s, "insert into auth_invites(id,principal_id,token_hash,created_at,expires_at) values($1,$2,$3,$4,$5)", id, p.UserID, digest, expires.Add(-10*time.Minute), expires)
	return id, token
}
func testSession(t *testing.T, s *db.Store, p core.Principal, expires time.Time, mfa *time.Time) (string, []byte) {
	t.Helper()
	token, h := testSecret(t)
	testExec(t, s, "insert into auth_sessions(id,principal_id,token_hash,created_at,expires_at,mfa_verified_at) values($1,$2,$3,$4,$5,$6)", testID(t), p.UserID, h, expires.Add(-30*time.Minute), expires, mfa)
	return token, h
}
func testRequest(token string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8090/auth/me", nil)
	if token != "" {
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
	}
	return r
}

// Broken expiry/single-use or client-controlled principal selection breaks this real-DB contract.
func TestInviteExpiresAndIsSingleUse(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	_, expired := testInvite(t, store, p, true)
	if _, err := svc.consumeInvite(context.Background(), expired, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Error("expired invite must be rejected")
	}
	_, valid := testInvite(t, store, p, false)
	session, err := svc.consumeInvite(context.Background(), valid, "")
	if err != nil {
		t.Fatal("expected valid invite consumption", err)
	}
	resolved, err := svc.Resolve(context.Background(), testRequest(session.token))
	if err != nil || resolved.UserID != p.UserID || resolved.ParticipantID != p.ParticipantID || resolved.Role != core.RoleParticipant || resolved.MFA {
		t.Fatal("expected intended participant-only principal")
	}
	if _, err = svc.consumeInvite(context.Background(), valid, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Error("replayed invite must be rejected")
	}
}
func TestInviteConsumptionConcurrent(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	_, token := testInvite(t, store, p, false)
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := svc.consumeInvite(context.Background(), token, ""); results <- err }()
	}
	wg.Wait()
	close(results)
	successful := 0
	for err := range results {
		if err == nil {
			successful++
		} else if !errors.Is(err, ErrUnauthenticated) {
			t.Error("unexpected concurrent consume error", err)
		}
	}
	if successful != 1 {
		t.Errorf("expected exactly one successful consumption, got %d", successful)
	}
	var n int
	if err := store.Pool.QueryRow(context.Background(), "select count(*) from auth_sessions where principal_id=$1", p.UserID).Scan(&n); err != nil || n != 1 {
		t.Error("expected exactly one committed session")
	}
}
func TestSharedContactDoesNotReassignIdentity(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	a := testPrincipal(t, store, core.RoleParticipant)
	b := testPrincipal(t, store, core.RoleParticipant)
	_, token := testInvite(t, store, a, false)
	session, err := svc.consumeInvite(context.Background(), token, "")
	if err != nil {
		t.Fatal("expected shared-contact fixture login", err)
	}
	req := testRequest(session.token)
	req.Header.Set("X-Role", "owner")
	req.Header.Set("X-MFA", "true")
	req.Header.Set("X-Participant-ID", string(b.ParticipantID))
	req.URL.RawQuery = "participant_id=" + string(b.ParticipantID) + "&role=system"
	p, err := svc.Resolve(context.Background(), req)
	if err != nil || p.UserID != a.UserID || p.ParticipantID != a.ParticipantID || p.Role != core.RoleParticipant || p.MFA {
		t.Fatal("expected server binding independent of shared contact/client claims")
	}
}
func TestResolveRejectsInvalidExpiredAndDuplicateCookies(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	expired, _ := testSession(t, store, p, time.Now().Add(-time.Minute), nil)
	for _, token := range []string{"", "STUDENT-1234", string(p.ParticipantID), expired} {
		if _, err := svc.Resolve(context.Background(), testRequest(token)); !errors.Is(err, ErrUnauthenticated) {
			t.Error("invalid or expired credential accepted")
		}
	}
	current, _ := testSession(t, store, p, time.Now().Add(10*time.Minute), nil)
	request := testRequest(current)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: current})
	if _, err := svc.Resolve(context.Background(), request); !errors.Is(err, ErrUnauthenticated) {
		t.Error("ambiguous duplicate cookie accepted")
	}
	request = testRequest("")
	request.Header.Set("Authorization", "Bearer "+current)
	if _, err := svc.Resolve(context.Background(), request); !errors.Is(err, ErrUnauthenticated) {
		t.Error("unsupported bearer credential accepted")
	}
}
func TestSessionRotationAndRevocation(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	previous, _ := testSession(t, store, p, time.Now().Add(10*time.Minute), nil)
	_, invite := testInvite(t, store, p, false)
	session, err := svc.consumeInvite(context.Background(), invite, previous)
	if err != nil || session.token == previous {
		t.Fatal("expected fresh rotated session")
	}
	if _, err := svc.Resolve(context.Background(), testRequest(previous)); !errors.Is(err, ErrUnauthenticated) {
		t.Error("old session survived rotation")
	}
	if _, err := svc.Resolve(context.Background(), testRequest(session.token)); err != nil {
		t.Fatal("new session cannot resolve")
	}
	if err := svc.revoke(context.Background(), session.token); err != nil {
		t.Fatal("revoke failed", err)
	}
	if _, err := svc.Resolve(context.Background(), testRequest(session.token)); !errors.Is(err, ErrUnauthenticated) {
		t.Error("revoked session accepted")
	}
}
func TestResolveRechecksDisabledPrincipal(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	token, _ := testSession(t, store, p, time.Now().Add(10*time.Minute), nil)
	if _, err := svc.Resolve(context.Background(), testRequest(token)); err != nil {
		t.Fatal("expected initial session resolution")
	}
	testExec(t, store, "update auth_principals set enabled=false where id=$1", p.UserID)
	if _, err := svc.Resolve(context.Background(), testRequest(token)); !errors.Is(err, ErrUnauthenticated) {
		t.Error("disabled identity retained authority")
	}
}
func TestInviteRollsBackOnCancelledContext(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	invite, token := testInvite(t, store, p, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.consumeInvite(ctx, token, ""); err == nil {
		t.Fatal("cancelled transaction must fail")
	}
	var unused bool
	if err := store.Pool.QueryRow(context.Background(), "select consumed_at is null from auth_invites where id=$1", invite).Scan(&unused); err != nil || !unused {
		t.Fatal("failed session transaction consumed invite")
	}
	if _, err := svc.consumeInvite(context.Background(), token, ""); err != nil {
		t.Fatal("invite should remain usable after rollback")
	}
}

// Captures synthetic delivery only; real DB write/rollback remains intact and no transport is contacted.
type testInviteQueue struct {
	token string
	fail  bool
}

func (q *testInviteQueue) QueueInvite(ctx context.Context, tx pgx.Tx, id, principal core.ID, token string) error {
	q.token = token
	if q.fail {
		return errors.New("synthetic delivery refusal")
	}
	_, err := tx.Exec(ctx, "insert into outbox(id,object_id,event_kind) values($1,$2,'synthetic-auth-delivery')", id, principal)
	return err
}
func TestIssueInviteReturnsRecordOnlyAndGatesDelivery(t *testing.T) {
	genuine, session, _ := legacySyntheticStaff(t, core.RoleOwner)
	store, svc := genuine.store, genuine.service
	queue := &testInviteQueue{}
	svc.queue = queue
	participant := testPrincipal(t, store, core.RoleParticipant)
	ctx := staffLoginContext(t, genuine, session)
	record, err := svc.IssueInvite(ctx, participant.UserID)
	if err != nil {
		t.Fatal("expected authorized invitation issuance", err)
	}
	if _, err = core.ParseID(string(record)); err != nil {
		t.Fatal("issuance must return record ID, not a secret")
	}
	var stored []byte
	if err = store.Pool.QueryRow(ctx, "select token_hash from auth_invites where id=$1", record).Scan(&stored); err != nil {
		t.Fatal("issued record unreadable")
	}
	expected := sha256.Sum256([]byte(queue.token))
	if len(stored) != 32 || string(stored) != string(expected[:]) || queue.token == string(record) {
		t.Fatal("expected hashed delivery credential bound to record")
	}
	// Remove only this inert outbox fixture; real delivery is unavailable.
	testExec(t, store, "delete from outbox where id=$1 and event_kind='synthetic-auth-delivery'", record)
	queue.fail = true
	if _, err = svc.IssueInvite(ctx, participant.UserID); err == nil {
		t.Error("delivery failure must reject issuance")
	}
	var n int
	if err = store.Pool.QueryRow(ctx, "select count(*) from auth_invites where principal_id=$1", participant.UserID).Scan(&n); err != nil || n != 1 {
		t.Error("failed transport left an issued record")
	}
	svc.queue = nil
	if _, err = svc.IssueInvite(ctx, participant.UserID); !errors.Is(err, ErrProviderUnverified) {
		t.Error("default delivery must remain unavailable")
	}
	if _, err = svc.IssueInvite(context.Background(), participant.UserID); !errors.Is(err, ErrUnauthenticated) {
		t.Error("untrusted context issued an invitation")
	}
}

func TestInviteSessionFailureRollsBackConsumedToken(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	invite, token := testInvite(t, store, p, false)
	// Trusted generated identifiers and exact test-principal filter; no client SQL input.
	name := "auth_test_fail_" + strings.ReplaceAll(string(testID(t)), "-", "")
	create := "CREATE FUNCTION " + name + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.principal_id='" + string(p.UserID) + "'::uuid THEN RAISE EXCEPTION 'synthetic session persistence failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER " + name + " BEFORE INSERT ON auth_sessions FOR EACH ROW EXECUTE FUNCTION " + name + "();"
	testExec(t, store, create)
	drop := func() {
		testExec(t, store, "DROP TRIGGER IF EXISTS "+name+" ON auth_sessions; DROP FUNCTION IF EXISTS "+name+"();")
	}
	t.Cleanup(drop)
	if _, err := svc.consumeInvite(context.Background(), token, ""); err == nil {
		t.Error("injected persistence failure must reject login")
	}
	var unused bool
	if err := store.Pool.QueryRow(context.Background(), "select consumed_at is null from auth_invites where id=$1", invite).Scan(&unused); err != nil || !unused {
		t.Fatal("session failure committed consumed invitation")
	}
	var n int
	if err := store.Pool.QueryRow(context.Background(), "select count(*) from auth_sessions where principal_id=$1", p.UserID).Scan(&n); err != nil || n != 0 {
		t.Fatal("failed persistence left a session")
	}
	drop()
	if _, err := svc.consumeInvite(context.Background(), token, ""); err != nil {
		t.Fatal("expected successful retry after exact synthetic failure removal")
	}
}

func TestInviteLoginProducesOneAtomicAudit(t *testing.T) {
	store := testStore(t)
	svc := NewService(store, nil)
	p := testPrincipal(t, store, core.RoleParticipant)
	_, invite := testInvite(t, store, p, false)
	session, err := svc.consumeInvite(context.Background(), invite, "")
	if err != nil {
		t.Fatal("expected audited login")
	}
	digestValue := sha256.Sum256([]byte(session.token))
	digest := digestValue[:]
	var n int
	q := "select count(*) from audit_events a join auth_sessions s on s.id=a.object_id where s.token_hash=$1 and a.action='auth_login'"
	if err = store.Pool.QueryRow(context.Background(), q, digest).Scan(&n); err != nil || n != 1 {
		t.Fatal("expected exactly one committed login audit")
	}
	if _, err = svc.consumeInvite(context.Background(), invite, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("replay accepted")
	}
	if err = store.Pool.QueryRow(context.Background(), q, digest).Scan(&n); err != nil || n != 1 {
		t.Error("replay duplicated audit")
	}
}
