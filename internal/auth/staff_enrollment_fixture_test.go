package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

type staffIdentityTestFixture struct {
	store    *db.Store
	service  *Service
	identity *StaffIdentity
	instance core.ID
	key      []byte
}

func staffIdentityFixture(t *testing.T) staffIdentityTestFixture {
	t.Helper()
	base := testStore(t)
	schema := "staff_identity_" + strings.ReplaceAll(string(testID(t)), "-", "")
	testExec(t, base, "create schema "+pgx.Identifier{schema}.Sanitize())
	t.Cleanup(func() {
		testExec(t, base, "drop schema "+pgx.Identifier{schema}.Sanitize()+" cascade")
	})
	config, err := pgxpool.ParseConfig(base.Pool.Config().ConnString())
	if err != nil {
		t.Fatal("synthetic staff schema configuration failed")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("synthetic staff schema pool failed")
	}
	store := &db.Store{Pool: pool}
	t.Cleanup(store.Close)
	if err = store.Migrate(ctx); err != nil {
		t.Fatal("synthetic staff schema migration failed")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal("synthetic key generation failed")
	}
	instance := testID(t)
	service := NewService(store, nil)
	identity, err := NewStaffIdentity(service, key, instance)
	if err != nil {
		t.Fatal("valid staff identity construction failed")
	}
	return staffIdentityTestFixture{store: store, service: service, identity: identity, instance: instance, key: key}
}

func staffBeginOwner(t *testing.T, f staffIdentityTestFixture, username, password string) StaffChallenge {
	t.Helper()
	capability, err := f.identity.EnsureBootstrap(context.Background())
	if err != nil || capability.Token == "" {
		t.Fatal("trusted empty bootstrap must create one private capability")
	}
	pending, err := f.identity.BeginEnrollment(context.Background(), capability.Token, username, password)
	if err != nil || pending.Token == "" {
		t.Fatal("valid capability must begin pending enrollment")
	}
	return pending
}

func staffSyntheticCode(t *testing.T, view StaffEnrollmentView, at time.Time) string {
	t.Helper()
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(view.Secret)
	if err != nil || len(seed) != 32 {
		t.Fatal("synthetic new factor must contain 32 random bytes")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, seed)
	if _, err = mac.Write(counter[:]); err != nil {
		t.Fatal("synthetic authenticator failed")
	}
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func staffConfirmSynthetic(t *testing.T, f staffIdentityTestFixture, pending StaffChallenge) StaffEnrollmentResult {
	t.Helper()
	view, err := f.identity.EnrollmentView(context.Background(), pending.Token)
	if err != nil {
		t.Fatal("live pending enrollment must expose only its new factor")
	}
	result, err := f.identity.ConfirmEnrollment(context.Background(), pending.Token, staffSyntheticCode(t, view, f.identity.now()))
	if err != nil || result.Session.Token == "" || len(result.RecoveryCodes) != 10 {
		t.Fatal("real cryptographic synthetic confirmation must create session and recovery digests")
	}
	return result
}

func staffEnrollmentCounts(t *testing.T, f staffIdentityTestFixture) [5]int {
	t.Helper()
	var owners, credentials, factors, sessions, attestations int
	statement := `select
(select count(*) from auth_principals where role='owner' and enabled),
(select count(*) from auth_staff_credentials where factor_version is not null),
(select count(*) from auth_staff_factors where revoked_at is null),
(select count(*) from auth_sessions where revoked_at is null),
(select count(*) from auth_staff_attestations)`
	if err := f.store.Pool.QueryRow(context.Background(), statement).Scan(&owners, &credentials, &factors, &sessions, &attestations); err != nil {
		t.Fatal("synthetic enrollment census failed")
	}
	return [5]int{owners, credentials, factors, sessions, attestations}
}

func staffAdminCapability(t *testing.T, f staffIdentityTestFixture, owner StaffSession) StaffChallenge {
	t.Helper()
	hash, err := tokenDigest(owner.Token)
	if err != nil {
		t.Fatal("synthetic owner session invalid")
	}
	var issuer, session core.ID
	if err = f.store.Pool.QueryRow(context.Background(), "select principal_id::text,id::text from auth_sessions where token_hash=$1", hash[:]).Scan(&issuer, &session); err != nil {
		t.Fatal("synthetic owner session lookup failed")
	}
	admin, challenge := testID(t), testID(t)
	token, digest := testSecret(t)
	testExec(t, f.store, "insert into auth_principals(id,role,enabled) values($1,'admin',false)", admin)
	testExec(t, f.store, queries.CreateStaffCredential, f.instance, admin, "admin", "admin.fixture", nil)
	now := f.identity.now()
	testExec(t, f.store, queries.CreateStaffChallenge, challenge, f.instance, admin, "admin", "admin_invite", digest, int64(1), int64(1), nil, nil, issuer, session, now, now.Add(5*time.Minute))
	return StaffChallenge{Token: token, ExpiresAt: now.Add(5 * time.Minute)}
}
