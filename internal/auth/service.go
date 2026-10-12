package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

var (
	ErrUnauthenticated    = errors.New("unauthenticated")
	ErrForbidden          = errors.New("forbidden")
	ErrProviderUnverified = errors.New("provider_unverified")
	ErrUnavailable        = errors.New("temporarily_unavailable")
)

const SessionCookieName = "osee_completion_r1_session"
const invitationLifetime = 10 * time.Minute
const sessionLifetime = 30 * time.Minute

// InvitationQueue is a trusted transactional boundary. Implementations must
// encrypt delivery secrets, bind the verified recipient, and enqueue using tx.
// A nil queue is unavailable; this package implements no delivery provider.
type InvitationQueue interface {
	QueueInvite(context.Context, pgx.Tx, core.ID, core.ID, string) error
}
type Service struct {
	store   *db.Store
	queue   InvitationQueue
	csrfKey [32]byte
	staff   *StaffIdentity
}
type issuedSession struct {
	token     string
	expiresAt time.Time
}
type proofContextKey struct{}
type sessionProof struct {
	service *Service
	hash    [32]byte
}
type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func NewService(store *db.Store, queue InvitationQueue) *Service {
	s := &Service{store: store, queue: queue}
	if _, err := rand.Read(s.csrfKey[:]); err != nil {
		s.store = nil
	}
	return s
}
func newSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
func tokenDigest(token string) ([32]byte, error) {
	if len(token) != 43 {
		return [32]byte{}, ErrUnauthenticated
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return [32]byte{}, ErrUnauthenticated
	}
	return sha256.Sum256([]byte(token)), nil
}
func uniqueCookie(r *http.Request, name string) (string, error) {
	if r == nil {
		return "", ErrUnauthenticated
	}
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			count++
			value = cookie.Value
		}
	}
	if count != 1 || value == "" {
		return "", ErrUnauthenticated
	}
	return value, nil
}
func (s *Service) Resolve(ctx context.Context, r *http.Request) (core.Principal, error) {
	token, err := uniqueCookie(r, SessionCookieName)
	if err != nil {
		return core.Principal{}, err
	}
	hash, err := tokenDigest(token)
	if err != nil {
		return core.Principal{}, err
	}
	if s.store == nil {
		return core.Principal{}, ErrUnavailable
	}
	return s.resolveHash(ctx, s.store.Pool, hash, false)
}
func (s *Service) resolveHash(ctx context.Context, q queryer, hash [32]byte, lock bool) (core.Principal, error) {
	statement := queries.ResolveSession
	if lock {
		tx, ok := q.(pgx.Tx)
		if !ok {
			return core.Principal{}, ErrUnavailable
		}
		if err := s.lockAuthority(ctx, tx); err != nil {
			return core.Principal{}, safeError(err)
		}
		statement = queries.ResolveSessionLocked
	}
	var p core.Principal
	var role string
	var mfa *time.Time
	var created, expires time.Time
	err := q.QueryRow(ctx, statement, hash[:]).Scan(&p.UserID, &p.ParticipantID, &p.PartnerID, &role, &mfa, &created, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return core.Principal{}, ErrUnavailable
	}
	// Use the wall clock after row locks, never a timestamp captured before waiting.
	now := s.authorityTime()
	if created.After(now) || !expires.After(now) {
		return core.Principal{}, ErrUnauthenticated
	}
	p.Role = core.Role(role)
	if _, err = core.ParseID(string(p.UserID)); err != nil {
		return core.Principal{}, ErrUnauthenticated
	}
	switch p.Role {
	case core.RoleParticipant:
		if _, err = core.ParseID(string(p.ParticipantID)); err != nil || p.PartnerID != "" {
			return core.Principal{}, ErrUnauthenticated
		}
	case core.RolePartner:
		if _, err = core.ParseID(string(p.PartnerID)); err != nil || p.ParticipantID != "" {
			return core.Principal{}, ErrUnauthenticated
		}
	case core.RoleAdmin, core.RoleOwner:
		if p.ParticipantID != "" || p.PartnerID != "" {
			return core.Principal{}, ErrUnauthenticated
		}
	default:
		return core.Principal{}, ErrUnauthenticated
	}
	if p.Role == core.RoleOwner || p.Role == core.RoleAdmin {
		p.MFA, err = s.currentStaffMFA(ctx, q, hash, p, lock)
		if err != nil {
			return core.Principal{}, safeError(err)
		}
	}
	return p, nil
}
func (s *Service) proof(ctx context.Context) (sessionProof, error) {
	p, ok := ctx.Value(proofContextKey{}).(sessionProof)
	if !ok || p.service != s {
		return sessionProof{}, ErrUnauthenticated
	}
	return p, nil
}
func staff(p core.Principal) bool {
	return (p.Role == core.RoleAdmin || p.Role == core.RoleOwner) && p.MFA
}
func safeError(err error) error {
	if err == nil || errors.Is(err, core.ErrInvalidInput) || errors.Is(err, core.ErrConflict) || errors.Is(err, core.ErrReviewRequired) || errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrForbidden) || errors.Is(err, ErrProviderUnverified) || errors.Is(err, ErrRateLimited) {
		return err
	}
	return ErrUnavailable
}
func audit(ctx context.Context, tx pgx.Tx, actor, object core.ID, action string) error {
	id, err := core.NewID()
	if err != nil {
		return ErrUnavailable
	}
	_, err = tx.Exec(ctx, queries.AuthAudit, id, actor, object, action)
	return err
}
func (s *Service) IssueInvite(ctx context.Context, principalID core.ID) (core.ID, error) {
	proof, err := s.proof(ctx)
	if err != nil {
		return "", err
	}
	if s.store == nil {
		return "", ErrUnavailable
	}
	var record core.ID
	err = s.store.WithTx(ctx, func(tx pgx.Tx) error {
		actor, err := s.resolveHash(ctx, tx, proof.hash, true)
		if err != nil {
			return err
		}
		if !staff(actor) {
			return ErrForbidden
		}
		if s.queue == nil {
			return ErrProviderUnverified
		}
		if _, err = core.ParseID(string(principalID)); err != nil {
			return ErrForbidden
		}
		var target core.ID
		err = tx.QueryRow(ctx, queries.InvitationTarget, principalID).Scan(&target)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		record, err = core.NewID()
		if err != nil {
			return err
		}
		secret, err := newSecret()
		if err != nil {
			return err
		}
		hash, _ := tokenDigest(secret)
		now := time.Now().UTC()
		if _, err = tx.Exec(ctx, queries.CreateInvite, record, target, hash[:], now, now.Add(invitationLifetime)); err != nil {
			return err
		}
		if err = s.queue.QueueInvite(ctx, tx, record, target, secret); err != nil {
			return err
		}
		return audit(ctx, tx, actor.UserID, record, "auth_invite_issued")
	})
	if err != nil {
		return "", safeError(err)
	}
	return record, nil
}
func (s *Service) consumeInvite(ctx context.Context, token, previous string) (issuedSession, error) {
	hash, err := tokenDigest(token)
	if err != nil {
		return issuedSession{}, err
	}
	if s.store == nil {
		return issuedSession{}, ErrUnavailable
	}
	var result issuedSession
	err = s.store.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.lockAuthority(ctx, tx); err != nil {
			return err
		}
		var invite, principal core.ID
		var created, expires time.Time
		err := tx.QueryRow(ctx, queries.LockInvite, hash[:]).Scan(&invite, &principal, &created, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthenticated
		}
		if err != nil {
			return err
		}
		now := s.authorityTime()
		if created.After(now) || !expires.After(now) {
			return ErrUnauthenticated
		}
		id, err := core.NewID()
		if err != nil {
			return err
		}
		result.token, err = newSecret()
		if err != nil {
			return err
		}
		sessionHash, _ := tokenDigest(result.token)
		result.expiresAt = now.Add(sessionLifetime)
		if _, err = tx.Exec(ctx, queries.ConsumeInvite, invite, now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, queries.CreateSession, id, principal, sessionHash[:], now, result.expiresAt); err != nil {
			return err
		}
		if previousHash, e := tokenDigest(previous); e == nil {
			if _, err = tx.Exec(ctx, "update auth_sessions set revoked_at=$3 where token_hash=$1 and principal_id=$2 and revoked_at is null", previousHash[:], principal, now); err != nil {
				return err
			}
		}
		return audit(ctx, tx, principal, id, "auth_login")
	})
	if err != nil {
		return issuedSession{}, safeError(err)
	}
	return result, nil
}
func (s *Service) revoke(ctx context.Context, token string) error {
	hash, err := tokenDigest(token)
	if err != nil {
		return err
	}
	if s.store == nil {
		return ErrUnavailable
	}
	err = s.store.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.lockAuthority(ctx, tx); err != nil {
			return err
		}
		var id, principal core.ID
		err := tx.QueryRow(ctx, queries.RevokeSession, hash[:], s.authorityTime()).Scan(&id, &principal)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, principal, id, "auth_logout")
	})
	return safeError(err)
}
