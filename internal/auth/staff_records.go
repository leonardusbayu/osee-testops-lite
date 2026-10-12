package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

type staffCredential struct {
	principal      core.ID
	username, role string
	enabled        bool
	password       *string
	epoch          int64
	factor         *int64
}
type staffPending struct {
	id, principal                  core.ID
	role, kind                     string
	version, epoch                 int64
	sealed                         []byte
	session, issuer, issuerSession *core.ID
	created, expires               time.Time
	consumed, revoked              *time.Time
}
type staffBootstrap struct {
	hash                         []byte
	created, expires             time.Time
	consumed, revoked, finalized *time.Time
}

func staffError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{ErrUnauthenticated, ErrForbidden, ErrUnavailable, ErrRateLimited, core.ErrInvalidInput, core.ErrConflict} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthenticated
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) && postgres.Code == "23505" {
		return core.ErrConflict
	}
	return ErrUnavailable
}

func (s *StaffIdentity) lockCredential(ctx context.Context, tx pgx.Tx, id core.ID) (staffCredential, error) {
	var c staffCredential
	err := tx.QueryRow(ctx, queries.LockStaffCredential, s.instance, id).Scan(&c.principal, &c.username, &c.role, &c.enabled, &c.password, &c.epoch, &c.factor)
	return c, err
}
func (s *StaffIdentity) lockPending(ctx context.Context, tx pgx.Tx, digest [32]byte) (staffPending, error) {
	var p staffPending
	err := tx.QueryRow(ctx, queries.LockStaffChallenge, s.instance, digest[:]).Scan(&p.id, &p.principal, &p.role, &p.kind, &p.version, &p.epoch, &p.sealed, &p.session, &p.issuer, &p.issuerSession, &p.created, &p.expires, &p.consumed, &p.revoked)
	return p, err
}
func (s *StaffIdentity) lockBootstrap(ctx context.Context, tx pgx.Tx) (staffBootstrap, error) {
	var b staffBootstrap
	err := tx.QueryRow(ctx, queries.LockBootstrap, s.instance).Scan(&b.hash, &b.created, &b.expires, &b.consumed, &b.revoked, &b.finalized)
	return b, err
}
func (p staffPending) live(now time.Time) bool {
	return !p.created.After(now) && p.expires.After(now) && p.consumed == nil && p.revoked == nil
}
func (s *StaffIdentity) issuerEligible(ctx context.Context, tx pgx.Tx, p staffPending) error {
	if p.issuer == nil || p.issuerSession == nil {
		return ErrUnauthenticated
	}
	c, err := s.lockCredential(ctx, tx, *p.issuer)
	if err != nil {
		return err
	}
	if c.role != "owner" || !c.enabled || c.factor == nil || c.password == nil {
		return ErrUnauthenticated
	}
	var id core.ID
	if err = tx.QueryRow(ctx, "select id::text from auth_sessions where id=$1 and principal_id=$2 for update", *p.issuerSession, *p.issuer).Scan(&id); err != nil {
		return err
	}
	var version, epoch int64
	var verified time.Time
	now := s.now().UTC()
	if err = tx.QueryRow(ctx, queries.ReadStaffAttestation, s.instance, *p.issuerSession, *p.issuer, now).Scan(&version, &epoch, &verified); err != nil {
		return err
	}
	if version != *c.factor || epoch != c.epoch || verified.After(now) || !verified.Add(5*time.Minute).After(now) {
		return ErrUnauthenticated
	}
	return nil
}
func (s *StaffIdentity) eligibleEnrollment(ctx context.Context, tx pgx.Tx, p staffPending) (staffCredential, error) {
	if lifecycleEnrollment(p.kind) {
		return s.eligibleLifecycleEnrollment(ctx, tx, p)
	}
	if !p.live(s.now().UTC()) || (p.kind != "owner_enroll" && p.kind != "admin_enroll") {
		return staffCredential{}, ErrUnauthenticated
	}
	if p.kind == "admin_enroll" {
		if err := s.issuerEligible(ctx, tx, p); err != nil {
			return staffCredential{}, err
		}
	}
	c, err := s.lockCredential(ctx, tx, p.principal)
	if err != nil {
		return c, err
	}
	if c.role != p.role || c.enabled || c.factor != nil || c.password == nil || c.epoch != p.epoch || p.version != 1 {
		return c, ErrUnauthenticated
	}
	if p.kind == "owner_enroll" {
		b, err := s.lockBootstrap(ctx, tx)
		if err != nil {
			return c, err
		}
		if b.consumed == nil || b.revoked != nil || b.finalized != nil {
			return c, ErrUnauthenticated
		}
	}
	if !p.live(s.now().UTC()) {
		return c, ErrUnauthenticated
	}
	return c, nil
}
func staffAudit(ctx context.Context, tx pgx.Tx, actor *core.ID, target core.ID, action string) error {
	id, err := core.NewID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "insert into audit_events(id,actor_id,object_id,action) values($1,$2,$3,$4)", id, actor, target, action)
	return err
}
