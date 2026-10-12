package auth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
)

func lifecycleEnrollment(kind string) bool { return kind == "replacement" || kind == "recovery" }
func (s *StaffIdentity) eligibleLifecycleEnrollment(ctx context.Context, tx pgx.Tx, p staffPending) (staffCredential, error) {
	c, e := s.lockCredential(ctx, tx, p.principal)
	if e != nil {
		return c, e
	}
	if !p.live(s.now().UTC()) || !c.active() || c.role != p.role || c.epoch != p.epoch || p.version != *c.factor+1 || p.sealed == nil || p.issuer != nil || p.issuerSession != nil {
		return c, ErrUnauthenticated
	}
	if _, e = s.readFactor(ctx, tx, c, true); e != nil {
		return c, e
	}
	if p.kind == "replacement" {
		if p.session == nil {
			return c, ErrUnauthenticated
		}
		var hash [32]byte
		var raw []byte
		if e = tx.QueryRow(ctx, "select token_hash from auth_sessions where id=$1 and principal_id=$2 and revoked_at is null", *p.session, p.principal).Scan(&raw); e != nil {
			return c, e
		}
		if len(raw) != len(hash) {
			return c, ErrUnauthenticated
		}
		copy(hash[:], raw)
		principal, e := s.service.resolveHash(ctx, tx, hash, true)
		if e != nil {
			return c, e
		}
		if !staff(principal) || principal.UserID != c.principal {
			return c, ErrUnauthenticated
		}
	} else if p.kind != "recovery" || p.session != nil {
		return c, ErrUnauthenticated
	}
	return c, nil
}
func (s *StaffIdentity) prepareEnrollmentActivation(ctx context.Context, tx pgx.Tx, c staffCredential, p staffPending, now time.Time) error {
	if !lifecycleEnrollment(p.kind) {
		return nil
	}
	if e := s.revokeStaffAccess(ctx, tx, c.principal, now, p.id); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, queries.RevokeStaffRecovery, s.instance, c.principal, now); e != nil {
		return e
	}
	changed, e := tx.Exec(ctx, queries.RevokeStaffFactors, s.instance, c.principal, now)
	if e != nil {
		return e
	}
	if changed.RowsAffected() != 1 {
		return ErrUnauthenticated
	}
	return nil
}
func (s *StaffIdentity) replacementFreshAtCommit(ctx context.Context, tx pgx.Tx, p staffPending, activated time.Time) error {
	if p.kind != "replacement" {
		return nil
	}
	if p.session == nil {
		return ErrUnauthenticated
	}
	var created, expires, verified, aCreated, aExpires, aVerified time.Time
	var revoked *time.Time
	var epoch, version int64
	e := tx.QueryRow(ctx, `select s.created_at,s.expires_at,s.mfa_verified_at,s.revoked_at,a.session_created_at,a.session_expires_at,a.verified_at,a.credential_epoch,a.factor_version
 from auth_sessions s join auth_staff_attestations a on a.session_id=s.id and a.principal_id=s.principal_id
 where s.id=$1 and s.principal_id=$2 and a.instance_id=$3 for update of s,a`, *p.session, p.principal, s.instance).Scan(&created, &expires, &verified, &revoked, &aCreated, &aExpires, &aVerified, &epoch, &version)
	if e != nil {
		return e
	}
	now := s.now().UTC()
	if !created.Equal(aCreated) || !expires.Equal(aExpires) || !verified.Equal(aVerified) || revoked == nil || !revoked.Equal(activated.Truncate(time.Microsecond)) || epoch != p.epoch || version != p.version-1 || created.After(now) || verified.After(now) || !expires.After(now) || !verified.Add(5*time.Minute).After(now) {
		return ErrUnauthenticated
	}
	return nil
}
