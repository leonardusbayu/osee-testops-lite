package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

type staffFactor struct {
	sealed   []byte
	seed     []byte
	counter  int64
	enrolled time.Time
	revoked  *time.Time
}

func (s *StaffIdentity) readFactor(ctx context.Context, q queryer, c staffCredential, lock bool) (staffFactor, error) {
	var factor staffFactor
	if !c.active() {
		return factor, ErrUnauthenticated
	}
	statement := "select encrypted_seed,last_totp_counter,enrolled_at,revoked_at from auth_staff_factors where instance_id=$1 and principal_id=$2 and factor_version=$3"
	if lock {
		statement = queries.LockStaffFactor
	}
	if err := q.QueryRow(ctx, statement, s.instance, c.principal, *c.factor).Scan(&factor.sealed, &factor.counter, &factor.enrolled, &factor.revoked); err != nil {
		return factor, err
	}
	if factor.revoked != nil || factor.enrolled.After(s.now().UTC()) {
		return factor, ErrUnauthenticated
	}
	seed, err := openStaffSeed(s.key[:], factor.sealed, s.seedAAD(c.principal, *c.factor))
	if err != nil {
		return factor, ErrUnavailable
	}
	factor.seed = seed
	return factor, nil
}
func (s *Service) lockAuthority(ctx context.Context, tx pgx.Tx) error {
	if s.staff == nil {
		return nil
	}
	err := s.staff.lockInstance(ctx, tx, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrForbidden
	}
	return err
}
func (s *Service) authorityTime() time.Time {
	if s.staff != nil {
		return s.staff.now().UTC()
	}
	return time.Now().UTC()
}
func (s *Service) currentStaffMFA(ctx context.Context, q queryer, hash [32]byte, p core.Principal, lock bool) (bool, error) {
	if s.staff == nil {
		return false, ErrForbidden
	}
	if lock {
		tx, ok := q.(pgx.Tx)
		if !ok {
			return false, ErrUnavailable
		}
		if _, err := s.staff.lockCredential(ctx, tx, p.UserID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return false, ErrForbidden
			}
			return false, err
		}
		var session core.ID
		if err := tx.QueryRow(ctx, `select a.session_id::text from auth_staff_attestations a join auth_sessions s on s.id=a.session_id
where a.instance_id=$1 and a.principal_id=$2 and s.token_hash=$3 for update of a`, s.staff.instance, p.UserID, hash[:]).Scan(&session); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return false, ErrForbidden
			}
			return false, err
		}
	}
	var verified, enrolled time.Time
	var sealed []byte
	var version int64
	statement := `select a.verified_at,f.enrolled_at,f.encrypted_seed,a.factor_version from auth_sessions s
join auth_principals p on p.id=s.principal_id
join auth_staff_attestations a on a.session_id=s.id and a.principal_id=p.id
join auth_staff_credentials c on c.instance_id=a.instance_id and c.principal_id=p.id and c.role=p.role
join auth_staff_factors f on f.instance_id=c.instance_id and f.principal_id=c.principal_id and f.factor_version=c.factor_version
join app_instance i on i.id=c.instance_id and i.singleton
where s.token_hash=$1 and p.id=$2 and c.instance_id=$3 and p.role=$4 and p.enabled
and c.password_hash is not null and c.credential_epoch=a.credential_epoch and c.factor_version=a.factor_version
and f.revoked_at is null and s.revoked_at is null and s.created_at=a.session_created_at and s.expires_at=a.session_expires_at
and s.mfa_verified_at=a.verified_at and a.verified_at>=s.created_at and a.verified_at<=s.expires_at
and f.enrolled_at<=a.verified_at and s.created_at<=$5 and s.expires_at>$5`
	now := s.authorityTime()
	if err := q.QueryRow(ctx, statement, hash[:], p.UserID, s.staff.instance, p.Role, now).Scan(&verified, &enrolled, &sealed, &version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrForbidden
		}
		return false, ErrUnavailable
	}
	if _, err := openStaffSeed(s.staff.key[:], sealed, s.staff.seedAAD(p.UserID, version)); err != nil {
		return false, ErrUnavailable
	}
	now = s.authorityTime()
	if verified.After(now) || enrolled.After(now) {
		return false, ErrForbidden
	}
	return verified.Add(5 * time.Minute).After(now), nil
}
func (s *Service) CurrentPrincipal(ctx context.Context) (core.Principal, error) {
	proof, err := s.proof(ctx)
	if err != nil {
		return core.Principal{}, err
	}
	if s.store == nil || s.store.Pool == nil {
		return core.Principal{}, ErrUnavailable
	}
	return s.resolveHash(ctx, s.store.Pool, proof.hash, false)
}
