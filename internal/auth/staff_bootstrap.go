package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

func (s *StaffIdentity) EnsureBootstrap(ctx context.Context) (StaffChallenge, error) {
	return s.writeEmptyBootstrap(ctx, false)
}
func (s *StaffIdentity) ResetEmptyBootstrap(ctx context.Context) (StaffChallenge, error) {
	return s.writeEmptyBootstrap(ctx, true)
}
func (s *StaffIdentity) noEnrolledStaff(ctx context.Context, tx pgx.Tx) error {
	var occupied bool
	query := `select exists(select 1 from auth_principals p left join auth_staff_credentials c on c.principal_id=p.id
where p.role in ('owner','admin') and (p.enabled or c.factor_version is not null))`
	if err := tx.QueryRow(ctx, query).Scan(&occupied); err != nil {
		return err
	}
	if occupied {
		return ErrForbidden
	}
	return nil
}
func (s *StaffIdentity) writeEmptyBootstrap(ctx context.Context, reset bool) (StaffChallenge, error) {
	var result StaffChallenge
	err := s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.lockInstance(ctx, tx, !reset); err != nil {
			return err
		}
		if err := s.noEnrolledStaff(ctx, tx); err != nil {
			return err
		}
		b, err := s.lockBootstrap(ctx, tx)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if b.finalized != nil {
			return ErrForbidden
		}
		if !reset && err == nil {
			return core.ErrConflict
		}
		if reset && errors.Is(err, pgx.ErrNoRows) {
			return core.ErrConflict
		}
		now := s.now().UTC()
		if reset {
			if _, err = tx.Exec(ctx, "update auth_staff_challenges set revoked_at=$2 where instance_id=$1 and consumed_at is null and revoked_at is null", s.instance, now); err != nil {
				return err
			}
		}
		token, err := newSecret()
		if err != nil {
			return err
		}
		digest, err := tokenDigest(token)
		if err != nil {
			return err
		}
		expires := now.Add(10 * time.Minute)
		changed, err := tx.Exec(ctx, queries.WriteBootstrap, s.instance, digest[:], now, expires)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return ErrForbidden
		}
		action := "staff_bootstrap_created"
		if reset {
			action = "staff_bootstrap_reset"
		}
		if err = staffAudit(ctx, tx, nil, s.instance, action); err != nil {
			return err
		}
		result = StaffChallenge{Token: token, ExpiresAt: expires}
		return nil
	})
	if err != nil {
		return StaffChallenge{}, err
	}
	return result, nil
}
func (s *StaffIdentity) pendingOwner(ctx context.Context, tx pgx.Tx, username, passwordHash string) (staffCredential, error) {
	rows, err := tx.Query(ctx, `select c.principal_id::text from auth_staff_credentials c join auth_principals p on p.id=c.principal_id
where c.instance_id=$1 and c.role='owner' and c.factor_version is null and not p.enabled for update of c,p`, s.instance)
	if err != nil {
		return staffCredential{}, err
	}
	var ids []core.ID
	for rows.Next() {
		var id core.ID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return staffCredential{}, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return staffCredential{}, err
	}
	if len(ids) > 1 {
		return staffCredential{}, ErrForbidden
	}
	if len(ids) == 1 {
		if _, err = tx.Exec(ctx, "update auth_staff_credentials set username=$3,password_hash=$4,credential_epoch=credential_epoch+1 where instance_id=$1 and principal_id=$2 and factor_version is null", s.instance, ids[0], username, passwordHash); err != nil {
			return staffCredential{}, err
		}
		return s.lockCredential(ctx, tx, ids[0])
	}
	id, err := core.NewID()
	if err != nil {
		return staffCredential{}, err
	}
	if _, err = tx.Exec(ctx, "insert into auth_principals(id,role,enabled) values($1,'owner',false)", id); err != nil {
		return staffCredential{}, err
	}
	if _, err = tx.Exec(ctx, queries.CreateStaffCredential, s.instance, id, "owner", username, passwordHash); err != nil {
		return staffCredential{}, err
	}
	return s.lockCredential(ctx, tx, id)
}
