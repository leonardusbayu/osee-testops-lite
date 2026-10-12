package auth

import (
	"context"
	"github.com/jackc/pgx/v5"
	"osee-testops-lite/internal/core"
)

// WithStaffTx requires this service's opaque middleware proof, locks current
// authority, and rechecks its wall-clock lifetime immediately before commit.
func (s *Service) WithStaffTx(ctx context.Context, actor core.Principal, fn func(pgx.Tx, core.Principal) error) error {
	proof, err := s.proof(ctx)
	if err != nil {
		return err
	}
	if s.store == nil || s.store.Pool == nil || fn == nil {
		return ErrUnavailable
	}
	err = s.store.WithTx(ctx, func(tx pgx.Tx) error {
		current, err := s.resolveHash(ctx, tx, proof.hash, true)
		if err != nil {
			return err
		}
		if !staff(current) || actor != current {
			return ErrForbidden
		}
		if err = fn(tx, current); err != nil {
			return err
		}
		current, err = s.resolveHash(ctx, tx, proof.hash, true)
		if err != nil {
			return err
		}
		if !staff(current) || actor != current {
			return ErrForbidden
		}
		return nil
	})
	return safeError(err)
}
