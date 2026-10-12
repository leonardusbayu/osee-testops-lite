package auth

import (
	"context"
	"github.com/jackc/pgx/v5"
	"net/http"
	"osee-testops-lite/internal/core"
)

func (s *Service) RequireIntake(next http.Handler) http.Handler {
	return s.require(next, "session")
}

func intakeAuthority(p core.Principal) bool {
	return p.Role == core.RoleParticipant || p.Role == core.RolePartner || staff(p)
}

// Opaque request proof and current identity, not command fields, determine the source.
func (s *Service) WithIntakeTx(ctx context.Context, fn func(pgx.Tx, core.Principal) error) error {
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
		if !intakeAuthority(current) {
			return ErrForbidden
		}
		before := current
		if err = fn(tx, current); err != nil {
			return err
		}
		current, err = s.resolveHash(ctx, tx, proof.hash, true)
		if err != nil {
			return err
		}
		if current != before || !intakeAuthority(current) {
			return ErrForbidden
		}
		return nil
	})
	return safeError(err)
}
