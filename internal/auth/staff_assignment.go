package auth

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

// CheckStaffAssignment validates enrollment without creating a session or authority proof.
func (s *Service) CheckStaffAssignment(ctx context.Context, tx pgx.Tx, id core.ID) error {
	if s == nil || s.staff == nil || tx == nil {
		return ErrUnavailable
	}
	if _, err := s.proof(ctx); err != nil {
		return err
	}
	var found core.ID
	var version int64
	var sealed []byte
	err := tx.QueryRow(ctx, queries.SessionAssignedStaff, id, s.staff.instance, s.authorityTime()).Scan(&found, &version, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ErrInvalidInput
	}
	if err != nil {
		return err
	}
	if found != id {
		return core.ErrInvalidInput
	}
	if _, err = openStaffSeed(s.staff.key[:], sealed, s.staff.seedAAD(id, version)); err != nil {
		return core.ErrInvalidInput
	}
	return nil
}
