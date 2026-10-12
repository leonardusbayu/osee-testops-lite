package intake

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
)

func (s *Service) SubmitForParticipant(ctx context.Context, target core.ID, in core.IntakeCommand) (core.Registration, error) {
	if _, err := core.ParseID(string(target)); err != nil {
		return core.Registration{}, core.ErrInvalidInput
	}
	return s.submit(ctx, in, target)
}
func resolveSelectedPerson(ctx context.Context, tx pgx.Tx, p core.Principal, source string, in *core.IntakeCommand, target core.ID) (core.ID, error) {
	err := tx.QueryRow(ctx, queries.IntakeSelectedPerson, target).Scan(&in.Name, &in.Email, &in.Phone)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", core.ErrInvalidInput
	}
	if err != nil {
		return "", err
	}
	var bound core.ID
	err = tx.QueryRow(ctx, queries.IntakePerson, source, in.PersonReference).Scan(&bound)
	if err == nil {
		if bound != target {
			return "", core.ErrConflict
		}
		return target, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	_, err = tx.Exec(ctx, queries.IntakeBindPerson, source, in.PersonReference, target, p.UserID)
	return target, err
}
func (s *Service) Receipt(ctx context.Context, eventReference string) (core.Registration, error) {
	if s == nil || s.authority == nil {
		return core.Registration{}, auth.ErrUnavailable
	}
	var result core.Registration
	err := s.authority.WithIntakeTx(ctx, func(tx pgx.Tx, p core.Principal) error {
		if !referencePattern.MatchString(eventReference) {
			return core.ErrInvalidInput
		}
		var source string
		switch p.Role {
		case core.RoleOwner, core.RoleAdmin:
			source = "staff:" + string(p.UserID)
		case core.RoleParticipant:
			source = "central:" + string(p.ParticipantID)
		case core.RolePartner:
			source = "partner:" + string(p.PartnerID)
		default:
			return auth.ErrForbidden
		}
		var receipt core.ID
		var hash string
		var raw []byte
		if err := tx.QueryRow(ctx, queries.IntakeReceipt, source, eventReference).Scan(&receipt, &hash, &raw); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return core.ErrInvalidInput
			}
			return err
		}
		var err error
		result, err = decodeOutcome(raw)
		return err
	})
	if err != nil {
		return core.Registration{}, err
	}
	return result, nil
}
