package intake

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"time"
)

type Service struct{ authority *auth.Service }

func NewService(authority *auth.Service) *Service { return &Service{authority: authority} }
func (s *Service) Submit(ctx context.Context, in core.IntakeCommand) (core.Registration, error) {
	return s.submit(ctx, in, "")
}
func (s *Service) submit(ctx context.Context, in core.IntakeCommand, target core.ID) (core.Registration, error) {
	if s == nil || s.authority == nil {
		return core.Registration{}, auth.ErrUnavailable
	}
	// Snapshot the explicit consent choice; database waits must not change the command.
	if in.CommunicationConsent != nil {
		choice := *in.CommunicationConsent
		in.CommunicationConsent = &choice
	}
	in.ConsentedAt = in.ConsentedAt.UTC().Truncate(time.Microsecond)
	var outcome core.Registration
	held := false
	err := s.authority.WithIntakeTx(ctx, func(tx pgx.Tx, p core.Principal) error {
		if target != "" && p.Role != core.RoleOwner && p.Role != core.RoleAdmin {
			return auth.ErrForbidden
		}
		if err := validateCommand(in); err != nil {
			return err
		}
		if err := validateProfile(in, target == ""); err != nil {
			return err
		}
		source, err := sourceFor(p, in)
		if err != nil {
			return err
		}
		hash, err := commandFingerprint(in, target)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, queries.IntakeSourceLock, source); err != nil {
			return err
		}
		outcome, held, err = s.submitTx(ctx, tx, p, source, in, hash, target)
		return err
	})
	if err != nil {
		return core.Registration{}, err
	}
	// Conflict evidence commits, but the rejected command never returns an accepted outcome.
	if held {
		return core.Registration{}, core.ErrConflict
	}
	return outcome, nil
}

func (s *Service) submitTx(ctx context.Context, tx pgx.Tx, p core.Principal, source string, in core.IntakeCommand, hash string, target core.ID) (core.Registration, bool, error) {
	var receipt core.ID
	var originalHash string
	var snapshot []byte
	err := tx.QueryRow(ctx, queries.IntakeReceipt, source, in.EventReference).Scan(&receipt, &originalHash, &snapshot)
	if err == nil {
		if originalHash == hash && len(snapshot) > 0 {
			outcome, err := decodeOutcome(snapshot)
			return outcome, false, err
		}
		reason := "event_reuse"
		if len(snapshot) == 0 {
			reason = "receipt_collision"
		}
		err = recordConflict(ctx, tx, p, receipt, source, in, hash, reason)
		return core.Registration{}, true, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.Registration{}, false, err
	}
	err = tx.QueryRow(ctx, queries.IntakeOrder, source, in.OrderReference).Scan(&receipt)
	if err == nil {
		err = recordConflict(ctx, tx, p, receipt, source, in, hash, "order_reuse")
		return core.Registration{}, true, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.Registration{}, false, err
	}
	_, err = lockSession(ctx, tx, in)
	if err != nil {
		return core.Registration{}, false, err
	}
	outcome, err := createOutcome(ctx, tx, p, source, in, hash, target)
	if err != nil {
		return core.Registration{}, false, err
	}
	// Re-read current persisted schedule after downstream transactional work.
	if _, err = lockSession(ctx, tx, in); err != nil {
		return core.Registration{}, false, err
	}
	return outcome, false, nil
}
