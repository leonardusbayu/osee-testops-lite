package auth

import (
	"context"
	"github.com/jackc/pgx/v5"
	"osee-testops-lite/internal/core"
)

func (s *StaffIdentity) auditPendingChallenge(ctx context.Context, tx pgx.Tx, result StaffChallenge, actor *core.ID, target core.ID, action string) error {
	before, e := s.lockPendingByToken(ctx, tx, result.Token)
	if e != nil {
		return e
	}
	if !before.live(s.now().UTC()) {
		return ErrUnauthenticated
	}
	if e = staffAudit(ctx, tx, actor, target, action); e != nil {
		return e
	}
	after, e := s.lockPendingByToken(ctx, tx, result.Token)
	if e != nil {
		return e
	}
	if !before.sameEnrollment(after) || !after.live(s.now().UTC()) {
		return ErrUnauthenticated
	}
	return nil
}
