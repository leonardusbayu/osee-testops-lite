package auth

import (
	"bytes"
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

type staffConfirmation struct {
	kind, previous string
	proof          *sessionProof
}

func (s *StaffIdentity) authenticationCredential(ctx context.Context, tx pgx.Tx, p staffPending, in staffConfirmation) (staffCredential, error) {
	c, err := s.lockCredential(ctx, tx, p.principal)
	if err != nil {
		return c, err
	}
	if !p.live(s.now().UTC()) || p.kind != in.kind || p.sealed != nil || p.issuer != nil || p.issuerSession != nil || !c.active() || c.role != p.role || c.epoch != p.epoch || *c.factor != p.version {
		return c, ErrUnauthenticated
	}
	if in.kind == "login" {
		if p.session != nil {
			return c, ErrUnauthenticated
		}
		return c, nil
	}
	if in.kind != "step_up" || in.proof == nil || p.session == nil {
		return c, ErrUnauthenticated
	}
	current, err := s.service.resolveHash(ctx, tx, in.proof.hash, true)
	if err != nil || current.UserID != p.principal {
		return c, ErrUnauthenticated
	}
	var session core.ID
	if err = tx.QueryRow(ctx, "select id::text from auth_sessions where token_hash=$1 and principal_id=$2 and revoked_at is null", in.proof.hash[:], p.principal).Scan(&session); err != nil {
		return c, err
	}
	if session != *p.session {
		return c, ErrUnauthenticated
	}
	return c, nil
}
func (s *StaffIdentity) rotateAuthenticatedSession(ctx context.Context, tx pgx.Tx, c staffCredential, in staffConfirmation, now time.Time) error {
	var digest [32]byte
	if in.proof != nil {
		digest = in.proof.hash
	} else {
		var err error
		digest, err = tokenDigest(in.previous)
		if err != nil {
			return nil
		}
	}
	_, err := tx.Exec(ctx, "update auth_sessions set revoked_at=$3 where token_hash=$1 and principal_id=$2 and revoked_at is null", digest[:], c.principal, now)
	return err
}
func (s *StaffIdentity) confirmAuthentication(ctx context.Context, challenge, code string, in staffConfirmation) (StaffSession, error) {
	digest, err := tokenDigest(challenge)
	if err != nil {
		return StaffSession{}, err
	}
	var result StaffSession
	var outcome error
	err = s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.lockInstance(ctx, tx, false); err != nil {
			return err
		}
		pending, err := s.lockPending(ctx, tx, digest)
		if err != nil {
			return err
		}
		c, err := s.authenticationCredential(ctx, tx, pending, in)
		if err != nil {
			return err
		}
		factor, err := s.readFactor(ctx, tx, c, true)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if !pending.live(now) {
			return ErrUnauthenticated
		}
		blocked, err := s.accountBlocked(ctx, tx, c.username, now)
		if err != nil {
			return err
		}
		if blocked {
			outcome = ErrRateLimited
			return nil
		}
		counter, err := acceptedTOTPCounter(factor.seed, code, s.now().UTC(), factor.counter)
		if err != nil {
			outcome = ErrUnauthenticated
			return s.failedLogin(ctx, tx, c.username, c.principal)
		}
		changed, err := tx.Exec(ctx, queries.AcceptStaffFactorCounter, s.instance, c.principal, *c.factor, counter)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return ErrUnauthenticated
		}
		result, err = s.createStaffSession(ctx, tx, c.principal, *c.factor, c.epoch, now)
		if err != nil {
			return err
		}
		if err = s.rotateAuthenticatedSession(ctx, tx, c, in, now); err != nil {
			return err
		}
		consumed := s.now().UTC().Truncate(time.Microsecond)
		changed, err = tx.Exec(ctx, queries.ConsumeStaffChallenge, s.instance, pending.id, consumed)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return ErrUnauthenticated
		}
		if err = s.clearLoginFailures(ctx, tx, c.username); err != nil {
			return err
		}
		sessionDigest, err := tokenDigest(result.Token)
		if err != nil {
			return err
		}
		var session core.ID
		if err = tx.QueryRow(ctx, "select id::text from auth_sessions where token_hash=$1", sessionDigest[:]).Scan(&session); err != nil {
			return err
		}
		action := "staff_login"
		if in.kind == "step_up" {
			action = "staff_step_up"
		}
		if err = staffAudit(ctx, tx, &c.principal, session, action); err != nil {
			return err
		}
		current, err := s.lockCredential(ctx, tx, c.principal)
		if err != nil {
			return err
		}
		if !c.sameCredential(current) {
			return ErrUnauthenticated
		}
		finalFactor, err := s.readFactor(ctx, tx, current, true)
		if err != nil {
			return err
		}
		if finalFactor.counter != counter || !bytes.Equal(finalFactor.sealed, factor.sealed) {
			return ErrUnauthenticated
		}
		finalPending, err := s.lockPending(ctx, tx, digest)
		if err != nil {
			return err
		}
		if !pending.sameEnrollment(finalPending) || finalPending.revoked != nil || finalPending.consumed == nil || !finalPending.consumed.Equal(consumed) || finalPending.created.After(s.now().UTC()) || !finalPending.expires.After(s.now().UTC()) {
			return ErrUnauthenticated
		}
		if _, err = acceptedTOTPCounter(factor.seed, code, s.now().UTC(), counter-1); err != nil {
			return err
		}
		p, err := s.service.resolveHash(ctx, tx, sessionDigest, true)
		if err != nil || !staff(p) || p.UserID != c.principal {
			return ErrUnauthenticated
		}
		return nil
	})
	if err != nil {
		return StaffSession{}, err
	}
	if outcome != nil {
		return StaffSession{}, outcome
	}
	return result, nil
}
