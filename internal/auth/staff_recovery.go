package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
)

func (s *StaffIdentity) recoveryBlocked(ctx context.Context, tx pgx.Tx, username string) (bool, error) {
	key := s.loginRateKey("recover_account", loginAccount(username))
	var count int
	e := tx.QueryRow(ctx, "select attempts from auth_staff_rates where instance_id=$1 and key_hash=$2 and (window_started_at>$3 or (attempts>=5 and expires_at>$3)) for update", s.instance, key[:], s.now().UTC()).Scan(&count)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	return e == nil, e
}
func (s *StaffIdentity) recoveryFailure(ctx context.Context, tx pgx.Tx, username string, c staffCredential) error {
	now := s.now().UTC()
	key := s.loginRateKey("recover_account", loginAccount(username))
	var attempts int
	if e := tx.QueryRow(ctx, queries.IncrementStaffRate, s.instance, key[:], "recover_account", now, now.Add(5*time.Minute)).Scan(&attempts); e != nil {
		return e
	}
	target := c.principal
	if target == "" {
		target = s.instance
	}
	return staffAudit(ctx, tx, nil, target, "staff_recovery_failed")
}
func (s *StaffIdentity) BeginRecovery(ctx context.Context, username, password, recoveryCode, peer string) (StaffChallenge, error) {
	var prior staffPasswordSnapshot
	var outcome error
	e := s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if e := s.lockInstance(ctx, tx, false); e != nil {
			return e
		}
		now := s.now().UTC()
		key := s.loginRateKey("recover_peer", loginPeer(peer))
		var attempts int
		if e := tx.QueryRow(ctx, queries.IncrementStaffRate, s.instance, key[:], "recover_peer", now, now.Add(time.Minute)).Scan(&attempts); e != nil {
			return e
		}
		if attempts > 10 {
			outcome = ErrRateLimited
			return nil
		}
		blocked, e := s.recoveryBlocked(ctx, tx, username)
		if e != nil {
			return e
		}
		if blocked {
			outcome = ErrRateLimited
			return nil
		}
		prior, e = s.passwordSnapshot(ctx, tx, staffPasswordInput{username: username})
		return e
	})
	if e != nil {
		return StaffChallenge{}, e
	}
	if outcome != nil {
		return StaffChallenge{}, outcome
	}
	valid := false
	if prior.credential.active() {
		valid = verifyStaffPassword(*prior.credential.password, password)
	} else {
		verifyUnknownStaffPassword(password)
	}
	encoded, digestErr := staffRecoveryDigest(recoveryCode)
	digest, _ := hex.DecodeString(encoded)
	var result StaffChallenge
	e = s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if e := s.lockInstance(ctx, tx, false); e != nil {
			return e
		}
		current, e := s.passwordSnapshot(ctx, tx, staffPasswordInput{username: username})
		if e != nil {
			return e
		}
		blocked, e := s.recoveryBlocked(ctx, tx, username)
		if e != nil {
			return e
		}
		if blocked {
			outcome = ErrRateLimited
			return nil
		}
		c := current.credential
		if !valid || digestErr != nil || !prior.credential.sameCredential(c) {
			outcome = ErrUnauthenticated
			return s.recoveryFailure(ctx, tx, username, c)
		}
		if _, e = s.readFactor(ctx, tx, c, true); e != nil {
			return e
		}
		now := s.now().UTC()
		consumed, e := tx.Exec(ctx, queries.ConsumeStaffRecovery, s.instance, c.principal, *c.factor, digest, now)
		if e != nil {
			return e
		}
		if consumed.RowsAffected() != 1 {
			outcome = ErrUnauthenticated
			return s.recoveryFailure(ctx, tx, username, c)
		}
		if e = s.revokeStaffAccess(ctx, tx, c.principal, now, ""); e != nil {
			return e
		}
		result, e = s.newLifecycleChallenge(ctx, tx, c, "recovery", nil, nil, nil)
		if e != nil {
			return e
		}
		if e = s.auditPendingChallenge(ctx, tx, result, &c.principal, c.principal, "staff_recovery_begun"); e != nil {
			return e
		}
		actual, e := s.lockCredential(ctx, tx, c.principal)
		if e != nil {
			return e
		}
		if !c.sameCredential(actual) {
			return ErrUnauthenticated
		}
		p, e := s.lockPendingByToken(ctx, tx, result.Token)
		if e != nil {
			return e
		}
		if p.kind != "recovery" || p.principal != c.principal || p.epoch != c.epoch || p.version != *c.factor+1 || !p.live(s.now().UTC()) {
			return ErrUnauthenticated
		}
		return nil
	})
	if e != nil {
		return StaffChallenge{}, e
	}
	if outcome != nil {
		return StaffChallenge{}, outcome
	}
	return result, nil
}
