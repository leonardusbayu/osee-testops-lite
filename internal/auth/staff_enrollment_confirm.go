package auth

import (
	"bytes"
	"context"
	"encoding/hex"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

func sameStaffID(a, b *core.ID) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func (p staffPending) sameEnrollment(other staffPending) bool {
	return p.id == other.id && p.principal == other.principal && p.role == other.role && p.kind == other.kind && p.version == other.version && p.epoch == other.epoch && bytes.Equal(p.sealed, other.sealed) && p.created.Equal(other.created) && p.expires.Equal(other.expires) && sameStaffID(p.session, other.session) && sameStaffID(p.issuer, other.issuer) && sameStaffID(p.issuerSession, other.issuerSession)
}

func (s *StaffIdentity) ConfirmEnrollment(ctx context.Context, challenge, code string) (StaffEnrollmentResult, error) {
	digest, err := tokenDigest(challenge)
	if err != nil {
		return StaffEnrollmentResult{}, err
	}
	var result StaffEnrollmentResult
	err = s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.lockInstance(ctx, tx, false); err != nil {
			return err
		}
		pending, err := s.lockPending(ctx, tx, digest)
		if err != nil {
			return err
		}
		credential, err := s.eligibleEnrollment(ctx, tx, pending)
		if err != nil {
			return err
		}
		if pending.kind == "owner_enroll" {
			if err = s.noEnrolledStaff(ctx, tx); err != nil {
				return err
			}
		}
		seed, err := openStaffSeed(s.key[:], pending.sealed, s.seedAAD(pending.principal, pending.version))
		if err != nil {
			return ErrUnavailable
		}
		now := s.now().UTC()
		counter, err := acceptedTOTPCounter(seed, code, now, -1)
		if err != nil {
			return err
		}
		if err = s.prepareEnrollmentActivation(ctx, tx, credential, pending, now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, queries.CreateStaffFactor, s.instance, pending.principal, pending.version, pending.sealed, counter, now); err != nil {
			return err
		}
		var epoch int64
		if err = tx.QueryRow(ctx, queries.ActivateStaffFactor, s.instance, pending.principal, pending.version, credential.epoch).Scan(&epoch); err != nil {
			return err
		}
		changed, err := tx.Exec(ctx, "update auth_principals set enabled=true where id=$1 and role=$2 and enabled=$3", pending.principal, pending.role, lifecycleEnrollment(pending.kind))
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return ErrUnauthenticated
		}
		session, err := s.createStaffSession(ctx, tx, pending.principal, pending.version, epoch, now)
		if err != nil {
			return err
		}
		codes, hashes, err := newStaffRecoveryMaterial()
		if err != nil {
			return err
		}
		for i, encoded := range hashes {
			hash, err := hex.DecodeString(encoded)
			if err != nil {
				return ErrUnavailable
			}
			if _, err = tx.Exec(ctx, queries.CreateStaffRecovery, s.instance, pending.principal, pending.version, i+1, hash, now); err != nil {
				return err
			}
		}
		action := "staff_enrolled"
		if pending.kind == "replacement" {
			action = "staff_factor_replaced"
		}
		if pending.kind == "recovery" {
			action = "staff_recovery_completed"
		}
		if err = staffAudit(ctx, tx, &pending.principal, pending.principal, action); err != nil {
			return err
		}
		current, err := s.lockCredential(ctx, tx, pending.principal)
		if err != nil {
			return err
		}
		if !current.enabled || current.role != pending.role || current.factor == nil || *current.factor != pending.version || current.epoch != epoch {
			return ErrUnauthenticated
		}
		currentPending, err := s.lockPending(ctx, tx, digest)
		if err != nil {
			return err
		}
		if !currentPending.sameEnrollment(pending) || !currentPending.live(s.now().UTC()) {
			return ErrUnauthenticated
		}
		if pending.kind == "admin_enroll" {
			if err = s.issuerEligible(ctx, tx, pending); err != nil {
				return err
			}
		}
		if err = s.replacementFreshAtCommit(ctx, tx, pending, now); err != nil {
			return err
		}
		if _, err = acceptedTOTPCounter(seed, code, s.now().UTC(), -1); err != nil {
			return err
		}
		changed, err = tx.Exec(ctx, queries.ConsumeStaffChallenge, s.instance, pending.id, s.now().UTC())
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return ErrUnauthenticated
		}
		if pending.kind == "owner_enroll" {
			changed, err = tx.Exec(ctx, queries.CloseBootstrap, s.instance, s.now().UTC())
			if err != nil {
				return err
			}
			if changed.RowsAffected() != 1 {
				return ErrUnauthenticated
			}
		}
		result = StaffEnrollmentResult{Session: session, RecoveryCodes: codes}
		return nil
	})
	if err != nil {
		return StaffEnrollmentResult{}, err
	}
	return result, nil
}
func (s *StaffIdentity) createStaffSession(ctx context.Context, tx pgx.Tx, principal core.ID, version, epoch int64, now time.Time) (StaffSession, error) {
	id, err := core.NewID()
	if err != nil {
		return StaffSession{}, err
	}
	token, err := newSecret()
	if err != nil {
		return StaffSession{}, err
	}
	digest, err := tokenDigest(token)
	if err != nil {
		return StaffSession{}, err
	}
	expires := now.Add(30 * time.Minute)
	if _, err = tx.Exec(ctx, queries.CreateSession, id, principal, digest[:], now, expires); err != nil {
		return StaffSession{}, err
	}
	if _, err = tx.Exec(ctx, "update auth_sessions set mfa_verified_at=$2 where id=$1", id, now); err != nil {
		return StaffSession{}, err
	}
	changed, err := tx.Exec(ctx, queries.CreateStaffAttestation, id, s.instance, version, epoch, now)
	if err != nil {
		return StaffSession{}, err
	}
	if changed.RowsAffected() != 1 {
		return StaffSession{}, ErrUnavailable
	}
	return StaffSession{Token: token, ExpiresAt: expires}, nil
}
