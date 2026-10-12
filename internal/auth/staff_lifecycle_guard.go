package auth

import (
	"bytes"
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

type staffActionTicket struct {
	credential                 staffCredential
	session                    *core.ID
	created, expires, verified time.Time
}
type staffActionEffect struct {
	credential staffCredential
	revokedAt  *time.Time
}

func (s *StaffIdentity) lockStaffAction(ctx context.Context, tx pgx.Tx, proof sessionProof, ownerOnly bool) (staffActionTicket, error) {
	var ticket staffActionTicket
	principal, e := s.service.resolveHash(ctx, tx, proof.hash, true)
	if e != nil {
		return ticket, e
	}
	if !staff(principal) || ownerOnly && principal.Role != core.RoleOwner {
		return ticket, ErrForbidden
	}
	ticket.credential, e = s.lockCredential(ctx, tx, principal.UserID)
	if e != nil {
		return ticket, e
	}
	var id core.ID
	e = tx.QueryRow(ctx, "select id::text,created_at,expires_at,mfa_verified_at from auth_sessions where token_hash=$1 and principal_id=$2 and revoked_at is null", proof.hash[:], principal.UserID).Scan(&id, &ticket.created, &ticket.expires, &ticket.verified)
	ticket.session = &id
	return ticket, e
}
func (t staffActionTicket) same(other staffActionTicket) bool {
	return t.credential.sameCredential(other.credential) && sameStaffID(t.session, other.session) && t.created.Equal(other.created) && t.expires.Equal(other.expires) && t.verified.Equal(other.verified)
}
func (s *StaffIdentity) withStaffAction(ctx context.Context, password, code string, ownerOnly bool, mutate func(context.Context, pgx.Tx, staffActionTicket) (staffActionEffect, error)) error {
	proof, e := s.service.proof(ctx)
	if e != nil {
		return e
	}
	var prior staffActionTicket
	e = s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if e := s.lockInstance(ctx, tx, false); e != nil {
			return e
		}
		var e error
		prior, e = s.lockStaffAction(ctx, tx, proof, ownerOnly)
		return e
	})
	if e != nil {
		return e
	}
	valid := verifyStaffPassword(*prior.credential.password, password)
	var outcome error
	e = s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if e := s.lockInstance(ctx, tx, false); e != nil {
			return e
		}
		current, e := s.lockStaffAction(ctx, tx, proof, ownerOnly)
		if e != nil {
			return e
		}
		if !prior.same(current) {
			return ErrUnauthenticated
		}
		blocked, e := s.accountBlocked(ctx, tx, current.credential.username, s.now().UTC())
		if e != nil {
			return e
		}
		if blocked {
			outcome = ErrRateLimited
			return nil
		}
		factor, e := s.readFactor(ctx, tx, current.credential, true)
		if e != nil {
			return e
		}
		counter, codeErr := acceptedTOTPCounter(factor.seed, code, s.now().UTC(), factor.counter)
		if !valid || codeErr != nil {
			outcome = ErrUnauthenticated
			return s.failedLogin(ctx, tx, current.credential.username, current.credential.principal)
		}
		changed, e := tx.Exec(ctx, queries.AcceptStaffFactorCounter, s.instance, current.credential.principal, *current.credential.factor, counter)
		if e != nil {
			return e
		}
		if changed.RowsAffected() != 1 {
			return ErrUnauthenticated
		}
		effect, e := mutate(ctx, tx, current)
		if e != nil {
			return e
		}
		return s.verifyStaffActionCommit(ctx, tx, proof, current, effect, factor, counter, code)
	})
	if e != nil {
		return e
	}
	return outcome
}
func (s *StaffIdentity) verifyStaffActionCommit(ctx context.Context, tx pgx.Tx, proof sessionProof, ticket staffActionTicket, effect staffActionEffect, factor staffFactor, counter int64, code string) error {
	c, e := s.lockCredential(ctx, tx, ticket.credential.principal)
	if e != nil {
		return e
	}
	if !effect.credential.sameCredential(c) {
		return ErrUnauthenticated
	}
	actual, e := s.readFactor(ctx, tx, c, true)
	if e != nil {
		return e
	}
	if actual.counter != counter || !bytes.Equal(actual.sealed, factor.sealed) || !actual.enrolled.Equal(factor.enrolled) {
		return ErrUnauthenticated
	}
	var id core.ID
	var created, expires, verified time.Time
	var revoked *time.Time
	e = tx.QueryRow(ctx, "select id::text,created_at,expires_at,mfa_verified_at,revoked_at from auth_sessions where token_hash=$1 and principal_id=$2", proof.hash[:], c.principal).Scan(&id, &created, &expires, &verified, &revoked)
	if e != nil {
		return e
	}
	if ticket.session == nil || id != *ticket.session || !created.Equal(ticket.created) || !expires.Equal(ticket.expires) || !verified.Equal(ticket.verified) {
		return ErrUnauthenticated
	}
	if effect.revokedAt == nil && revoked != nil || effect.revokedAt != nil && (revoked == nil || !revoked.Equal(*effect.revokedAt)) {
		return ErrUnauthenticated
	}
	var epoch, version int64
	var aCreated, aExpires, aVerified time.Time
	e = tx.QueryRow(ctx, "select credential_epoch,factor_version,session_created_at,session_expires_at,verified_at from auth_staff_attestations where instance_id=$1 and principal_id=$2 and session_id=$3", s.instance, c.principal, id).Scan(&epoch, &version, &aCreated, &aExpires, &aVerified)
	if e != nil {
		return e
	}
	if epoch != ticket.credential.epoch || version != *ticket.credential.factor || !aCreated.Equal(created) || !aExpires.Equal(expires) || !aVerified.Equal(verified) {
		return ErrUnauthenticated
	}
	now := s.now().UTC()
	if created.After(now) || verified.After(now) || !expires.After(now) || !verified.Add(5*time.Minute).After(now) {
		return ErrUnauthenticated
	}
	_, e = acceptedTOTPCounter(factor.seed, code, now, counter-1)
	return e
}
