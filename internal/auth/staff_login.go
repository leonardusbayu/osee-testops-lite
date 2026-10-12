package auth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

type staffPasswordInput struct {
	username, password, peer string
	proof                    *sessionProof
}
type staffPasswordSnapshot struct {
	credential staffCredential
	session    *core.ID
}

func (c staffCredential) active() bool {
	return c.enabled && c.password != nil && c.factor != nil && (c.role == "owner" || c.role == "admin")
}
func (c staffCredential) sameCredential(other staffCredential) bool {
	return c.principal == other.principal && c.username == other.username && c.role == other.role && c.enabled == other.enabled && c.epoch == other.epoch && c.password != nil && other.password != nil && *c.password == *other.password && c.factor != nil && other.factor != nil && *c.factor == *other.factor
}
func (s *StaffIdentity) passwordSnapshot(ctx context.Context, tx pgx.Tx, in staffPasswordInput) (staffPasswordSnapshot, error) {
	var snapshot staffPasswordSnapshot
	if in.proof == nil {
		if !validStaffUsername(in.username) {
			return snapshot, nil
		}
		c := &snapshot.credential
		err := tx.QueryRow(ctx, queries.LockStaffUsername, s.instance, in.username).Scan(&c.principal, &c.username, &c.role, &c.enabled, &c.password, &c.epoch, &c.factor)
		if errors.Is(err, pgx.ErrNoRows) {
			return staffPasswordSnapshot{}, nil
		}
		return snapshot, err
	}
	current, err := s.service.resolveHash(ctx, tx, in.proof.hash, true)
	if err != nil {
		return snapshot, err
	}
	if current.Role != core.RoleOwner && current.Role != core.RoleAdmin {
		return snapshot, ErrForbidden
	}
	snapshot.credential, err = s.lockCredential(ctx, tx, current.UserID)
	if err != nil {
		return snapshot, err
	}
	var id core.ID
	if err = tx.QueryRow(ctx, "select id::text from auth_sessions where token_hash=$1 and principal_id=$2 and revoked_at is null", in.proof.hash[:], current.UserID).Scan(&id); err != nil {
		return snapshot, err
	}
	snapshot.session = &id
	return snapshot, nil
}
func (s *StaffIdentity) BeginLogin(ctx context.Context, username, password, peer string) (StaffChallenge, error) {
	return s.beginPassword(ctx, staffPasswordInput{username: username, password: password, peer: peer})
}
func (s *StaffIdentity) BeginStepUp(ctx context.Context, password string) (StaffChallenge, error) {
	proof, err := s.service.proof(ctx)
	if err != nil {
		return StaffChallenge{}, err
	}
	return s.beginPassword(ctx, staffPasswordInput{password: password, proof: &proof})
}
func (s *StaffIdentity) beginPassword(ctx context.Context, in staffPasswordInput) (StaffChallenge, error) {
	var snapshot staffPasswordSnapshot
	var outcome error
	err := s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.lockInstance(ctx, tx, false); err != nil {
			return err
		}
		if in.proof == nil {
			blocked, err := s.reserveLoginPeer(ctx, tx, in.peer)
			if err != nil {
				return err
			}
			if blocked {
				outcome = ErrRateLimited
				return nil
			}
		}
		var err error
		snapshot, err = s.passwordSnapshot(ctx, tx, in)
		if err != nil {
			return err
		}
		username := in.username
		if in.proof != nil {
			username = snapshot.credential.username
		}
		blocked, err := s.accountBlocked(ctx, tx, username, s.now().UTC())
		if err != nil {
			return err
		}
		if blocked {
			outcome = ErrRateLimited
		}
		return nil
	})
	if err != nil {
		return StaffChallenge{}, err
	}
	if outcome != nil {
		return StaffChallenge{}, outcome
	}
	valid := false
	if snapshot.credential.active() {
		valid = verifyStaffPassword(*snapshot.credential.password, in.password)
	} else {
		verifyUnknownStaffPassword(in.password)
	}
	var result StaffChallenge
	err = s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.lockInstance(ctx, tx, false); err != nil {
			return err
		}
		current, err := s.passwordSnapshot(ctx, tx, in)
		if err != nil {
			return err
		}
		username := in.username
		if in.proof != nil {
			username = current.credential.username
		}
		blocked, err := s.accountBlocked(ctx, tx, username, s.now().UTC())
		if err != nil {
			return err
		}
		if blocked {
			outcome = ErrRateLimited
			return nil
		}
		if !valid || !snapshot.credential.sameCredential(current.credential) || !sameStaffID(snapshot.session, current.session) {
			outcome = ErrUnauthenticated
			return s.failedLogin(ctx, tx, username, current.credential.principal)
		}
		if _, err = s.readFactor(ctx, tx, current.credential, true); err != nil {
			return err
		}
		kind := "login"
		if in.proof != nil {
			kind = "step_up"
		}
		id, err := core.NewID()
		if err != nil {
			return err
		}
		token, err := newSecret()
		if err != nil {
			return err
		}
		digest, err := tokenDigest(token)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		c := current.credential
		if _, err = tx.Exec(ctx, queries.CreateStaffChallenge, id, s.instance, c.principal, c.role, kind, digest[:], *c.factor, c.epoch, nil, current.session, nil, nil, now, now.Add(5*time.Minute)); err != nil {
			return err
		}
		result = StaffChallenge{Token: token, ExpiresAt: now.Add(5 * time.Minute)}
		return nil
	})
	if err != nil {
		return StaffChallenge{}, err
	}
	if outcome != nil {
		return StaffChallenge{}, outcome
	}
	return result, nil
}
func (s *StaffIdentity) ConfirmLogin(ctx context.Context, challenge, code, previous string) (StaffSession, error) {
	return s.confirmAuthentication(ctx, challenge, code, staffConfirmation{kind: "login", previous: previous})
}
func (s *StaffIdentity) ConfirmStepUp(ctx context.Context, challenge, code string) (StaffSession, error) {
	proof, err := s.service.proof(ctx)
	if err != nil {
		return StaffSession{}, err
	}
	return s.confirmAuthentication(ctx, challenge, code, staffConfirmation{kind: "step_up", proof: &proof})
}
