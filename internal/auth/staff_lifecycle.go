package auth

import (
	"bytes"
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

func (s *StaffIdentity) ProvisionAdmin(ctx context.Context, username, password, code string) (StaffChallenge, error) {
	if !validStaffUsername(username) {
		return StaffChallenge{}, core.ErrInvalidInput
	}
	var result StaffChallenge
	err := s.withStaffAction(ctx, password, code, true, func(ctx context.Context, tx pgx.Tx, ticket staffActionTicket) (staffActionEffect, error) {
		target, err := s.passwordSnapshot(ctx, tx, staffPasswordInput{username: username})
		if err != nil {
			return staffActionEffect{}, err
		}
		c := target.credential
		if c.principal == "" {
			id, e := core.NewID()
			if e != nil {
				return staffActionEffect{}, e
			}
			if _, e = tx.Exec(ctx, "insert into auth_principals(id,role,enabled) values($1,'admin',false)", id); e != nil {
				return staffActionEffect{}, e
			}
			if _, e = tx.Exec(ctx, queries.CreateStaffCredential, s.instance, id, "admin", username, nil); e != nil {
				return staffActionEffect{}, e
			}
			c, e = s.lockCredential(ctx, tx, id)
			if e != nil {
				return staffActionEffect{}, e
			}
		} else {
			if c.role != "admin" || c.enabled || c.factor != nil {
				return staffActionEffect{}, core.ErrConflict
			}
			if e := s.revokeStaffAccess(ctx, tx, c.principal, s.now().UTC(), ""); e != nil {
				return staffActionEffect{}, e
			}
			if _, e := tx.Exec(ctx, "update auth_staff_credentials set password_hash=null,credential_epoch=credential_epoch+1 where instance_id=$1 and principal_id=$2", s.instance, c.principal); e != nil {
				return staffActionEffect{}, e
			}
			var e error
			c, e = s.lockCredential(ctx, tx, c.principal)
			if e != nil {
				return staffActionEffect{}, e
			}
		}
		var e error
		result, e = s.newLifecycleChallenge(ctx, tx, c, "admin_invite", nil, &ticket.credential.principal, ticket.session)
		if e != nil {
			return staffActionEffect{}, e
		}
		if e = s.auditPendingChallenge(ctx, tx, result, &ticket.credential.principal, c.principal, "staff_admin_provisioned"); e != nil {
			return staffActionEffect{}, e
		}
		checked, e := s.lockCredential(ctx, tx, c.principal)
		if e != nil {
			return staffActionEffect{}, e
		}
		if checked.principal != c.principal || checked.role != "admin" || checked.username != c.username || checked.enabled || checked.password != nil || checked.factor != nil || checked.epoch != c.epoch {
			return staffActionEffect{}, ErrUnauthenticated
		}
		if _, e = s.lockPendingByToken(ctx, tx, result.Token); e != nil {
			return staffActionEffect{}, e
		}
		return staffActionEffect{credential: ticket.credential}, nil
	})
	if err != nil {
		return StaffChallenge{}, err
	}
	return result, nil
}

func (s *StaffIdentity) BeginReplacement(ctx context.Context, password, code string) (StaffChallenge, error) {
	var result StaffChallenge
	err := s.withStaffAction(ctx, password, code, false, func(ctx context.Context, tx pgx.Tx, ticket staffActionTicket) (staffActionEffect, error) {
		if _, e := tx.Exec(ctx, queries.RevokeStaffChallenges, s.instance, ticket.credential.principal, s.now().UTC()); e != nil {
			return staffActionEffect{}, e
		}
		var e error
		result, e = s.newLifecycleChallenge(ctx, tx, ticket.credential, "replacement", ticket.session, nil, nil)
		if e != nil {
			return staffActionEffect{}, e
		}
		if e = s.auditPendingChallenge(ctx, tx, result, &ticket.credential.principal, ticket.credential.principal, "staff_factor_replacement_begun"); e != nil {
			return staffActionEffect{}, e
		}
		return staffActionEffect{credential: ticket.credential}, nil
	})
	if err != nil {
		return StaffChallenge{}, err
	}
	return result, nil
}
func (s *StaffIdentity) ChangePassword(ctx context.Context, oldPassword, newPassword, code string) error {
	if !validStaffPassword(newPassword) {
		return core.ErrInvalidInput
	}
	return s.withStaffAction(ctx, oldPassword, code, false, func(ctx context.Context, tx pgx.Tx, ticket staffActionTicket) (staffActionEffect, error) {
		encoded, e := hashStaffPassword(newPassword)
		if e != nil {
			return staffActionEffect{}, e
		}
		changed, e := tx.Exec(ctx, queries.SetStaffPassword, s.instance, ticket.credential.principal, encoded, ticket.credential.epoch)
		if e != nil {
			return staffActionEffect{}, e
		}
		if changed.RowsAffected() != 1 {
			return staffActionEffect{}, ErrUnauthenticated
		}
		at := s.now().UTC().Truncate(time.Microsecond)
		if e = s.revokeStaffAccess(ctx, tx, ticket.credential.principal, at, ""); e != nil {
			return staffActionEffect{}, e
		}
		if e = staffAudit(ctx, tx, &ticket.credential.principal, ticket.credential.principal, "staff_password_changed"); e != nil {
			return staffActionEffect{}, e
		}
		expected := ticket.credential
		expected.password = &encoded
		expected.epoch++
		return staffActionEffect{credential: expected, revokedAt: &at}, nil
	})
}
func (s *StaffIdentity) SetAdminEnabled(ctx context.Context, id core.ID, enabled bool, password, code string) error {
	if _, e := core.ParseID(string(id)); e != nil {
		return core.ErrInvalidInput
	}
	return s.withStaffAction(ctx, password, code, true, func(ctx context.Context, tx pgx.Tx, ticket staffActionTicket) (staffActionEffect, error) {
		target, e := s.lockCredential(ctx, tx, id)
		if e != nil {
			return staffActionEffect{}, e
		}
		if target.role != "admin" || target.principal == ticket.credential.principal || target.factor == nil || target.password == nil {
			return staffActionEffect{}, ErrForbidden
		}
		var revoked *time.Time
		if e = tx.QueryRow(ctx, "select revoked_at from auth_staff_factors where instance_id=$1 and principal_id=$2 and factor_version=$3 for update", s.instance, id, *target.factor).Scan(&revoked); e != nil {
			return staffActionEffect{}, e
		}
		if revoked != nil {
			return staffActionEffect{}, ErrForbidden
		}
		at := s.now().UTC().Truncate(time.Microsecond)
		if _, e = tx.Exec(ctx, "update auth_principals set enabled=$2 where id=$1 and role='admin'", id, enabled); e != nil {
			return staffActionEffect{}, e
		}
		if _, e = tx.Exec(ctx, "update auth_staff_credentials set credential_epoch=credential_epoch+1 where instance_id=$1 and principal_id=$2", s.instance, id); e != nil {
			return staffActionEffect{}, e
		}
		if e = s.revokeStaffAccess(ctx, tx, id, at, ""); e != nil {
			return staffActionEffect{}, e
		}
		action := "staff_admin_disabled"
		if enabled {
			action = "staff_admin_enabled"
		}
		if e = staffAudit(ctx, tx, &ticket.credential.principal, id, action); e != nil {
			return staffActionEffect{}, e
		}
		expected := target
		expected.enabled = enabled
		expected.epoch++
		actual, e := s.lockCredential(ctx, tx, id)
		if e != nil {
			return staffActionEffect{}, e
		}
		if !expected.sameCredential(actual) {
			return staffActionEffect{}, ErrUnauthenticated
		}
		return staffActionEffect{credential: ticket.credential}, nil
	})
}
func (s *StaffIdentity) revokeStaffAccess(ctx context.Context, tx pgx.Tx, id core.ID, at time.Time, except core.ID) error {
	if _, e := tx.Exec(ctx, "update auth_sessions set revoked_at=$2 where principal_id=$1 and revoked_at is null", id, at); e != nil {
		return e
	}
	_, e := tx.Exec(ctx, "update auth_staff_challenges set revoked_at=$3 where instance_id=$1 and (principal_id=$2 or issuer_id=$2) and id::text<>$4 and consumed_at is null and revoked_at is null", s.instance, id, at, string(except))
	return e
}
func (s *StaffIdentity) newLifecycleChallenge(ctx context.Context, tx pgx.Tx, c staffCredential, kind string, session, issuer, issuerSession *core.ID) (StaffChallenge, error) {
	version := int64(1)
	var sealed []byte
	if kind == "replacement" || kind == "recovery" {
		if c.factor == nil {
			return StaffChallenge{}, ErrUnauthenticated
		}
		version = *c.factor + 1
		seed, e := newStaffTOTPSeed()
		if e != nil {
			return StaffChallenge{}, e
		}
		sealed, e = sealStaffSeed(s.key[:], seed, s.seedAAD(c.principal, version))
		if e != nil {
			return StaffChallenge{}, e
		}
	}
	id, e := core.NewID()
	if e != nil {
		return StaffChallenge{}, e
	}
	token, e := newSecret()
	if e != nil {
		return StaffChallenge{}, e
	}
	digest, e := tokenDigest(token)
	if e != nil {
		return StaffChallenge{}, e
	}
	now := s.now().UTC()
	expires := now.Add(5 * time.Minute)
	if _, e = tx.Exec(ctx, queries.CreateStaffChallenge, id, s.instance, c.principal, c.role, kind, digest[:], version, c.epoch, sealed, session, issuer, issuerSession, now, expires); e != nil {
		return StaffChallenge{}, e
	}
	pending, e := s.lockPending(ctx, tx, digest)
	if e != nil {
		return StaffChallenge{}, e
	}
	expected := staffPending{id: id, principal: c.principal, role: c.role, kind: kind, version: version, epoch: c.epoch, sealed: sealed, session: session, issuer: issuer, issuerSession: issuerSession, created: now.Truncate(time.Microsecond), expires: expires.Truncate(time.Microsecond)}
	if !expected.sameEnrollment(pending) || !bytes.Equal(pending.sealed, sealed) || !pending.live(s.now().UTC()) {
		return StaffChallenge{}, ErrUnauthenticated
	}
	return StaffChallenge{Token: token, ExpiresAt: expires}, nil
}
func (s *StaffIdentity) lockPendingByToken(ctx context.Context, tx pgx.Tx, token string) (staffPending, error) {
	digest, e := tokenDigest(token)
	if e != nil {
		return staffPending{}, e
	}
	return s.lockPending(ctx, tx, digest)
}
