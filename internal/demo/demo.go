// Package demo is an opt-in local synthetic participant adapter, never a staff issuer.
package demo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/jackc/pgx/v5"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
	"time"
)

const markerSQL = `SELECT d.principal_id FROM development_fixtures d
 JOIN auth_principals a ON a.id=d.principal_id
 JOIN participants p ON p.id=d.participant_id
 JOIN registrations r ON r.id=d.registration_id AND r.participant_id=d.participant_id AND r.session_id=d.session_id
 JOIN sessions s ON s.id=d.session_id
 WHERE d.name='participant-demo' AND d.kind='local-synthetic'
 AND a.enabled AND a.role='participant' AND a.participant_id=d.participant_id AND a.partner_id IS NULL
 AND p.email='participant-demo@osee.invalid'
 AND (SELECT count(*) FROM registrations own WHERE own.participant_id=p.id)=1
 AND (SELECT count(*) FROM auth_principals own WHERE own.participant_id=p.id)=1`

func localStore(s *db.Store) bool {
	if s == nil || s.Pool == nil {
		return false
	}
	c := s.Pool.Config().ConnConfig
	return c.Host == "osee-testops-db" && c.Port == 5432 && (c.Database == "osee_testops_dev" || c.Database == "osee_testops_test")
}
func Principal(ctx context.Context, s *db.Store) (core.ID, error) {
	if !localStore(s) {
		return "", auth.ErrUnavailable
	}
	var id core.ID
	if err := s.Pool.QueryRow(ctx, markerSQL).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", auth.ErrForbidden
		}
		return "", auth.ErrUnavailable
	}
	return id, nil
}

// Seed is an explicit operator action, never invoked by an HTTP request.
func Seed(ctx context.Context, s *db.Store) error {
	if !localStore(s) {
		return auth.ErrUnavailable
	}
	err := s.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock(73629105)"); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, "select exists(select 1 from development_fixtures where name='participant-demo')").Scan(&exists); err != nil {
			return err
		}
		if exists {
			var id core.ID
			return tx.QueryRow(ctx, markerSQL+" FOR UPDATE OF d,a,p,r,s").Scan(&id)
		}
		if err := tx.QueryRow(ctx, "select exists(select 1 from participants where email='participant-demo@osee.invalid')").Scan(&exists); err != nil {
			return err
		}
		if exists {
			return auth.ErrForbidden
		}
		participant, err := core.NewID()
		if err != nil {
			return err
		}
		principal, err := core.NewID()
		if err != nil {
			return err
		}
		session, err := core.NewID()
		if err != nil {
			return err
		}
		registration, err := core.NewID()
		if err != nil {
			return err
		}
		start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{"insert into participants(id,email) values($1,'participant-demo@osee.invalid')", []any{participant}},
			{"insert into auth_principals(id,role,participant_id) values($1,'participant',$2)", []any{principal, participant}},
			{"insert into sessions(id,starts_at,cutoff_at,capacity,host_ready) values($1,$2,$3,1,false)", []any{session, start, start.Add(-2 * time.Hour)}},
			{"insert into registrations(id,participant_id,session_id,registration_state) values($1,$2,$3,'CONFIRMED')", []any{registration, participant, session}},
			{"insert into development_fixtures(name,participant_id,principal_id,session_id,registration_id) values('participant-demo',$1,$2,$3,$4)", []any{participant, principal, session, registration}},
		} {
			if _, err = tx.Exec(ctx, statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return recordAudit(ctx, tx, principal, "development_fixture_seeded")
	})
	if err != nil {
		if errors.Is(err, auth.ErrForbidden) || errors.Is(err, pgx.ErrNoRows) {
			return auth.ErrForbidden
		}
		return auth.ErrUnavailable
	}
	return nil
}

// Issue binds only the explicit local participant marker. Caller-supplied identities are impossible.
func Issue(ctx context.Context, s *db.Store) (string, error) {
	if !localStore(s) {
		return "", auth.ErrUnavailable
	}
	var token string
	err := s.WithTx(ctx, func(tx pgx.Tx) error {
		var principal core.ID
		if err := tx.QueryRow(ctx, markerSQL+" FOR UPDATE OF d,a,p,r,s").Scan(&principal); err != nil {
			return err
		}
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return err
		}
		token = base64.RawURLEncoding.EncodeToString(bytes)
		hash := sha256.Sum256([]byte(token))
		id, err := core.NewID()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if _, err = tx.Exec(ctx, "insert into auth_invites(id,principal_id,token_hash,created_at,expires_at) values($1,$2,$3,$4,$5)", id, principal, hash[:], now, now.Add(time.Minute)); err != nil {
			return err
		}
		return recordAudit(ctx, tx, id, "auth_demo_invite_issued")
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", auth.ErrForbidden
		}
		return "", auth.ErrUnavailable
	}
	return token, nil
}
func recordAudit(ctx context.Context, tx pgx.Tx, object core.ID, action string) error {
	id, err := core.NewID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "insert into audit_events(id,object_id,action) values($1,$2,$3)", id, object, action)
	return err
}
