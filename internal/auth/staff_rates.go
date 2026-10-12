package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

var ErrRateLimited = errors.New("rate_limited")

func (s *StaffIdentity) loginRateKey(kind, value string) [32]byte {
	return sha256.Sum256([]byte(string(s.instance) + "\x00" + kind + "\x00" + value))
}
func loginAccount(username string) string {
	if !validStaffUsername(username) {
		return "invalid"
	}
	return strings.ToLower(username)
}
func loginPeer(peer string) string {
	if len(peer) > 64 {
		return "unavailable"
	}
	if ip := net.ParseIP(peer); ip != nil {
		return ip.String()
	}
	return "unavailable"
}
func (s *StaffIdentity) accountBlocked(ctx context.Context, tx pgx.Tx, username string, now time.Time) (bool, error) {
	key := s.loginRateKey("login_account", loginAccount(username))
	var attempts int
	var started, expires time.Time
	err := tx.QueryRow(ctx, queries.LockStaffRate, s.instance, key[:]).Scan(&attempts, &started, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if started.After(now) {
		return true, nil
	}
	return attempts >= 5 && expires.After(now), nil
}
func (s *StaffIdentity) reserveLoginPeer(ctx context.Context, tx pgx.Tx, peer string) (bool, error) {
	now := s.now().UTC()
	key := s.loginRateKey("login_peer", loginPeer(peer))
	var attempts int
	if err := tx.QueryRow(ctx, queries.IncrementStaffRate, s.instance, key[:], "login_peer", now, now.Add(time.Minute)).Scan(&attempts); err != nil {
		return false, err
	}
	if attempts == 11 {
		if err := staffAudit(ctx, tx, nil, s.instance, "staff_login_peer_limited"); err != nil {
			return false, err
		}
	}
	return attempts > 10, nil
}
func (s *StaffIdentity) failedLogin(ctx context.Context, tx pgx.Tx, username string, principal core.ID) error {
	now := s.now().UTC()
	key := s.loginRateKey("login_account", loginAccount(username))
	var attempts int
	if err := tx.QueryRow(ctx, queries.IncrementStaffRate, s.instance, key[:], "login_account", now, now.Add(5*time.Minute)).Scan(&attempts); err != nil {
		return err
	}
	if principal == "" {
		principal = s.instance
	}
	return staffAudit(ctx, tx, nil, principal, "staff_login_failed")
}
func (s *StaffIdentity) clearLoginFailures(ctx context.Context, tx pgx.Tx, username string) error {
	key := s.loginRateKey("login_account", loginAccount(username))
	_, err := tx.Exec(ctx, "delete from auth_staff_rates where instance_id=$1 and key_hash=$2 and kind='login_account'", s.instance, key[:])
	return err
}
