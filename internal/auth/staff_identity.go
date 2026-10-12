package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

type StaffChallenge struct {
	Token     string `json:"-"`
	ExpiresAt time.Time
}
type StaffEnrollmentView struct {
	Username  string
	Secret    string `json:"-"`
	ExpiresAt time.Time
}
type StaffSession struct {
	Token     string `json:"-"`
	ExpiresAt time.Time
}
type StaffEnrollmentResult struct {
	Session       StaffSession
	RecoveryCodes []string `json:"-"`
}

func (StaffChallenge) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "StaffChallenge{private:[REDACTED]}")
}
func (StaffEnrollmentView) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "StaffEnrollmentView{private:[REDACTED]}")
}
func (StaffSession) Format(s fmt.State, _ rune) { fmt.Fprint(s, "StaffSession{private:[REDACTED]}") }
func (StaffEnrollmentResult) Format(s fmt.State, _ rune) {
	fmt.Fprint(s, "StaffEnrollmentResult{private:[REDACTED]}")
}
func (*StaffIdentity) Format(s fmt.State, _ rune) { fmt.Fprint(s, "StaffIdentity{private:[REDACTED]}") }

type StaffIdentity struct {
	service  *Service
	key      [32]byte
	instance core.ID
	now      func() time.Time
}

func NewStaffIdentity(service *Service, key []byte, instance core.ID) (*StaffIdentity, error) {
	if service == nil || service.store == nil || service.store.Pool == nil || len(key) != 32 {
		return nil, core.ErrInvalidInput
	}
	if _, err := core.ParseID(string(instance)); err != nil {
		return nil, core.ErrInvalidInput
	}
	if service.staff != nil {
		return nil, core.ErrConflict
	}
	identity := &StaffIdentity{service: service, instance: instance, now: func() time.Time { return time.Now().UTC() }}
	copy(identity.key[:], key)
	service.staff = identity
	return identity, nil
}

func validStaffUsername(value string) bool {
	if len(value) < 3 || len(value) > 32 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == '-') {
			return false
		}
	}
	return true
}

func (s *StaffIdentity) seedAAD(principal core.ID, version int64) string {
	return "osee:staff:v1:" + string(s.instance) + ":" + string(principal) + ":" + strconv.FormatInt(version, 10)
}

func (s *StaffIdentity) transaction(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return staffError(s.service.store.WithTx(ctx, func(tx pgx.Tx) error { return fn(ctx, tx) }))
}

func (s *StaffIdentity) lockInstance(ctx context.Context, tx pgx.Tx, create bool) error {
	if create {
		if _, err := tx.Exec(ctx, queries.CreateLogicalInstance, s.instance); err != nil {
			return err
		}
	}
	var instance core.ID
	if err := tx.QueryRow(ctx, queries.LockLogicalInstance).Scan(&instance); err != nil {
		return err
	}
	if instance != s.instance {
		return ErrForbidden
	}
	return nil
}

func (s *StaffIdentity) ValidateStoredSecrets(ctx context.Context) error {
	return s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.lockInstance(ctx, tx, false); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `select principal_id::text,factor_version,encrypted_seed from auth_staff_factors where instance_id=$1
union all select principal_id::text,factor_version,encrypted_seed from auth_staff_challenges where instance_id=$1 and encrypted_seed is not null`, s.instance)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var principal core.ID
			var version int64
			var sealed []byte
			if err = rows.Scan(&principal, &version, &sealed); err != nil {
				return err
			}
			if _, err = openStaffSeed(s.key[:], sealed, s.seedAAD(principal, version)); err != nil {
				return ErrUnavailable
			}
		}
		return rows.Err()
	})
}
