package auth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base32"
	"image/png"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

func (s *StaffIdentity) BeginEnrollment(ctx context.Context, capability, username, password string) (StaffChallenge, error) {
	digest, err := tokenDigest(capability)
	if err != nil {
		return StaffChallenge{}, err
	}
	if !validStaffUsername(username) || !validStaffPassword(password) {
		return StaffChallenge{}, core.ErrInvalidInput
	}
	var result StaffChallenge
	err = s.transaction(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := s.lockInstance(ctx, tx, false); err != nil {
			return err
		}
		b, bootstrapErr := s.lockBootstrap(ctx, tx)
		isOwner := bootstrapErr == nil && subtle.ConstantTimeCompare(b.hash, digest[:]) == 1
		var invite staffPending
		if isOwner {
			if err = s.liveBootstrap(ctx, tx, b); err != nil {
				return err
			}
		} else {
			invite, err = s.lockPending(ctx, tx, digest)
			if err != nil {
				return err
			}
			if !invite.live(s.now().UTC()) || invite.kind != "admin_invite" || invite.role != "admin" {
				return ErrUnauthenticated
			}
			if err = s.issuerEligible(ctx, tx, invite); err != nil {
				return err
			}
		}
		passwordHash, err := hashStaffPassword(password)
		if err != nil {
			return err
		}
		var credential staffCredential
		kind := "owner_enroll"
		if isOwner {
			if err = s.liveBootstrap(ctx, tx, b); err != nil {
				return err
			}
			credential, err = s.pendingOwner(ctx, tx, username, passwordHash)
		} else {
			kind = "admin_enroll"
			credential, err = s.lockCredential(ctx, tx, invite.principal)
			if err != nil {
				return err
			}
			if credential.role != "admin" || credential.enabled || credential.factor != nil || credential.password != nil || credential.epoch != invite.epoch || !strings.EqualFold(credential.username, username) {
				return ErrUnauthenticated
			}
			changed, err := tx.Exec(ctx, queries.SetStaffPassword, s.instance, credential.principal, passwordHash, credential.epoch)
			if err != nil {
				return err
			}
			if changed.RowsAffected() != 1 {
				return ErrUnauthenticated
			}
			credential, err = s.lockCredential(ctx, tx, invite.principal)
		}
		if err != nil {
			return err
		}
		result, err = s.createEnrollment(ctx, tx, credential, kind, invite)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if isOwner {
			changed, err := tx.Exec(ctx, queries.ConsumeBootstrap, s.instance, now)
			if err != nil {
				return err
			}
			if changed.RowsAffected() != 1 {
				return ErrUnauthenticated
			}
		} else {
			if err = s.issuerEligible(ctx, tx, invite); err != nil {
				return err
			}
			changed, err := tx.Exec(ctx, queries.ConsumeStaffChallenge, s.instance, invite.id, s.now().UTC())
			if err != nil {
				return err
			}
			if changed.RowsAffected() != 1 {
				return ErrUnauthenticated
			}
		}
		return staffAudit(ctx, tx, nil, credential.principal, "staff_enrollment_begun")
	})
	if err != nil {
		return StaffChallenge{}, err
	}
	return result, nil
}
func (s *StaffIdentity) liveBootstrap(ctx context.Context, tx pgx.Tx, b staffBootstrap) error {
	now := s.now().UTC()
	if b.created.After(now) || !b.expires.After(now) || b.consumed != nil || b.revoked != nil || b.finalized != nil {
		return ErrUnauthenticated
	}
	return s.noEnrolledStaff(ctx, tx)
}
func (s *StaffIdentity) createEnrollment(ctx context.Context, tx pgx.Tx, c staffCredential, kind string, invite staffPending) (StaffChallenge, error) {
	seed, err := newStaffTOTPSeed()
	if err != nil {
		return StaffChallenge{}, err
	}
	sealed, err := sealStaffSeed(s.key[:], seed, s.seedAAD(c.principal, 1))
	if err != nil {
		return StaffChallenge{}, err
	}
	token, err := newSecret()
	if err != nil {
		return StaffChallenge{}, err
	}
	digest, err := tokenDigest(token)
	if err != nil {
		return StaffChallenge{}, err
	}
	id, err := core.NewID()
	if err != nil {
		return StaffChallenge{}, err
	}
	now := s.now().UTC()
	expires := now.Add(5 * time.Minute)
	_, err = tx.Exec(ctx, queries.CreateStaffChallenge, id, s.instance, c.principal, c.role, kind, digest[:], int64(1), c.epoch, sealed, nil, invite.issuer, invite.issuerSession, now, expires)
	if err != nil {
		return StaffChallenge{}, err
	}
	return StaffChallenge{Token: token, ExpiresAt: expires}, nil
}

func (s *StaffIdentity) EnrollmentView(ctx context.Context, challenge string) (StaffEnrollmentView, error) {
	digest, err := tokenDigest(challenge)
	if err != nil {
		return StaffEnrollmentView{}, err
	}
	var result StaffEnrollmentView
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
		seed, err := openStaffSeed(s.key[:], pending.sealed, s.seedAAD(pending.principal, pending.version))
		if err != nil {
			return ErrUnavailable
		}
		if !pending.live(s.now().UTC()) {
			return ErrUnauthenticated
		}
		result = StaffEnrollmentView{Username: credential.username, Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed), ExpiresAt: pending.expires}
		return nil
	})
	if err != nil {
		return StaffEnrollmentView{}, err
	}
	return result, nil
}
func (s *StaffIdentity) EnrollmentQR(ctx context.Context, challenge string) ([]byte, error) {
	view, err := s.EnrollmentView(ctx, challenge)
	if err != nil {
		return nil, err
	}
	params := url.Values{"secret": {view.Secret}, "issuer": {"OSEE TestOps"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	uri := url.URL{Scheme: "otpauth", Host: "totp", Path: "/OSEE TestOps:" + view.Username, RawQuery: params.Encode()}
	key, err := otp.NewKeyFromURL(uri.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	image, err := key.Image(256, 256)
	if err != nil {
		return nil, ErrUnavailable
	}
	var output bytes.Buffer
	if err = png.Encode(&output, image); err != nil {
		return nil, ErrUnavailable
	}
	// Rendering cannot revive a challenge consumed or revoked during QR work.
	if _, err = s.EnrollmentView(ctx, challenge); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
