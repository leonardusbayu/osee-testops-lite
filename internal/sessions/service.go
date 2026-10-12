package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
)

var ErrInvalidInput = core.ErrInvalidInput
var ErrConflict = core.ErrConflict
var ErrReviewRequired = core.ErrReviewRequired
var referencePattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

type Service struct{ authorizer *auth.Service }

func NewService(authorizer *auth.Service) *Service { return &Service{authorizer: authorizer} }
func (s *Service) withStaff(ctx context.Context, actor core.Principal, fn func(pgx.Tx, core.Principal) error) error {
	if s == nil || s.authorizer == nil {
		return auth.ErrUnavailable
	}
	return s.authorizer.WithStaffTx(ctx, actor, fn)
}
func normalizedTimes(start, cutoff time.Time) (time.Time, time.Time, error) {
	start = start.UTC().Truncate(time.Microsecond)
	cutoff = cutoff.UTC().Truncate(time.Microsecond)
	now := time.Now().UTC()
	if start.IsZero() || cutoff.IsZero() || start.Year() < 2000 || start.Year() > 9999 || cutoff.Year() < 2000 || cutoff.Year() > 9999 || cutoff.After(start) || !start.After(now) || !cutoff.After(now) {
		return time.Time{}, time.Time{}, ErrInvalidInput
	}
	return start, cutoff, nil
}
func (s *Service) assignment(ctx context.Context, tx pgx.Tx, id core.ID, guide, meeting string) error {
	if _, err := core.ParseID(string(id)); err != nil || !referencePattern.MatchString(guide) || !referencePattern.MatchString(meeting) {
		return ErrInvalidInput
	}
	return s.authorizer.CheckStaffAssignment(ctx, tx, id)
}
func validReason(reason string) bool {
	if !utf8.ValidString(reason) || strings.TrimSpace(reason) == "" || utf8.RuneCountInString(reason) > 500 {
		return false
	}
	for _, r := range reason {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func lockSession(ctx context.Context, tx pgx.Tx, id core.ID) (core.Session, error) {
	if _, err := core.ParseID(string(id)); err != nil {
		return core.Session{}, ErrInvalidInput
	}
	var s core.Session
	err := tx.QueryRow(ctx, queries.SessionLock, id).Scan(&s.ID, &s.Version, &s.ScheduleVersion, &s.StartsAt, &s.CutoffAt, &s.Capacity, &s.AssignedStaffID, &s.GuideReference, &s.MeetingReference, &s.HostReady)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Session{}, ErrConflict
	}
	s.StartsAt = s.StartsAt.UTC()
	s.CutoffAt = s.CutoffAt.UTC()
	return s, err
}
func recordHistory(ctx context.Context, tx pgx.Tx, s core.Session, actor core.Principal, reason string) error {
	_, err := tx.Exec(ctx, queries.SessionHistory, s.ID, s.ScheduleVersion, s.Version, s.StartsAt, s.CutoffAt, s.Capacity, s.AssignedStaffID, s.GuideReference, s.MeetingReference, s.HostReady, actor.UserID, reason)
	return err
}
func recordEvent(ctx context.Context, tx pgx.Tx, s core.Session, actor core.Principal, action string) error {
	auditID, err := core.NewID()
	if err != nil {
		return err
	}
	outboxID, err := core.NewID()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		ScheduleVersion core.Version `json:"schedule_version"`
		RowVersion      core.Version `json:"row_version"`
		StartsAt        time.Time    `json:"starts_at"`
		CutoffAt        time.Time    `json:"cutoff_at"`
		HostReady       bool         `json:"host_ready"`
	}{s.ScheduleVersion, s.Version, s.StartsAt, s.CutoffAt, s.HostReady})
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, queries.SessionAudit, auditID, s.ID, action, actor.UserID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, queries.SessionOutbox, outboxID, s.ID, action, s.ScheduleVersion, payload)
	return err
}
func (s *Service) Create(ctx context.Context, actor core.Principal, in core.SessionCommand) (core.Session, error) {
	var result core.Session
	err := s.withStaff(ctx, actor, func(tx pgx.Tx, current core.Principal) error {
		if in.Capacity <= 0 {
			return ErrInvalidInput
		}
		if err := s.assignment(ctx, tx, in.AssignedStaffID, in.GuideReference, in.MeetingReference); err != nil {
			return err
		}
		start, cutoff, err := normalizedTimes(in.StartsAt, in.CutoffAt)
		if err != nil {
			return err
		}
		id, err := core.NewID()
		if err != nil {
			return err
		}
		result = core.Session{ID: id, Version: 1, ScheduleVersion: 1, StartsAt: start, CutoffAt: cutoff, Capacity: in.Capacity, AssignedStaffID: in.AssignedStaffID, GuideReference: in.GuideReference, MeetingReference: in.MeetingReference}
		if _, err = tx.Exec(ctx, queries.SessionCreate, id, start, cutoff, in.Capacity, in.AssignedStaffID, in.GuideReference, in.MeetingReference); err != nil {
			return err
		}
		if err = recordHistory(ctx, tx, result, current, "session_created"); err != nil {
			return err
		}
		if err = recordEvent(ctx, tx, result, current, "session_created"); err != nil {
			return err
		}
		return s.assignment(ctx, tx, in.AssignedStaffID, in.GuideReference, in.MeetingReference)
	})
	if err != nil {
		return core.Session{}, err
	}
	return result, nil
}
func (s *Service) Reschedule(ctx context.Context, actor core.Principal, id core.ID, in core.SessionChange) (core.Session, error) {
	var result core.Session
	err := s.withStaff(ctx, actor, func(tx pgx.Tx, current core.Principal) error {
		if in.ExpectedVersion <= 0 || !validReason(in.Reason) {
			return ErrInvalidInput
		}
		locked, err := lockSession(ctx, tx, id)
		if err != nil {
			return err
		}
		if locked.ScheduleVersion != in.ExpectedVersion {
			return ErrConflict
		}
		if !locked.BookingOpen(time.Now().UTC()) {
			return ErrReviewRequired
		}
		if err = s.assignment(ctx, tx, in.AssignedStaffID, in.GuideReference, in.MeetingReference); err != nil {
			return err
		}
		if !locked.BookingOpen(time.Now().UTC()) {
			return ErrReviewRequired
		}
		start, cutoff, err := normalizedTimes(in.StartsAt, in.CutoffAt)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, queries.SessionReschedule, id, start, cutoff, in.AssignedStaffID, in.GuideReference, in.MeetingReference); err != nil {
			return err
		}
		locked.Version++
		locked.ScheduleVersion++
		locked.StartsAt = start
		locked.CutoffAt = cutoff
		locked.AssignedStaffID = in.AssignedStaffID
		locked.GuideReference = in.GuideReference
		locked.MeetingReference = in.MeetingReference
		locked.HostReady = false
		result = locked
		if err = recordHistory(ctx, tx, result, current, in.Reason); err != nil {
			return err
		}
		if err = recordEvent(ctx, tx, result, current, "session_rescheduled"); err != nil {
			return err
		}
		return s.assignment(ctx, tx, in.AssignedStaffID, in.GuideReference, in.MeetingReference)
	})
	if err != nil {
		return core.Session{}, err
	}
	return result, nil
}
func (s *Service) SetHostReady(ctx context.Context, actor core.Principal, id core.ID, ready bool) error {
	return s.withStaff(ctx, actor, func(tx pgx.Tx, current core.Principal) error {
		locked, err := lockSession(ctx, tx, id)
		if err != nil {
			return err
		}
		if locked.HostReady == ready {
			return nil
		}
		if _, err = tx.Exec(ctx, queries.SessionSetReady, id, ready); err != nil {
			return err
		}
		locked.Version++
		locked.HostReady = ready
		return recordEvent(ctx, tx, locked, current, "session_host_ready_changed")
	})
}
