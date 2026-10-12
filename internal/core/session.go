package core

import (
	"errors"
	"time"
	_ "time/tzdata"
)

type SessionCommand struct {
	StartsAt, CutoffAt               time.Time
	Capacity                         int32
	AssignedStaffID                  ID
	GuideReference, MeetingReference string
}
type SessionChange struct {
	ExpectedVersion                          Version
	StartsAt, CutoffAt                       time.Time
	AssignedStaffID                          ID
	GuideReference, MeetingReference, Reason string
}
type Session struct {
	ID                               ID
	Version, ScheduleVersion         Version
	StartsAt, CutoffAt               time.Time
	Capacity                         int32
	AssignedStaffID                  ID
	GuideReference, MeetingReference string
	HostReady                        bool
}

var ErrInvalidInput = errors.New("invalid_input")
var ErrConflict = errors.New("conflict")
var ErrReviewRequired = errors.New("review_required")

var sessionWIB = func() *time.Location {
	location, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		panic("required session display timezone unavailable")
	}
	return location
}()

func (s Session) BookingOpen(now time.Time) bool {
	return !now.IsZero() && !s.StartsAt.IsZero() && !s.CutoffAt.IsZero() && s.CutoffAt.Compare(s.StartsAt) <= 0 && now.Before(s.CutoffAt)
}
func (s Session) AcceptsSchedule(version Version) bool {
	return version > 0 && version == s.ScheduleVersion
}
func (s Session) DisplayWIB() string {
	if s.StartsAt.IsZero() {
		return "Not scheduled"
	}
	return s.StartsAt.In(sessionWIB).Format("Mon, 02 Jan 2006 · 15:04 WIB")
}
