package core

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
)

type ID string
type Version int64
type Money struct {
	MinorUnits int64
	Currency   string
}
type Role string

const (
	RoleParticipant Role = "participant"
	RolePartner     Role = "partner"
	RoleAdmin       Role = "admin"
	RoleOwner       Role = "owner"
	RoleSystem      Role = "system"
)

type Principal struct {
	UserID        ID
	ParticipantID ID
	PartnerID     ID
	Role          Role
	MFA           bool
}
type PaymentState string
type RegistrationState string
type AttendanceState string
type ResultState string
type ShipmentState string

const (
	PaymentPending          PaymentState      = "PENDING"
	PaymentVerified         PaymentState      = "VERIFIED"
	PaymentReview           PaymentState      = "REVIEW"
	PaymentRefunded         PaymentState      = "REFUNDED"
	RegistrationDraft       RegistrationState = "DRAFT"
	RegistrationEligible    RegistrationState = "ELIGIBLE"
	RegistrationConfirmed   RegistrationState = "CONFIRMED"
	RegistrationCancelled   RegistrationState = "CANCELLED"
	AttendanceNotCheckedIn  AttendanceState   = "NOT_CHECKED_IN"
	AttendanceCheckedIn     AttendanceState   = "CHECKED_IN"
	AttendanceVerified      AttendanceState   = "ATTENDANCE_VERIFIED"
	AttendanceCompleted     AttendanceState   = "COMPLETED"
	AttendanceNoShow        AttendanceState   = "NO_SHOW"
	ResultNotReceived       ResultState       = "NOT_RECEIVED"
	ResultValidated         ResultState       = "VALIDATED"
	ResultHold              ResultState       = "HOLD"
	ResultApproved          ResultState       = "APPROVED"
	ResultReleased          ResultState       = "RELEASED"
	ShipmentLabelCreated    ShipmentState     = "label_created"
	ShipmentHandedToCourier ShipmentState     = "handed_to_courier"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ParseID(s string) (ID, error) {
	if !uuidPattern.MatchString(s) {
		return "", errors.New("invalid internal ID")
	}
	return ID(s), nil
}
func NewID() (ID, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return ID(fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])), nil
}
