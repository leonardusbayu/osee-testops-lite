package core

import "time"

type IntakeCommand struct {
	EventReference, OrderReference string
	SessionID                      ID
	ScheduleVersion                Version
	ProductReference               string
	ParticipantID, PartnerID       ID
	PersonReference                string
	Name, Email, Phone             string
	CommunicationConsent           *bool
	ConsentVersion                 string
	ConsentedAt                    time.Time
}

type Registration struct {
	ID, ParticipantID, SessionID, PartnerID ID
	Version, ScheduleVersion                Version
	ProductReference                        string
	State                                   RegistrationState
	ExternalRegistrationState               string
}
