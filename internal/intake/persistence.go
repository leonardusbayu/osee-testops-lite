package intake

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
)

func recordConflict(ctx context.Context, tx pgx.Tx, p core.Principal, receipt core.ID, source string, in core.IntakeCommand, hash, reason string) error {
	id, err := core.NewID()
	if err != nil {
		return err
	}
	var recorded core.ID
	err = tx.QueryRow(ctx, queries.IntakeConflict, id, receipt, source, in.EventReference, hash, reason, p.UserID).Scan(&recorded)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return writeAudit(ctx, tx, p, receipt, "intake_conflict")
}

func writeAudit(ctx context.Context, tx pgx.Tx, p core.Principal, object core.ID, action string) error {
	id, err := core.NewID()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, queries.IntakeAudit, id, object, action, p.UserID)
	return err
}

func lockSession(ctx context.Context, tx pgx.Tx, in core.IntakeCommand) (core.Session, error) {
	var session core.Session
	err := tx.QueryRow(ctx, queries.IntakeSession, in.SessionID).Scan(&session.StartsAt, &session.CutoffAt, &session.ScheduleVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return session, core.ErrInvalidInput
	}
	if err != nil {
		return session, err
	}
	return session, sessionDecision(session, in.ScheduleVersion)
}
func sessionDecision(session core.Session, revision core.Version) error {
	if !session.AcceptsSchedule(revision) {
		return core.ErrConflict
	}
	if !session.BookingOpen(time.Now().UTC()) {
		return core.ErrReviewRequired
	}
	return nil
}

func resolvePerson(ctx context.Context, tx pgx.Tx, p core.Principal, source string, in core.IntakeCommand) (core.ID, error) {
	if p.Role == core.RoleParticipant {
		return p.ParticipantID, nil
	}
	var person core.ID
	err := tx.QueryRow(ctx, queries.IntakePerson, source, in.PersonReference).Scan(&person)
	if err == nil {
		return person, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	person, err = core.NewID()
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, queries.IntakeNewPerson, person, in.Name, in.Email, in.Phone); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, queries.IntakeBindPerson, source, in.PersonReference, person, p.UserID); err != nil {
		return "", err
	}
	return person, nil
}

func createOutcome(ctx context.Context, tx pgx.Tx, p core.Principal, source string, in core.IntakeCommand, hash string, target core.ID) (core.Registration, error) {
	var person core.ID
	var err error
	if target == "" {
		person, err = resolvePerson(ctx, tx, p, source, in)
	} else {
		person, err = resolveSelectedPerson(ctx, tx, p, source, &in, target)
	}
	if err != nil {
		return core.Registration{}, err
	}
	registration, err := core.NewID()
	if err != nil {
		return core.Registration{}, err
	}
	receipt, err := core.NewID()
	if err != nil {
		return core.Registration{}, err
	}
	outcome := core.Registration{ID: registration, ParticipantID: person, SessionID: in.SessionID, PartnerID: p.PartnerID, Version: 1, ScheduleVersion: in.ScheduleVersion, ProductReference: in.ProductReference, State: core.RegistrationDraft, ExternalRegistrationState: "NOT_REGISTERED"}
	if _, err = tx.Exec(ctx, queries.IntakeNewRegistration, outcome.ID, person, in.SessionID, in.ProductReference, string(p.PartnerID), in.ScheduleVersion); err != nil {
		return core.Registration{}, err
	}
	if _, err = tx.Exec(ctx, queries.IntakeNewReceipt, receipt, source, in.EventReference, hash); err != nil {
		return core.Registration{}, err
	}
	if err = persistSnapshots(ctx, tx, p, source, in, receipt, outcome); err != nil {
		return core.Registration{}, err
	}
	if target != "" {
		var intact bool
		err = tx.QueryRow(ctx, queries.IntakeSelectedOutcome, outcome.ID, outcome.ParticipantID, outcome.SessionID, outcome.ProductReference, int64(outcome.Version), int64(outcome.ScheduleVersion), string(outcome.PartnerID), string(outcome.State), outcome.ExternalRegistrationState, in.Name, in.Email, in.Phone, in.PersonReference, source).Scan(&intact)
		if err != nil {
			return core.Registration{}, err
		}
		if !intact {
			return core.Registration{}, core.ErrConflict
		}
	}
	return outcome, nil
}

func persistSnapshots(ctx context.Context, tx pgx.Tx, p core.Principal, source string, in core.IntakeCommand, receipt core.ID, outcome core.Registration) error {
	registration, err := json.Marshal(outcome)
	if err != nil {
		return err
	}
	person, err := json.Marshal(struct{ Name, Email, Phone string }{in.Name, in.Email, in.Phone})
	if err != nil {
		return err
	}
	consent, err := json.Marshal(struct {
		Communication bool      `json:"communication"`
		Version       string    `json:"version"`
		At            time.Time `json:"at"`
	}{*in.CommunicationConsent, in.ConsentVersion, in.ConsentedAt})
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, queries.IntakeRecord, receipt, outcome.ID, source, in.OrderReference, registration, person, consent, p.UserID); err != nil {
		return err
	}
	if err = writeAudit(ctx, tx, p, outcome.ID, "intake_created"); err != nil {
		return err
	}
	outbox, err := core.NewID()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		RegistrationID core.ID `json:"registration_id"`
		SessionID      core.ID `json:"session_id"`
	}{outcome.ID, in.SessionID})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, queries.IntakeOutbox, outbox, outcome.ID, in.ScheduleVersion, payload)
	return err
}

func decodeOutcome(raw []byte) (core.Registration, error) {
	var outcome core.Registration
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return outcome, auth.ErrUnavailable
	}
	if _, err := core.ParseID(string(outcome.ID)); err != nil {
		return outcome, auth.ErrUnavailable
	}
	return outcome, nil
}
