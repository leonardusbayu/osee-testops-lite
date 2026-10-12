package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"osee-testops-lite/internal/auth"
	"osee-testops-lite/internal/core"
)

var referencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

func boundedText(value string, min, max int) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < min || length > max {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validate(in core.IntakeCommand) error {
	if err := validateCommand(in); err != nil {
		return err
	}
	return validateProfile(in, true)
}
func validateCommand(in core.IntakeCommand) error {
	for _, ref := range []string{in.EventReference, in.OrderReference, in.ProductReference, in.ConsentVersion} {
		if !referencePattern.MatchString(ref) {
			return core.ErrInvalidInput
		}
	}
	if _, err := core.ParseID(string(in.SessionID)); err != nil || in.ScheduleVersion < 1 {
		return core.ErrInvalidInput
	}
	if in.CommunicationConsent == nil || in.ConsentedAt.IsZero() || in.ConsentedAt.After(time.Now().UTC()) {
		return core.ErrInvalidInput
	}
	return nil
}

func validateProfile(in core.IntakeCommand, required bool) error {
	minimum := 0
	if required {
		minimum = 1
	}
	if !boundedText(in.Name, minimum, 120) || !boundedText(in.Email, 0, 254) || !boundedText(in.Phone, 0, 40) || (required && in.Email == "" && in.Phone == "") {
		return core.ErrInvalidInput
	}
	if in.Email != "" {
		address, err := mail.ParseAddress(in.Email)
		if err != nil || address.Address != in.Email {
			return core.ErrInvalidInput
		}
	}
	return nil
}
func commandFingerprint(in core.IntakeCommand, target core.ID) (string, error) {
	if target == "" {
		return fingerprint(in)
	}
	encoded, err := json.Marshal(struct {
		Command             core.IntakeCommand
		SelectedParticipant core.ID
	}{in, target})
	if err != nil {
		return "", auth.ErrUnavailable
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
func sourceFor(p core.Principal, in core.IntakeCommand) (string, error) {
	if in.PartnerID != "" {
		return "", auth.ErrForbidden
	}
	if p.Role == core.RoleParticipant {
		if (in.ParticipantID != "" && in.ParticipantID != p.ParticipantID) || in.PersonReference != "" {
			return "", auth.ErrForbidden
		}
		return "central:" + string(p.ParticipantID), nil
	}
	if in.ParticipantID != "" {
		return "", auth.ErrForbidden
	}
	if !referencePattern.MatchString(in.PersonReference) {
		return "", core.ErrInvalidInput
	}
	if p.Role == core.RolePartner {
		return "partner:" + string(p.PartnerID), nil
	}
	return "staff:" + string(p.UserID), nil
}

func fingerprint(in core.IntakeCommand) (string, error) {
	encoded, err := json.Marshal(in)
	if err != nil {
		return "", auth.ErrUnavailable
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
