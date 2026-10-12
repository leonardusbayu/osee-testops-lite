package integrations

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"osee-testops-lite/internal/core"
	"osee-testops-lite/internal/db"
)

const MaxEventBytes = 32 * 1024

var (
	ErrEventUnavailable  = errors.New("integration event unavailable")
	ErrEventUnauthorized = errors.New("integration event authentication failed")
	ErrEventInvalid      = errors.New("invalid integration event")
	ErrEventTooLarge     = errors.New("integration event too large")
	ErrEventConflict     = errors.New("integration event identity conflict")
)

type EventConfig struct {
	Secrets map[string][]byte
	Clock   func() time.Time
}

type EventReceipt struct {
	ReceiptID core.ID `json:"receipt_id"`
	Status    string  `json:"status"`
	Replayed  bool    `json:"replayed"`
}

type EventGateway struct {
	store   *db.Store
	secrets map[string][]byte
	clock   func() time.Time
}

var eventKinds = map[string][]string{
	"tinycommand": {"registration.submitted", "schedule.changed", "reminder.requested", "result.imported", "shipment.updated", "task.requested"},
	"trafft":      {"booking.created", "booking.updated", "booking.cancelled"},
	"anychat":     {"conversation.created", "conversation.updated", "ticket.created", "ticket.updated", "message.status"},
	"partner":     {"registration.submitted", "settlement.reported"},
}

// SupportedEventKinds lists observations that may be received, never business permissions.
func SupportedEventKinds(source string) []string { return append([]string(nil), eventKinds[source]...) }

func NewEventGateway(store *db.Store, config EventConfig) (*EventGateway, error) {
	gateway := &EventGateway{store: store, secrets: map[string][]byte{}, clock: config.Clock}
	if gateway.clock == nil {
		gateway.clock = time.Now
	}
	for source, secret := range config.Secrets {
		if _, ok := eventKinds[source]; !ok || len(secret) < 32 || len(secret) > 256 {
			return nil, ErrEventInvalid
		}
		gateway.secrets[source] = append([]byte(nil), secret...)
	}
	return gateway, nil
}

func (gateway *EventGateway) Receive(ctx context.Context, source, timestamp, signature string, body []byte) (EventReceipt, error) {
	if gateway == nil || len(gateway.secrets) == 0 {
		return EventReceipt{}, ErrEventUnavailable
	}
	if len(body) > MaxEventBytes {
		return EventReceipt{}, ErrEventTooLarge
	}
	secret, enabled := gateway.secrets[source]
	if !enabled || !gateway.freshTimestamp(timestamp) || len(signature) != 67 || !strings.HasPrefix(signature, "v1=") {
		return EventReceipt{}, ErrEventUnauthorized
	}
	supplied, err := hex.DecodeString(signature[3:])
	if err != nil {
		return EventReceipt{}, ErrEventUnauthorized
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(source + "\n" + timestamp + "\n"))
	_, _ = mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), supplied) {
		return EventReceipt{}, ErrEventUnauthorized
	}
	event, hash, err := decodeEvent(source, body)
	if err != nil {
		return EventReceipt{}, err
	}
	return gateway.persistEvent(ctx, event, hash, timestamp)
}

func (gateway *EventGateway) freshTimestamp(raw string) bool {
	if len(raw) == 0 || len(raw) > 12 {
		return false
	}
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return false
	}
	delta := gateway.clock().Sub(time.Unix(value, 0))
	return delta >= -5*time.Minute && delta <= 5*time.Minute
}
