package integrations

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"osee-testops-lite/db/queries"
	"osee-testops-lite/internal/core"
)

func eventSignal(ctx context.Context, tx pgx.Tx, object core.ID, action string, data map[string]string) error {
	audit, err := core.NewID()
	if err != nil {
		return err
	}
	outbox, err := core.NewID()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, queries.IntegrationEventAudit, audit, object, "integration_event_"+action); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, queries.IntegrationEventOutbox, outbox, object, "integration.event."+action, payload)
	return err
}

func (gateway *EventGateway) persistEvent(ctx context.Context, event normalizedEvent, hash, timestamp string) (EventReceipt, error) {
	if gateway.store == nil || gateway.store.Pool == nil {
		return EventReceipt{}, ErrEventUnavailable
	}
	receiptID, err := core.NewID()
	if err != nil {
		return EventReceipt{}, ErrEventUnavailable
	}
	result := EventReceipt{Status: "received"}
	conflict := false
	err = gateway.store.WithTx(ctx, func(tx pgx.Tx) error {
		if !gateway.freshTimestamp(timestamp) {
			return ErrEventUnauthorized
		}
		provider := "gateway:" + event.Source
		err := tx.QueryRow(ctx, queries.IntegrationReceiptInsert, receiptID, provider, event.EventID, hash).Scan(&result.ReceiptID)
		if errors.Is(err, pgx.ErrNoRows) {
			var originalHash string
			var originalObject core.ID
			if err = tx.QueryRow(ctx, queries.IntegrationReceiptRead, provider, event.EventID).Scan(&result.ReceiptID, &originalHash, &originalObject); err != nil {
				return err
			}
			if originalHash == hash {
				result.Replayed = true
				return nil
			}
			conflict = true
			conflictID, err := core.NewID()
			if err != nil {
				return err
			}
			err = tx.QueryRow(ctx, queries.IntegrationConflictInsert, conflictID, result.ReceiptID, hash).Scan(&conflictID)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if err = eventSignal(ctx, tx, originalObject, "conflict", map[string]string{"receipt_id": string(result.ReceiptID), "conflict_id": string(conflictID), "source": event.Source, "event_id": event.EventID}); err != nil {
				return err
			}
		} else {
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, queries.IntegrationEventInsert, result.ReceiptID, event.Source, event.EventID, event.Kind, event.ObjectID, []byte(event.Payload)); err != nil {
				return err
			}
			if err = eventSignal(ctx, tx, event.ObjectID, "received", map[string]string{"receipt_id": string(result.ReceiptID), "source": event.Source, "event_id": event.EventID, "kind": event.Kind}); err != nil {
				return err
			}
		}
		if !gateway.freshTimestamp(timestamp) {
			return ErrEventUnauthorized
		}
		return nil
	})
	if errors.Is(err, ErrEventUnauthorized) {
		return EventReceipt{}, ErrEventUnauthorized
	}
	if err != nil {
		return EventReceipt{}, ErrEventUnavailable
	}
	if conflict {
		return EventReceipt{}, ErrEventConflict
	}
	return result, nil
}
