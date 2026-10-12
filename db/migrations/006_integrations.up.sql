-- Normalized ingress observations only; transport authentication never verifies business state.
CREATE TABLE IF NOT EXISTS integration_events (
 receipt_id uuid PRIMARY KEY REFERENCES inbound_receipts(id),
 source text NOT NULL CHECK(source IN ('tinycommand','trafft','anychat','partner')),
 event_key text NOT NULL CHECK(event_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
 kind text NOT NULL CHECK(
  (source='tinycommand' AND kind IN ('registration.submitted','schedule.changed','reminder.requested','result.imported','shipment.updated','task.requested')) OR
  (source='trafft' AND kind IN ('booking.created','booking.updated','booking.cancelled')) OR
  (source='anychat' AND kind IN ('conversation.created','conversation.updated','ticket.created','ticket.updated','message.status')) OR
  (source='partner' AND kind IN ('registration.submitted','settlement.reported'))
 ),
 object_id uuid NOT NULL CHECK(object_id <> '00000000-0000-0000-0000-000000000000'::uuid),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=32768),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(source,event_key)
);
CREATE TABLE IF NOT EXISTS integration_event_conflicts (
 id uuid PRIMARY KEY,
 receipt_id uuid NOT NULL REFERENCES integration_events(receipt_id),
 incoming_fingerprint text NOT NULL CHECK(incoming_fingerprint ~ '^[0-9a-f]{64}$'),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(receipt_id,incoming_fingerprint)
);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='integration_events'::regclass AND tgname='integration_event_immutable') THEN
  CREATE TRIGGER integration_event_immutable BEFORE UPDATE OR DELETE ON integration_events FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='integration_event_conflicts'::regclass AND tgname='integration_event_conflict_immutable') THEN
  CREATE TRIGGER integration_event_conflict_immutable BEFORE UPDATE OR DELETE ON integration_event_conflicts FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
 END IF;
END $$;
