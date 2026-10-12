-- Additive intake provenance; legacy people/attempts keep unknown fields NULL.
ALTER TABLE participants ADD COLUMN IF NOT EXISTS display_name text CHECK(display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 120);
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS product_reference text CHECK(product_reference IS NULL OR product_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$');
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS partner_id uuid;
ALTER TABLE registrations ADD COLUMN IF NOT EXISTS intake_schedule_version bigint CHECK(intake_schedule_version>0);
CREATE TABLE IF NOT EXISTS intake_person_bindings (
 source_key text NOT NULL,
 person_reference text NOT NULL CHECK(person_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
 participant_id uuid NOT NULL REFERENCES participants(id),
 actor_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(source_key,person_reference)
);
CREATE TABLE IF NOT EXISTS intake_records (
 receipt_id uuid PRIMARY KEY REFERENCES inbound_receipts(id),
 registration_id uuid NOT NULL UNIQUE REFERENCES registrations(id),
 source_key text NOT NULL,
 order_reference text NOT NULL CHECK(order_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
 registration_snapshot jsonb NOT NULL CHECK(jsonb_typeof(registration_snapshot)='object'),
 participant_snapshot jsonb NOT NULL CHECK(jsonb_typeof(participant_snapshot)='object'),
 consent_snapshot jsonb NOT NULL CHECK(jsonb_typeof(consent_snapshot)='object'),
 actor_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(source_key,order_reference)
);
CREATE TABLE IF NOT EXISTS intake_conflicts (
 id uuid PRIMARY KEY,
 receipt_id uuid NOT NULL REFERENCES inbound_receipts(id),
 source_key text NOT NULL,
 event_reference text NOT NULL CHECK(event_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'),
 fingerprint text NOT NULL CHECK(fingerprint ~ '^[0-9a-f]{64}$'),
 reason text NOT NULL CHECK(reason IN ('event_reuse','order_reuse','receipt_collision')),
 actor_id uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(source_key,event_reference,fingerprint,reason)
);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='intake_person_bindings'::regclass AND tgname='intake_person_immutable') THEN
  CREATE TRIGGER intake_person_immutable BEFORE UPDATE OR DELETE ON intake_person_bindings FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='intake_records'::regclass AND tgname='intake_record_immutable') THEN
  CREATE TRIGGER intake_record_immutable BEFORE UPDATE OR DELETE ON intake_records FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='intake_conflicts'::regclass AND tgname='intake_conflict_immutable') THEN
  CREATE TRIGGER intake_conflict_immutable BEFORE UPDATE OR DELETE ON intake_conflicts FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
 END IF;
END $$;
