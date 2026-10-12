-- Additive T05 storage; legacy rows retain unknown assignment/reference provenance.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS schedule_version bigint NOT NULL DEFAULT 1 CHECK(schedule_version>0);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS assigned_staff_id uuid;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS guide_reference text CHECK(guide_reference IS NULL OR guide_reference ~ '^[A-Za-z0-9._:/-]{1,128}$');
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS meeting_reference text CHECK(meeting_reference IS NULL OR meeting_reference ~ '^[A-Za-z0-9._:/-]{1,128}$');
-- Durable initiating actor IDs deliberately do not reference deletable current principals.
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS actor_id uuid;
ALTER TABLE outbox ADD COLUMN IF NOT EXISTS schedule_version bigint CHECK(schedule_version>0);
ALTER TABLE outbox ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(payload)='object');
CREATE TABLE IF NOT EXISTS session_schedule_history (
 session_id uuid NOT NULL REFERENCES sessions(id),
 schedule_version bigint NOT NULL CHECK(schedule_version>0),
 row_version bigint NOT NULL CHECK(row_version>0),
 starts_at timestamptz NOT NULL,
 cutoff_at timestamptz NOT NULL CHECK(cutoff_at<=starts_at),
 capacity integer NOT NULL CHECK(capacity>0),
 assigned_staff_id uuid,
 guide_reference text,
 meeting_reference text,
 host_ready boolean NOT NULL,
 actor_id uuid,
 reason text NOT NULL CHECK(char_length(reason) BETWEEN 1 AND 500),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(session_id,schedule_version)
);
INSERT INTO session_schedule_history(session_id,schedule_version,row_version,starts_at,cutoff_at,capacity,assigned_staff_id,guide_reference,meeting_reference,host_ready,actor_id,reason)
SELECT id,schedule_version,version,starts_at,cutoff_at,capacity,assigned_staff_id,guide_reference,meeting_reference,host_ready,NULL,'legacy_snapshot' FROM sessions
ON CONFLICT(session_id,schedule_version) DO NOTHING;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='session_schedule_history'::regclass AND tgname='session_history_immutable') THEN
  CREATE TRIGGER session_history_immutable BEFORE UPDATE OR DELETE ON session_schedule_history FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
 END IF;
END $$;
