CREATE TABLE IF NOT EXISTS dart_exception_sync (
 exception_id uuid PRIMARY KEY CHECK(exception_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 source_version bigint NOT NULL CHECK(source_version>0),
 desired_hash text NOT NULL CHECK(desired_hash ~ '^[0-9a-f]{64}$'),
 desired_task jsonb NOT NULL CHECK(jsonb_typeof(desired_task)='object' AND octet_length(desired_task::text)<=4096),
 external_task_id text UNIQUE CHECK(external_task_id ~ '^[A-Za-z0-9]{12}$'),
 state text NOT NULL CHECK(state IN ('PENDING','SYNCING','UNCERTAIN','SYNCED')),
 mutation_kind text CHECK(mutation_kind IN ('scan','create','update')),
 lease_token uuid,
 lease_until timestamptz,
 applied_version bigint NOT NULL DEFAULT 0 CHECK(applied_version>=0 AND applied_version<=source_version),
 applied_hash text CHECK(applied_hash ~ '^[0-9a-f]{64}$'),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((state='SYNCING' AND lease_token IS NOT NULL AND lease_until IS NOT NULL) OR (state<>'SYNCING' AND lease_token IS NULL AND lease_until IS NULL)),
 CHECK(state<>'UNCERTAIN' OR (mutation_kind IS NOT NULL AND mutation_kind IN ('create','update'))),
 CHECK(state<>'SYNCED' OR (external_task_id IS NOT NULL AND applied_version=source_version AND applied_hash=desired_hash))
);
CREATE TABLE IF NOT EXISTS dart_exception_sync_history (
 id uuid PRIMARY KEY,
 exception_id uuid NOT NULL REFERENCES dart_exception_sync(exception_id),
 source_version bigint NOT NULL CHECK(source_version>0),
 desired_hash text NOT NULL CHECK(desired_hash ~ '^[0-9a-f]{64}$'),
 state text NOT NULL,
 external_task_id text,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='dart_exception_sync_history'::regclass AND tgname='dart_sync_history_immutable') THEN
  CREATE TRIGGER dart_sync_history_immutable BEFORE UPDATE OR DELETE ON dart_exception_sync_history FOR EACH ROW EXECUTE FUNCTION reject_immutable_change();
 END IF;
END $$;
