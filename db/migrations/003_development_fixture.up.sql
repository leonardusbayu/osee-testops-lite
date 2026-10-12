-- Explicit opt-in local synthetic fixture provenance, never a production account table.
CREATE TABLE development_fixtures (
 name text PRIMARY KEY CHECK(name='participant-demo'),
 kind text NOT NULL DEFAULT 'local-synthetic' CHECK(kind='local-synthetic'),
 participant_id uuid NOT NULL UNIQUE REFERENCES participants(id),
 principal_id uuid NOT NULL UNIQUE REFERENCES auth_principals(id),
 session_id uuid NOT NULL UNIQUE REFERENCES sessions(id),
 registration_id uuid NOT NULL UNIQUE REFERENCES registrations(id),
 created_at timestamptz NOT NULL DEFAULT now()
);
