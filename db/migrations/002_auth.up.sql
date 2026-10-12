-- Auth owns principal identity; contact details never determine or merge ownership.
CREATE TABLE auth_principals (
    id uuid PRIMARY KEY,
    role text NOT NULL CHECK (role IN ('participant','partner','admin','owner')),
    participant_id uuid UNIQUE REFERENCES participants(id),
    partner_id uuid,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (role='participant' AND participant_id IS NOT NULL AND partner_id IS NULL)
        OR (role='partner' AND partner_id IS NOT NULL AND participant_id IS NULL)
        OR (role IN ('admin','owner') AND participant_id IS NULL AND partner_id IS NULL)
    )
);
CREATE TABLE auth_invites (
    id uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES auth_principals(id),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);
CREATE TABLE auth_sessions (
    id uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES auth_principals(id),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    mfa_verified_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 minutes'),
    CHECK (mfa_verified_at IS NULL OR (mfa_verified_at >= created_at AND mfa_verified_at <= expires_at))
);
CREATE INDEX auth_invites_principal ON auth_invites(principal_id);
CREATE INDEX auth_sessions_principal ON auth_sessions(principal_id);
