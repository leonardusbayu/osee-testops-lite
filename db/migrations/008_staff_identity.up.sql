CREATE TABLE app_instance (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE auth_principals ADD CONSTRAINT auth_principals_id_role UNIQUE (id,role);
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_id_principal UNIQUE (id,principal_id);
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_attestation_binding UNIQUE (id,principal_id,created_at,expires_at);

CREATE TABLE auth_staff_credentials (
    principal_id uuid PRIMARY KEY,
    instance_id uuid NOT NULL REFERENCES app_instance(id),
    role text NOT NULL CHECK (role IN ('owner','admin')),
    username text NOT NULL CHECK (username ~ '^[A-Za-z0-9._-]{3,32}$'),
    password_hash text CHECK (password_hash ~ '^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'),
    credential_epoch bigint NOT NULL DEFAULT 1 CHECK (credential_epoch > 0),
    factor_version bigint CHECK (factor_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (principal_id,role) REFERENCES auth_principals(id,role),
    UNIQUE (instance_id,principal_id),
    UNIQUE (principal_id,role),
    CHECK (password_hash IS NOT NULL OR factor_version IS NULL)
);
CREATE UNIQUE INDEX auth_staff_username ON auth_staff_credentials(lower(username));

CREATE TABLE auth_staff_factors (
    instance_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    factor_version bigint NOT NULL CHECK (factor_version > 0),
    encrypted_seed bytea NOT NULL CHECK (octet_length(encrypted_seed)=60),
    last_totp_counter bigint NOT NULL DEFAULT -1 CHECK (last_totp_counter >= -1),
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz CHECK (revoked_at >= enrolled_at),
    PRIMARY KEY (principal_id,factor_version),
    UNIQUE (instance_id,principal_id,factor_version),
    FOREIGN KEY (instance_id,principal_id) REFERENCES auth_staff_credentials(instance_id,principal_id)
);
CREATE UNIQUE INDEX auth_staff_active_factor ON auth_staff_factors(principal_id) WHERE revoked_at IS NULL;
-- Keep historical attestations bound to their original factor during rotation.
ALTER TABLE auth_staff_credentials ADD CONSTRAINT auth_staff_current_factor
FOREIGN KEY (instance_id,principal_id,factor_version)
REFERENCES auth_staff_factors(instance_id,principal_id,factor_version) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE auth_bootstrap (
    instance_id uuid PRIMARY KEY REFERENCES app_instance(id),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    finalized_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    CHECK (consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at <= expires_at)),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (finalized_at IS NULL OR (consumed_at IS NOT NULL AND finalized_at >= consumed_at))
);

CREATE TABLE auth_staff_challenges (
    id uuid PRIMARY KEY,
    instance_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    target_role text NOT NULL CHECK (target_role IN ('owner','admin')),
    kind text NOT NULL CHECK (kind IN ('owner_enroll','admin_invite','admin_enroll','login','step_up','replacement','recovery')),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash)=32),
    factor_version bigint NOT NULL CHECK (factor_version > 0),
    credential_epoch bigint NOT NULL CHECK (credential_epoch > 0),
    encrypted_seed bytea CHECK (octet_length(encrypted_seed)=60),
    session_id uuid,
    issuer_id uuid,
    issuer_session_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    revoked_at timestamptz,
    FOREIGN KEY (instance_id,principal_id) REFERENCES auth_staff_credentials(instance_id,principal_id),
    FOREIGN KEY (principal_id,target_role) REFERENCES auth_staff_credentials(principal_id,role),
    FOREIGN KEY (session_id,principal_id) REFERENCES auth_sessions(id,principal_id),
    FOREIGN KEY (issuer_session_id,issuer_id) REFERENCES auth_sessions(id,principal_id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '5 minutes'),
    CHECK (consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at <= expires_at)),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK ((kind IN ('owner_enroll','admin_enroll','replacement','recovery')) = (encrypted_seed IS NOT NULL)),
    CHECK ((kind IN ('step_up','replacement')) = (session_id IS NOT NULL)),
    CHECK (
        (kind IN ('admin_invite','admin_enroll') AND target_role='admin' AND issuer_id IS NOT NULL
         AND issuer_session_id IS NOT NULL AND issuer_id<>principal_id)
        OR (kind NOT IN ('admin_invite','admin_enroll') AND issuer_id IS NULL AND issuer_session_id IS NULL)
    ),
    CHECK (kind<>'owner_enroll' OR target_role='owner')
);
CREATE INDEX auth_staff_challenges_principal ON auth_staff_challenges(principal_id,expires_at);
CREATE INDEX auth_staff_challenges_issuer ON auth_staff_challenges(issuer_id) WHERE issuer_id IS NOT NULL;

CREATE TABLE auth_staff_recovery (
    instance_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    factor_version bigint NOT NULL,
    slot smallint NOT NULL CHECK (slot BETWEEN 1 AND 10),
    code_hash bytea NOT NULL UNIQUE CHECK (octet_length(code_hash)=32),
    created_at timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz CHECK (consumed_at >= created_at),
    revoked_at timestamptz CHECK (revoked_at >= created_at),
    PRIMARY KEY (principal_id,factor_version,slot),
    FOREIGN KEY (instance_id,principal_id,factor_version) REFERENCES auth_staff_factors(instance_id,principal_id,factor_version)
);

CREATE TABLE auth_staff_attestations (
    session_id uuid PRIMARY KEY,
    instance_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    factor_version bigint NOT NULL,
    credential_epoch bigint NOT NULL CHECK (credential_epoch > 0),
    session_created_at timestamptz NOT NULL,
    session_expires_at timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    FOREIGN KEY (session_id,principal_id,session_created_at,session_expires_at)
        REFERENCES auth_sessions(id,principal_id,created_at,expires_at),
    FOREIGN KEY (instance_id,principal_id,factor_version)
        REFERENCES auth_staff_factors(instance_id,principal_id,factor_version),
    CHECK (verified_at >= session_created_at AND verified_at <= session_expires_at)
);
CREATE INDEX auth_staff_attestations_principal ON auth_staff_attestations(principal_id);

CREATE TABLE auth_staff_rates (
    key_hash bytea PRIMARY KEY CHECK (octet_length(key_hash)=32),
    instance_id uuid NOT NULL REFERENCES app_instance(id),
    kind text NOT NULL CHECK (kind IN ('login_account','login_peer','recover_account','recover_peer')),
    attempts integer NOT NULL CHECK (attempts BETWEEN 1 AND 10000),
    window_started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > window_started_at AND expires_at <= window_started_at + interval '15 minutes')
);
CREATE INDEX auth_staff_rates_expiry ON auth_staff_rates(expires_at);

CREATE TABLE app_operating_state (
    instance_id uuid PRIMARY KEY REFERENCES app_instance(id),
    worker_heartbeat_at timestamptz,
    last_job_success_at timestamptz,
    last_checked_backup_at timestamptz
);
