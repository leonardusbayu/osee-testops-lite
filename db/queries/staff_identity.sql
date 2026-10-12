-- name: ReadLogicalInstance :one
SELECT id::text FROM app_instance WHERE singleton;

-- name: LockLogicalInstance :one
SELECT id::text FROM app_instance WHERE singleton FOR UPDATE;

-- name: CreateLogicalInstance :exec
INSERT INTO app_instance(id) VALUES($1) ON CONFLICT(singleton) DO NOTHING;

-- name: LockBootstrap :one
SELECT token_hash,created_at,expires_at,consumed_at,revoked_at,finalized_at
FROM auth_bootstrap WHERE instance_id=$1 FOR UPDATE;

-- name: WriteBootstrap :execrows
INSERT INTO auth_bootstrap(instance_id,token_hash,created_at,expires_at) VALUES($1,$2,$3,$4)
ON CONFLICT(instance_id) DO UPDATE SET token_hash=EXCLUDED.token_hash,created_at=EXCLUDED.created_at,
expires_at=EXCLUDED.expires_at,consumed_at=NULL,revoked_at=NULL
WHERE auth_bootstrap.finalized_at IS NULL;

-- name: ConsumeBootstrap :execrows
UPDATE auth_bootstrap SET consumed_at=$2
WHERE instance_id=$1 AND consumed_at IS NULL AND revoked_at IS NULL AND finalized_at IS NULL AND expires_at>$2;

-- name: CloseBootstrap :execrows
UPDATE auth_bootstrap SET finalized_at=$2
WHERE instance_id=$1 AND consumed_at IS NOT NULL AND finalized_at IS NULL;

-- name: ReadStaffCredential :one
SELECT c.principal_id::text,c.username,c.role,p.enabled,c.password_hash,c.credential_epoch,c.factor_version
FROM auth_staff_credentials c JOIN auth_principals p ON p.id=c.principal_id AND p.role=c.role
WHERE c.instance_id=$1 AND c.principal_id=$2;

-- name: LockStaffCredential :one
SELECT c.principal_id::text,c.username,c.role,p.enabled,c.password_hash,c.credential_epoch,c.factor_version
FROM auth_staff_credentials c JOIN auth_principals p ON p.id=c.principal_id AND p.role=c.role
WHERE c.instance_id=$1 AND c.principal_id=$2 FOR UPDATE OF c,p;

-- name: LockStaffUsername :one
SELECT c.principal_id::text,c.username,c.role,p.enabled,c.password_hash,c.credential_epoch,c.factor_version
FROM auth_staff_credentials c JOIN auth_principals p ON p.id=c.principal_id AND p.role=c.role
WHERE c.instance_id=$1 AND lower(c.username)=lower($2) FOR UPDATE OF c,p;

-- name: CreateStaffCredential :exec
INSERT INTO auth_staff_credentials(instance_id,principal_id,role,username,password_hash)
VALUES($1,$2,$3,$4,$5);

-- name: SetStaffPassword :execrows
UPDATE auth_staff_credentials SET password_hash=$3,credential_epoch=credential_epoch+1
WHERE instance_id=$1 AND principal_id=$2 AND credential_epoch=$4;

-- name: ActivateStaffFactor :one
UPDATE auth_staff_credentials SET factor_version=$3,credential_epoch=credential_epoch+1
WHERE instance_id=$1 AND principal_id=$2 AND credential_epoch=$4 RETURNING credential_epoch;

-- name: LockStaffFactor :one
SELECT encrypted_seed,last_totp_counter,enrolled_at,revoked_at
FROM auth_staff_factors WHERE instance_id=$1 AND principal_id=$2 AND factor_version=$3 FOR UPDATE;

-- name: CreateStaffFactor :exec
INSERT INTO auth_staff_factors(instance_id,principal_id,factor_version,encrypted_seed,last_totp_counter,enrolled_at)
VALUES($1,$2,$3,$4,$5,$6);

-- name: AcceptStaffFactorCounter :execrows
UPDATE auth_staff_factors SET last_totp_counter=$4
WHERE instance_id=$1 AND principal_id=$2 AND factor_version=$3 AND revoked_at IS NULL AND last_totp_counter<$4;

-- name: RevokeStaffFactors :execrows
UPDATE auth_staff_factors SET revoked_at=$3
WHERE instance_id=$1 AND principal_id=$2 AND revoked_at IS NULL;

-- name: CreateStaffChallenge :exec
INSERT INTO auth_staff_challenges(id,instance_id,principal_id,target_role,kind,token_hash,factor_version,credential_epoch,
encrypted_seed,session_id,issuer_id,issuer_session_id,created_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14);

-- name: LockStaffChallenge :one
SELECT id::text,principal_id::text,target_role,kind,factor_version,credential_epoch,encrypted_seed,
session_id::text,issuer_id::text,issuer_session_id::text,created_at,expires_at,consumed_at,revoked_at
FROM auth_staff_challenges WHERE instance_id=$1 AND token_hash=$2 FOR UPDATE;

-- name: ConsumeStaffChallenge :execrows
UPDATE auth_staff_challenges SET consumed_at=$3
WHERE instance_id=$1 AND id=$2 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at>$3;

-- name: RevokeStaffChallenges :execrows
UPDATE auth_staff_challenges SET revoked_at=$3
WHERE instance_id=$1 AND (principal_id=$2 OR issuer_id=$2) AND consumed_at IS NULL AND revoked_at IS NULL;

-- name: CreateStaffRecovery :exec
INSERT INTO auth_staff_recovery(instance_id,principal_id,factor_version,slot,code_hash,created_at)
VALUES($1,$2,$3,$4,$5,$6);

-- name: ConsumeStaffRecovery :execrows
UPDATE auth_staff_recovery SET consumed_at=$5
WHERE instance_id=$1 AND principal_id=$2 AND factor_version=$3 AND code_hash=$4
AND consumed_at IS NULL AND revoked_at IS NULL AND created_at<=$5;

-- name: RevokeStaffRecovery :execrows
UPDATE auth_staff_recovery SET revoked_at=$3
WHERE instance_id=$1 AND principal_id=$2 AND revoked_at IS NULL;

-- name: CreateStaffAttestation :execrows
INSERT INTO auth_staff_attestations(session_id,instance_id,principal_id,factor_version,credential_epoch,
session_created_at,session_expires_at,verified_at)
SELECT id,$2,principal_id,$3,$4,created_at,expires_at,$5 FROM auth_sessions WHERE id=$1;

-- name: ReadStaffAttestation :one
SELECT a.factor_version,a.credential_epoch,a.verified_at
FROM auth_staff_attestations a
JOIN auth_staff_credentials c ON c.instance_id=a.instance_id AND c.principal_id=a.principal_id
JOIN auth_staff_factors f ON f.instance_id=a.instance_id AND f.principal_id=a.principal_id AND f.factor_version=a.factor_version
JOIN auth_sessions s ON s.id=a.session_id AND s.principal_id=a.principal_id
JOIN auth_principals p ON p.id=a.principal_id AND p.role=c.role
WHERE a.instance_id=$1 AND a.session_id=$2 AND a.principal_id=$3
AND c.factor_version=a.factor_version AND c.credential_epoch=a.credential_epoch
AND s.mfa_verified_at=a.verified_at AND s.revoked_at IS NULL AND f.revoked_at IS NULL AND p.enabled
AND s.created_at<=$4 AND s.expires_at>$4;

-- name: IncrementStaffRate :one
INSERT INTO auth_staff_rates(instance_id,key_hash,kind,attempts,window_started_at,expires_at)
VALUES($1,$2,$3,1,$4,$5)
ON CONFLICT(key_hash) DO UPDATE SET
attempts=CASE WHEN auth_staff_rates.expires_at<=EXCLUDED.window_started_at THEN 1 ELSE LEAST(auth_staff_rates.attempts+1,10000) END,
window_started_at=CASE WHEN auth_staff_rates.expires_at<=EXCLUDED.window_started_at THEN EXCLUDED.window_started_at ELSE auth_staff_rates.window_started_at END,
expires_at=CASE WHEN auth_staff_rates.expires_at<=EXCLUDED.window_started_at THEN EXCLUDED.expires_at ELSE auth_staff_rates.expires_at END
WHERE auth_staff_rates.instance_id=EXCLUDED.instance_id AND auth_staff_rates.kind=EXCLUDED.kind
RETURNING attempts;

-- name: LockStaffRate :one
SELECT attempts,window_started_at,expires_at FROM auth_staff_rates
WHERE instance_id=$1 AND key_hash=$2 FOR UPDATE;

-- name: ReadOperatingState :one
SELECT worker_heartbeat_at,last_job_success_at,last_checked_backup_at FROM app_operating_state WHERE instance_id=$1;

-- name: ObserveWorkerHeartbeat :exec
INSERT INTO app_operating_state(instance_id,worker_heartbeat_at) VALUES($1,$2)
ON CONFLICT(instance_id) DO UPDATE SET worker_heartbeat_at=EXCLUDED.worker_heartbeat_at;

-- name: ObserveJobSuccess :exec
INSERT INTO app_operating_state(instance_id,last_job_success_at) VALUES($1,$2)
ON CONFLICT(instance_id) DO UPDATE SET last_job_success_at=EXCLUDED.last_job_success_at;

-- name: ObserveCheckedBackup :exec
INSERT INTO app_operating_state(instance_id,last_checked_backup_at) VALUES($1,$2)
ON CONFLICT(instance_id) DO UPDATE SET last_checked_backup_at=EXCLUDED.last_checked_backup_at;
