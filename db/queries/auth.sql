-- name: ResolveSession :one
SELECT p.id::text, COALESCE(p.participant_id::text,''), COALESCE(p.partner_id::text,''), p.role,
       s.mfa_verified_at, s.created_at, s.expires_at
FROM auth_sessions s JOIN auth_principals p ON p.id=s.principal_id
WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND p.enabled;

-- name: ResolveSessionLocked :one
SELECT p.id::text, COALESCE(p.participant_id::text,''), COALESCE(p.partner_id::text,''), p.role,
       s.mfa_verified_at, s.created_at, s.expires_at
FROM auth_sessions s JOIN auth_principals p ON p.id=s.principal_id
WHERE s.token_hash=$1 AND s.revoked_at IS NULL AND p.enabled
FOR UPDATE OF s,p;

-- name: LockInvite :one
SELECT i.id::text, p.id::text, i.created_at, i.expires_at
FROM auth_invites i JOIN auth_principals p ON p.id=i.principal_id
WHERE i.token_hash=$1 AND i.consumed_at IS NULL AND i.revoked_at IS NULL AND p.enabled AND p.role='participant'
FOR UPDATE OF i,p;

-- name: ConsumeInvite :exec
UPDATE auth_invites SET consumed_at=$2 WHERE id=$1;

-- name: CreateSession :exec
INSERT INTO auth_sessions(id,principal_id,token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5);

-- name: RevokeSession :one
UPDATE auth_sessions SET revoked_at=$2 WHERE token_hash=$1 AND revoked_at IS NULL RETURNING id::text,principal_id::text;

-- name: InvitationTarget :one
SELECT id::text FROM auth_principals WHERE id=$1 AND enabled AND role='participant' FOR UPDATE;

-- name: CreateInvite :exec
INSERT INTO auth_invites(id,principal_id,token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5);

-- name: AuthAudit :exec
INSERT INTO audit_events(id,actor_id,object_id,action) VALUES($1,$2,$3,$4);
