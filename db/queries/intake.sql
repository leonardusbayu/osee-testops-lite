-- name: IntakeSourceLock :exec
SELECT pg_advisory_xact_lock(hashtextextended($1,73629105));

-- name: IntakeReceipt :one
SELECT i.id::text,i.fingerprint,r.registration_snapshot FROM inbound_receipts i LEFT JOIN intake_records r ON r.receipt_id=i.id WHERE i.provider=$1 AND i.event_key=$2;

-- name: IntakeOrder :one
SELECT receipt_id::text FROM intake_records WHERE source_key=$1 AND order_reference=$2;

-- name: IntakeConflict :one
INSERT INTO intake_conflicts(id,receipt_id,source_key,event_reference,fingerprint,reason,actor_id) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(source_key,event_reference,fingerprint,reason) DO NOTHING RETURNING id::text;

-- name: IntakeSession :one
SELECT starts_at,cutoff_at,schedule_version FROM sessions WHERE id=$1 FOR SHARE;

-- name: IntakePerson :one
SELECT participant_id::text FROM intake_person_bindings WHERE source_key=$1 AND person_reference=$2;

-- name: IntakeSelectedPerson :one
SELECT coalesce(display_name,''),coalesce(email,''),coalesce(phone,'') FROM participants WHERE id=$1 FOR SHARE;

-- name: IntakeSelectedOutcome :one
SELECT EXISTS(SELECT 1 FROM registrations r JOIN participants p ON p.id=r.participant_id
JOIN intake_person_bindings b ON b.participant_id=p.id AND b.person_reference=$13 AND b.source_key=$14
WHERE r.id=$1 AND r.participant_id=$2 AND r.session_id=$3 AND r.product_reference=$4
AND r.version=$5 AND r.intake_schedule_version=$6 AND coalesce(r.partner_id::text,'')=$7
AND r.registration_state=$8 AND r.external_registration_state=$9
AND coalesce(p.display_name,'')=$10 AND coalesce(p.email,'')=$11 AND coalesce(p.phone,'')=$12);

-- name: IntakeNewPerson :exec
INSERT INTO participants(id,display_name,email,phone) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''));

-- name: IntakeBindPerson :exec
INSERT INTO intake_person_bindings(source_key,person_reference,participant_id,actor_id) VALUES($1,$2,$3,$4);

-- name: IntakeNewRegistration :exec
INSERT INTO registrations(id,participant_id,session_id,product_reference,partner_id,intake_schedule_version) VALUES($1,$2,$3,$4,NULLIF($5,'')::uuid,$6);

-- name: IntakeNewReceipt :exec
INSERT INTO inbound_receipts(id,provider,event_key,fingerprint,received_at) VALUES($1,$2,$3,$4,clock_timestamp());

-- name: IntakeRecord :exec
INSERT INTO intake_records(receipt_id,registration_id,source_key,order_reference,registration_snapshot,participant_snapshot,consent_snapshot,actor_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8);

-- name: IntakeAudit :exec
INSERT INTO audit_events(id,object_id,action,actor_id) VALUES($1,$2,$3,$4);

-- name: IntakeOutbox :exec
INSERT INTO outbox(id,object_id,event_kind,schedule_version,payload) VALUES($1,$2,'intake_created',$3,$4);
