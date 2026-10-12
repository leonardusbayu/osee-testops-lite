-- name: IntegrationReceiptInsert
INSERT INTO inbound_receipts(id,provider,event_key,fingerprint) VALUES($1,$2,$3,$4) ON CONFLICT(provider,event_key) DO NOTHING RETURNING id;
-- name: IntegrationReceiptRead
SELECT r.id,r.fingerprint,e.object_id FROM inbound_receipts r JOIN integration_events e ON e.receipt_id=r.id WHERE r.provider=$1 AND r.event_key=$2;
-- name: IntegrationEventInsert
INSERT INTO integration_events(receipt_id,source,event_key,kind,object_id,payload) VALUES($1,$2,$3,$4,$5,$6);
-- name: IntegrationConflictInsert
INSERT INTO integration_event_conflicts(id,receipt_id,incoming_fingerprint) VALUES($1,$2,$3) ON CONFLICT(receipt_id,incoming_fingerprint) DO NOTHING RETURNING id;
-- name: IntegrationEventAudit
INSERT INTO audit_events(id,object_id,action) VALUES($1,$2,$3);
-- name: IntegrationEventOutbox
INSERT INTO outbox(id,object_id,event_kind,payload) VALUES($1,$2,$3,$4);
