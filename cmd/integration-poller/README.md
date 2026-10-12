# Local staging queue worker

This command polls the exact TinyCommand outbox and submits narrowly validated operational exception tasks to the exact Dart board. It is disabled by default and has no listener, scheduler, customer messaging, migrations, or payment/booking/result/shipment mutation. Native Trafft observations, blank rows and unrelated kinds do not become task commands.

**Not active:** `api.tinycommand.com` did not resolve during the 2026-10-09 tokenless preflight, and the account's API-key UI/entitlement is not established. The public protocol is documented at <https://tinycommand.com/docs/tables/api>. A live credential and synthetic table round trip must verify the protocol before enabling. Never substitute a guessed host or send credentials to another endpoint.

The optional protected `.local/integrations/poller.json` file defaults to disabled. An example without secrets:

```json
{
  "enabled": false,
  "staging": true,
  "table_id": "cmv0m8pgc0wglh7nyr0u9p0eu",
  "dartboard": "osee.co.id TestOps/Tasks",
  "tiny_credentials_file": ".local/integrations/tinycommand.json",
  "dart_token_file": ".local/integrations/dart-token",
  "source_secret_file": ".local/integrations/tinycommand-source-secret"
}
```

Enabled execution additionally requires `-once`. Other tables, boards, non-staging mode, arbitrary input payloads and paths outside `.local/integrations` are rejected. JSON requires exact lowercase field names, no unknown/duplicate keys and one bounded object. TinyCommand credentials are a separate protected JSON object with only `api_key`. Dart token and the 32–256-character internal receipt secret are separate protected text files. The internal secret authenticates the normalized local hop; it does not prove a native vendor webhook, payment or exam outcome. This command does not create or rotate credentials.

Restrict NTFS ACLs to the integration owner, SYSTEM and Administrators. On Unix, files must be owner-only (`0600`); regular files only, no symlinks. Do not put credentials or a database DSN in arguments, source, screenshots or documentation.

Execution reuses `config.Load`: `APP_ENV=development`, the isolated `osee_testops_dev` database at `osee-testops-db:5432`, `OUTBOUND_MODE=off`, and test recipients. Because the database host is intentionally container-local, run the built command inside the existing isolated Docker network/environment. A native Windows invocation cannot bypass that environment guard. Existing database migrations must already be applied through the approved workflow; this command never runs them.

NTFS-protected bind-mounted files can appear group/world-readable inside Linux Docker. Do not relax the Unix permission guard. An eventual approved one-shot launcher must copy only the configured secrets and configuration into an owned private tmpfs working directory, set files to `0600`, preserve the relative `.local/integrations` paths, and run the binary there. It must verify the owned database/network and pass database credentials without printing them. This launcher is not an active recurring deployment.

```text
integration-poller -config .local/integrations/poller.json -once
```

Before any task write, the command checks all nine exact queue column names: `event_id`, `source`, `kind`, `object_id`, `source_version`, `receipt_id`, `last_error`, `envelope_json`, `queue_status`. The documented schema example verifies API type `text` only. The actual UI uses Short Text and Long Text for `envelope_json`; its API enum mapping is unverified. The current gate deliberately requires exact `text` and fails closed on any different type. Resolve the observed API mapping and update the gate with evidence before enabling. Schema is checked again for each page and acknowledgment. Exact table ID is the scope boundary; a name is not participant authentication.

Rows are fetched without a mutable status filter, in bounded pages of 100 with a 10,000-row local ceiling. Only allowed operational envelopes reach EventGateway's durable receipts and DartSynchronizer's durable mapping. Invalid events and uncertain outcomes remain review/retry entries. The only TinyCommand writes are `queue_status`, `receipt_id`, and allowlisted machine-code `last_error`. Duplicate processing must retain the event/exception identity and reuse durable receipts; an ambiguous Dart write requires read-only reconciliation.

JSON output contains counts only. `acknowledgments_submitted` means a PATCH received a successful HTTP status, **not** verified persistence or fulfillment. After each accepted acknowledgment, the worker rereads its bounded page and checks one matching row, its unchanged event identity/envelope/version, status, receipt and error code. Missing, changed or unpersisted bookkeeping stops the pass while preserving local receipts. Readback is an observation, not an atomic update or guarantee against later row changes. No repeated business operation is allowed after bookkeeping failure. This command makes no automatic retries and exits after one bounded pass.

Before enabling, prove that event identity, envelope and source version are append-only in the cloud queue: create a new row for each event/version and prevent workflows or editors from replacing a pending row's identity. This API does not document a conditional PATCH or compare-and-swap operation. A row changed between read and acknowledgment can otherwise receive an old acknowledgment for a new request. Local durable receipts prevent duplicate Dart writes but cannot make that cloud update atomic. This remains an activation gate; schema checks alone do not close it.
