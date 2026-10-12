# Local integration receiver

This separate process binds only `127.0.0.1` or `::1`. It mounts authenticated `POST /v1/integration-events` and `GET /healthz`, which reports database reachability. It does not run migrations, create accounts, send messages, or change bookings/payments/results. EventGateway owns validated durable observation receipts; its schema must be deployed separately under the approved database workflow. A healthy process is not proof that an event has been accepted or a business transition completed.

Build the Windows executable with the pinned existing Go SDK. Run from the repository root:

```powershell
.\.local\bin\integration-gateway.exe -config .local/integrations/gateway.json
```

The protected local JSON file requires `listen_address`, `database_url` and a `sources` object. Listener ports must be explicit. Database URL must be PostgreSQL at an explicit loopback address/port, with credentials and an `osee_testops_` database name. Allowed query parameters: `sslmode` (disable, require, verify-full), and optional `connect_timeout` (1–10 seconds). Supported source names are tinycommand, trafft, anychat and partner; each enabled source requires a 32–256-byte shared secret. No unknown or duplicate JSON fields are accepted. Protect the file's NTFS ACL on Windows; Unix permissions must be owner-only. Never place its real DSN or secrets in documentation or command arguments.

Observed foundation database published port is `127.0.0.1:55438`; this metadata does not authorize connecting to another business database or applying a migration. The proposed gateway listener is `127.0.0.1:8120`, subject to an availability check at launch. This command does not create its secret configuration or launch automatically.

Use the independent read-only preflight for the existing Trafft credentials:

```powershell
.\.local\bin\integration-gateway.exe -trafft-catalog -trafft-credentials .local/integrations/trafft.json
```

This mode uses the actual Go Trafft client and reads only Services metadata, at most ten pages of ten services with a 45-second overall deadline. It does not read the receiver configuration, open a database, bind a server, or call customer/appointment endpoints. The credentials file uses `base_url/client_id/client_secret`; it is not the receiver's inbound source-secret file. Redirects are denied and errors with upstream bodies are withheld.

External SaaS cannot call a loopback URL directly. A separately approved HTTPS ingress/proxy and sender configuration are required before activating external event delivery. Trafft's static verification token and raw payload do not meet the gateway's timestamp/HMAC normalized-event contract without an authenticated adapter. No CORS access is provided.
