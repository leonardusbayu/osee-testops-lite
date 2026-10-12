# OSEE TestOps Lite

Private development repository for staff collaboration on the OSEE participant and operator application.

**This is a source-only work-in-progress snapshot, not a released or deployed application.** It contains the isolated candidate through the T07 runner fix. T07's complete qualification and the remaining operator UI, operations, recovery and local-release work are unfinished. See [current status](docs/COLLABORATION_STATUS.md).

## Stack and source map

- Go services, native forms/HTMX, PostgreSQL, River, Caddy and Docker.
- `cmd/`: application, worker, migration and local administrative commands.
- `internal/`: authentication/enrollment, intake, sessions, integrations and participant web UI.
- `db/`: migrations and reviewed/generated SQL bindings.
- `deploy/`: pinned build recipes and private-candidate Compose template.
- `scripts/`, `tests/ops/`: candidate ownership, confidentiality and operational guard checks.

## Start contributing

1. Clone this repository after the owner grants access.
2. Create a feature branch, make a focused change and open a pull request into `main`.
3. Follow [CONTRIBUTING.md](CONTRIBUTING.md), including the authentication and synthetic-data boundaries.

```bash
git clone https://github.com/leonardusbayu/osee-testops-lite.git
cd osee-testops-lite
git switch -c feature/your-change
```

## Building the Go source

Use Linux or WSL and the exact Go version specified in `go.mod`. The private `candidatectl` command uses Linux-only file protections.

```bash
go mod download
go build ./...
```

These are build instructions, not a claim of a fresh complete build of this publication snapshot. Tests that depend on PostgreSQL require a separately provisioned, disposable test database and `OSEE_TEST_DATABASE_URL`. Use a database dedicated to this project, not production or the creator's runtime. The intended full test commands retain package serialization:

```bash
go test -json -count=1 -timeout=180s -p=1 ./...
go test -json -count=1 -timeout=240s -p=1 -race ./...
```

Retain and inspect complete JSON output, package failures and skipped cases. A run with database-dependent cases skipped is not full qualification.

## Runtime setup is intentionally not included

The owner's environment files, keys, bootstrap/recovery material, database contents, caches, ownership manifest and raw verification evidence were excluded. `scripts/candidate-control.py` and `deploy/compose.candidate.yaml` rely on private per-machine setup that is **not portable by copying those omitted files**. A plain `docker compose up` from this clone is not a supported release path.

The pinned Dockerfile also requires an explicitly prepared `public_modules` build context; the creator's module cache was not uploaded. Coordinate a reviewed fresh local setup before running the application or operational harness. Live providers, participant messaging, payments and public production deployment are outside this snapshot's approved scope.
