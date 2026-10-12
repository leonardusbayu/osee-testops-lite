# Contributing

## Working agreement

- Use one focused branch and pull request per change. Include the intended behavior, test commands, actual results and unresolved limitations.
- Keep Go dependency pins and checksums. Add a dependency only after review.
- Reproduce a bug with a failing test before its fix. Keep every existing acceptance case; a skipped database test does not prove the protected workflow.
- Change reviewed SQL under `db/queries/` through `scripts/generate-staff-queries.py`, then verify the generated binding checks. Preserve migration history.

## Authentication and data safety

- Test with synthetic participants and a dedicated disposable database.
- Preserve current-authority, role/object, MFA, CSRF, one-use capability and transaction-final-state checks.
- An explicitly selected participant is not permission to merge profiles, rebind authentication ownership or grant staff authority.
- Require genuine current staff eligibility for assignments. Synthetic staff fixtures are not owner enrollment or a live permission grant.
- Leave outbound providers disabled. Coordinate any runtime, schema cleanup, genuine owner setup or deployment with the owner.

## Secrets and provenance

Keep environment files, keys, session tokens, MFA seeds, bootstrap/recovery material, database dumps and raw operational logs out of Git and issue/PR comments. Synthetic test constants are not credentials for the creator's runtime.

The repository is a fresh collaboration snapshot with no imported parent Git history or creator-owned resource manifest. Its source provenance is recorded in `docs/SOURCE_SNAPSHOT.json`. The creator's isolated candidate remains a separate single-writer workspace; pull requests do not automatically change or deploy it.

## Before submitting

1. Review the exact diff for credentials and unintended generated artifacts.
2. Run the affected regression tests with the required synthetic database setup.
3. Run the complete applicable normal/race suites; attach their truthful outcomes and explicitly list skips, package failures and incomplete runs.
4. State whether the change affects enrollment, current authority, SQL/migrations, idempotency, assignment or deployment configuration.

No automatic CI or deployment workflow is included in this initial publication. Arrange reviewed CI and the account's usage limits before enabling automation.
