# Backup and Migration

## Database migrations

- SQL files in `migrations/` (timestamped, ordered).
- Embedded in `hecate-api` via `sqlx::migrate!`; applied automatically on API startup.
- Local apply without starting server: `make migrate` (requires `sqlx-cli` and `DATABASE_URL`).
- Docker: migrations run when the `api` container starts (entrypoint → `hecate-api`).

## Backup format

- Versioned JSON manifest (`hecate-protocol::backup`) with HMAC over sections.
- Export via admin API (`/api/v1/admin/backup/*`); selective section export supported.
- Import validates manifest version, upgrades older formats when possible, then applies sections transactionally.

## Operational notes

- Take Postgres snapshots before major upgrades or restore operations.
- Rotate `SESSION_SECRET` and `API_KEY_PEPPER` independently; backup export does not include raw pepper values.
- Test restore on a staging instance before applying production imports.
