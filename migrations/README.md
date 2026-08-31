# Database migrations

SQLx records a checksum for every applied migration. **Never edit a migration file after it has shipped** (merged to `master` or included in a release tag). If a follow-up change is needed:

1. Add a **new** migration file with a later timestamp.
2. Use `ON CONFLICT` / idempotent `UPDATE` when backfilling data for databases that already ran the original migration.

Editing an applied migration causes startup failure:

```text
Error: migration <version> was previously applied but has been modified
```
