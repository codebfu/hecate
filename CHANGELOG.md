# Changelog

## Unreleased

## 1.2.1 — 2026-11-08

### Fixed

- Cancelling a dispatched/running command now signals the agent via heartbeat so in-flight `shell.run` processes are killed instead of leaving the agent stuck until timeout.

### Added

- `GET /healthz` liveness endpoint; Docker/Caddy healthchecks and autoheal labels for production compose.
- Identity `cancel_command` may abort queued, dispatched, or running commands owned by that identity.

## 1.2.0 — 2026-09-30

### Added

- Propylaea rate-limit snapshots on proxy heartbeat (enroll / allowed / unrecognized).
- Admin API and proxy detail UI to list limited client IPs and queue unbans delivered on proxy sync.

## 1.0.0 — 2026-08-31

Initial public release.
