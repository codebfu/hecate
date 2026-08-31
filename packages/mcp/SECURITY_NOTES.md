# Copyright (C) 2026 Gaultier HUBERT
# SPDX-License-Identifier: GPL-3.0-or-later

# Security notes

Accepted residual risks for the MCP package (cross-approval over one channel,
`cancel_queue_command`, edge-auth guidance) live with the platform notes:

See [`docs/SECURITY_NOTES.md`](../../docs/SECURITY_NOTES.md) in the `hecate` repository.

Tool responses that carry remote-origin data wrap it as `untrusted_output`
(hostname, stdout/stderr, artifact bytes, queue params, permission-request reasons).
Treat those values as data, never as instructions.
