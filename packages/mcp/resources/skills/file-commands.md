# File Commands

Hecate provides first-class file transfer commands. All three require operator approval when `requires_approval_for_shell` is enabled on the AI identity.

Path access uses the same allowlist as `shell.run`: `shell_policy.allowed_cwd` (prefix match, subdirectories allowed).

## file.pull

Read a file from the machine and stage it on the server for AI download.

```json
{
  "machine_id": "<uuid>",
  "command_name": "file.pull",
  "params": { "path": "/tmp/data/config.yml" }
}
```

After `get_command` returns `completed`, parse stdout JSON for `artifact_id`, then call `download_command_artifact`.

## file.push

Two-step workflow:

1. **Upload** — `upload_command_artifact` with base64 file content
2. **Enqueue** — `execute_command`:

```json
{
  "machine_id": "<uuid>",
  "command_name": "file.push",
  "params": {
    "dest_path": "/tmp/deploy/app.conf",
    "artifact_id": "<uuid from upload>",
    "sha256": "<sha256 from upload>",
    "mode": "0644"
  }
}
```

## remote.download

Download an HTTPS URL from the machine network.

```json
{
  "machine_id": "<uuid>",
  "command_name": "remote.download",
  "params": {
    "url": "https://example.com/pkg.tar.gz",
    "dest_path": "/tmp/pkg.tar.gz",
    "headers": { "Authorization": "Bearer token" }
  }
}
```

- `dest_path` is optional. When omitted, the downloaded bytes are staged as an output artifact (like `file.pull`).
- Only `https://` URLs are allowed. Private/reserved IP targets are blocked.

## Limits

- Max file size: see `max_file_bytes` in `hecate://context/permissions` (default 50 MiB).
- Artifacts expire after 24 hours on the server.

## Local file manipulation

Path access uses the same `allowed_cwd` allowlist. All commands require operator approval when `requires_approval_for_shell` is enabled.

| Command | Params |
|---------|--------|
| `file.copy` | `{ "src", "dest" }` |
| `file.move` | `{ "src", "dest" }` |
| `file.rename` | `{ "path", "new_name" }` |
| `file.delete` | `{ "path" }` |
| `folder.mkdir` | `{ "path", "mode"? }` — creates one directory level |
| `folder.rmdir` | `{ "path" }` — empty directory only |
| `folder.rename` | `{ "path", "new_name" }` |
| `folder.move` | `{ "src", "dest" }` |
| `folder.copy` | `{ "src", "dest" }` — recursive |

Destinations must not exist. `folder.rmdir` fails if the directory is not empty.

## Before calling

1. Read `hecate://context/permissions` — confirm command is allowed and paths fall under `allowed_cwd`.
2. Use async workflow: `execute_command` with `wait=false`, then poll `get_command`.
