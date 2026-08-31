# Hecate

Server platform: API, operator UI, MCP bridge, and shared `hecate-protocol` crate.

## Quick start (development)

Build images locally from this repository:

```bash
make prerequisites
make test
make docker-up   # local stack via docker/docker-compose.yml
```

## Run with GHCR images (no local build)

Pull the published images from GitHub Container Registry and start the stack with
[`docker/docker-compose.prod.yml`](docker/docker-compose.prod.yml):

```bash
cp docker/.env.example docker/.env
# Edit docker/.env: set strong secrets and your public host / WebAuthn values.
docker compose -f docker/docker-compose.prod.yml --env-file docker/.env pull
docker compose -f docker/docker-compose.prod.yml --env-file docker/.env up -d
```

Defaults (override with `HECATE_API_IMAGE` / `HECATE_MCP_IMAGE` in `.env`):

| Service | Image |
|---|---|
| API + UI | `ghcr.io/codebfu/hecate:1.0.0` |
| MCP | `ghcr.io/codebfu/hecate-mcp:1.0.0` |

Images are public on GHCR; `docker login` is not required to pull.

- API / operator UI: `http://127.0.0.1:8080` (or `API_PORT`)
- MCP (loopback only): `http://127.0.0.1:3100` (or `MCP_PORT` / `MCP_BIND_ADDR`)

For a full production install (TLS reverse proxy, host layout, systemd), see
[docs/install.md](docs/install.md). Ecosystem map: [docs/ecosystem.md](docs/ecosystem.md).

## Official feature repository

Agent installers, helpers, and feature packages are published to a signed static repository:

| Setting | Value |
|---|---|
| URL | `https://repo.hecate-mcp.com` |
| Ed25519 public key (base64) | `kHWEtm3yvH9wV2PPb2FMB9XJ0oM68CvUXTUxzAWeGTo=` |

Set the same value in production as `RELEASE_SIGNING_PUBLIC_KEY_B64` (see [`docker/.env.example`](docker/.env.example)).
Hecate verifies every `features.json`, manifest, and artifact against this key. A mismatch produces
`repository signature verification failed`.

The key is also baked into the API as `OFFICIAL_PUBLIC_KEY_B64` when the env var is empty; for
production deployments always set the env var explicitly so `repo_sources` and release verification
stay aligned after restarts.

Legacy GitLab Package Registry key (pre–v1.0.0 public repo): `DUmxIh9XT8jpvDyeQ9QTmmC3ddC4xr9abA3faSNusqY=`

## License

GPL-3.0-or-later — Copyright (C) 2026 Gaultier HUBERT.
