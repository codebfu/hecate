# Production install (without Ansible)

Manual setup of the Hecate server stack on Ubuntu: PostgreSQL, API, MCP, and Caddy behind HTTPS.

If you prefer automation, use [ansible/README.md](../ansible/README.md) instead.

## What you get

| Component | Role |
|---|---|
| `postgres` | PostgreSQL 16 (internal Docker network only) |
| `api` | Rust API + operator UI |
| `mcp` | MCP HTTP server (no published host port) |
| `caddy` | TLS reverse proxy on a high HTTPS port (default `18443`) |

Public URLs (replace with your FQDN and port):

- Operator UI / API: `https://<fqdn>:18443/`
- MCP: `https://<fqdn>:18443/mcp`
- Lampad agents: `server_url = "https://<fqdn>:18443"`

## Prerequisites

- Ubuntu host with root/sudo SSH access
- DNS `A`/`AAAA` for your FQDN pointing at the server
- Firewall: allow **only** the HTTPS port (default **18443/tcp**); do not open HTTP/80
- Access to the container registry that publishes `api-*` / `mcp-*` images
- Optional: GitLab token with `read_package_registry` for agent release sync
- Optional: Cloudflare API token if you use DNS-01 for Let's Encrypt (recommended when port 80 is closed)

Throughout this guide:

| Placeholder | Example |
|---|---|
| `<FQDN>` | `hecate.example.com` |
| `<HTTPS_PORT>` | `18443` |
| `<REGISTRY>` | `ghcr.io` |
| `<APP_TAG>` | `master` (or a semver like `0.1.42`) |

## 1. Install Docker

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

ARCH="$(dpkg --print-architecture)"
. /etc/os-release
echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker
```

Log in to the private registry (skip if images are public):

```bash
echo '<REGISTRY_PASSWORD>' | sudo docker login <REGISTRY> \
  --username '<REGISTRY_USERNAME>' --password-stdin
```

## 2. Create directories

The API container runs as uid/gid `1000`. Release artifacts, command artifacts, and the update trigger directory must be writable by that user.

```bash
sudo mkdir -p /opt/hecate/{releases,command-artifacts,run}
sudo mkdir -p /etc/hecate/tls
sudo chown 1000:1000 /opt/hecate/{releases,command-artifacts,run}
sudo chmod 0755 /opt/hecate /opt/hecate/{releases,command-artifacts,run}
sudo chmod 0750 /etc/hecate/tls
```

## 3. Deploy compose and Caddy config

Copy the production compose file from this repository:

```bash
sudo cp ansible/roles/hecate_docker/files/docker-compose.yml \
  /opt/hecate/docker-compose.yml
sudo chmod 0644 /opt/hecate/docker-compose.yml
```

Create `/opt/hecate/Caddyfile`:

```caddy
:443 {
    tls /etc/caddy/tls/cert.pem /etc/caddy/tls/key.pem

    handle /mcp* {
        reverse_proxy mcp:3100
    }

    handle {
        reverse_proxy api:8080
    }
}
```

```bash
sudo chmod 0644 /opt/hecate/Caddyfile
```

## 4. Create the environment file

Generate strong secrets (do not reuse defaults):

```bash
openssl rand -hex 32   # POSTGRES_PASSWORD
openssl rand -hex 32   # SESSION_SECRET
openssl rand -hex 32   # API_KEY_PEPPER
openssl rand -hex 32   # INTERNAL_TOKEN
```

Create `/opt/hecate/.env` (mode `0640`). Adjust placeholders to your environment:

```env
HECATE_API_IMAGE=<REGISTRY>/hecate/hecate:${VERSION}
HECATE_MCP_IMAGE=<REGISTRY>/hecate/hecate:${VERSION}
HECATE_HTTPS_PORT=<HTTPS_PORT>
HECATE_ENV=production
POSTGRES_PASSWORD=<postgres-password>
SESSION_SECRET=<session-secret>
API_KEY_PEPPER=<api-key-pepper>
INTERNAL_TOKEN=<internal-token>
WEBAUTHN_RP_ID=<FQDN>
WEBAUTHN_RP_ORIGIN=https://<FQDN>:<HTTPS_PORT>
CORS_ALLOWED_ORIGINS=https://<FQDN>:<HTTPS_PORT>
MCP_ALLOWED_HOSTS=<FQDN>,localhost,mcp
HECATE_PUBLIC_BASE_URL=https://<FQDN>:<HTTPS_PORT>
RUST_LOG=info
GITLAB_HOST=<gitlab-host>
GITLAB_PACKAGE_REGISTRY_TOKEN=<token-with-read_package_registry>
GITLAB_PACKAGE_PROJECTS=linux:x86_64:56,linux:aarch64:56,macos:x86_64:57,macos:aarch64:57,windows:x86_64:58
RELEASE_ARTIFACTS_DIR=/opt/hecate/releases
COMMAND_ARTIFACTS_DIR=/opt/hecate/command-artifacts
HECATE_REPO_URL=https://repo.hecate-mcp.com
RELEASE_SIGNING_PUBLIC_KEY_B64=kHWEtm3yvH9wV2PPb2FMB9XJ0oM68CvUXTUxzAWeGTo=
HECATE_APP_TAG=<APP_TAG>
RELEASE_SYNC_INTERVAL_SECS=900
SERVER_UPDATE_TRIGGER_PATH=/opt/hecate/run/server-update.trigger
```

```bash
sudo chmod 0640 /opt/hecate/.env
```

Notes:

- `HECATE_ENV=production` is required; the API refuses default secrets in production.
- `INTERNAL_TOKEN` is shared only between the API and MCP containers — not an operator API key.
- `GITLAB_PACKAGE_REGISTRY_TOKEN` and `RELEASE_SIGNING_PUBLIC_KEY_B64` can be left empty if you do not sync agent releases from GitLab Package Registry. Registry login passwords often lack `read_package_registry`; use a deploy token or PAT when you need release sync.
- For the official feature repo (`https://repo.hecate-mcp.com`), set `HECATE_REPO_URL` and `RELEASE_SIGNING_PUBLIC_KEY_B64=kHWEtm3yvH9wV2PPb2FMB9XJ0oM68CvUXTUxzAWeGTo=`. A wrong key causes `repository signature verification failed` when refreshing or installing features.
- `GITLAB_PACKAGE_PROJECTS` maps `os:arch:project_id` for your GitLab projects; change IDs to match your instance.

## 5. Obtain a TLS certificate

Caddy expects files under `/etc/hecate/tls/` that are copied from Let's Encrypt (or equivalent) before each start.

### Option A — Certbot + Cloudflare DNS-01 (port 80 closed)

```bash
sudo apt-get install -y certbot python3-certbot-dns-cloudflare

sudo mkdir -p /etc/letsencrypt
sudo tee /etc/letsencrypt/cloudflare.ini >/dev/null <<'EOF'
dns_cloudflare_api_token = <CLOUDFLARE_API_TOKEN>
EOF
sudo chmod 0600 /etc/letsencrypt/cloudflare.ini

sudo certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  -d <FQDN> \
  --agree-tos \
  -m admin@example.com \
  --non-interactive
```

Certificates land in `/etc/letsencrypt/live/<FQDN>/`.

### Option B — Existing PEM files

Place a full chain and private key where Certbot would:

```text
/etc/letsencrypt/live/<FQDN>/fullchain.pem
/etc/letsencrypt/live/<FQDN>/privkey.pem
```

Or adapt `prepare-caddy-tls.sh` (next section) to read from another path.

Verify the certificate subject matches your FQDN:

```bash
sudo openssl x509 -in /etc/letsencrypt/live/<FQDN>/fullchain.pem -noout -subject
```

## 6. Install helper scripts

### `/usr/local/sbin/prepare-caddy-tls.sh`

Copies Let's Encrypt material into the Caddy volume path atomically. Set `SRC_DIR` to your certificate lineage (same FQDN as Certbot):

```bash
sudo tee /usr/local/sbin/prepare-caddy-tls.sh >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail

SRC_DIR="/etc/letsencrypt/live/hecate.example.com"
DST_DIR="/etc/hecate/tls"
TMP_CERT="${DST_DIR}/cert.pem.tmp.$$"
TMP_KEY="${DST_DIR}/key.pem.tmp.$$"
OUT_CERT="${DST_DIR}/cert.pem"
OUT_KEY="${DST_DIR}/key.pem"

if [[ ! -f "${SRC_DIR}/fullchain.pem" || ! -f "${SRC_DIR}/privkey.pem" ]]; then
  echo "prepare-caddy-tls: missing fullchain.pem or privkey.pem in ${SRC_DIR}" >&2
  exit 1
fi

install -d -m 0750 "${DST_DIR}"
install -m 0644 /dev/null "${TMP_CERT}"
install -m 0600 /dev/null "${TMP_KEY}"

cat "${SRC_DIR}/fullchain.pem" > "${TMP_CERT}"
cat "${SRC_DIR}/privkey.pem" > "${TMP_KEY}"

mv -f "${TMP_CERT}" "${OUT_CERT}"
mv -f "${TMP_KEY}" "${OUT_KEY}"

chmod 0750 "${DST_DIR}"
chmod 0644 "${OUT_CERT}"
chmod 0600 "${OUT_KEY}"
EOF
sudo chmod 0750 /usr/local/sbin/prepare-caddy-tls.sh
# Edit SRC_DIR if your FQDN is not hecate.example.com:
#   sudo nano /usr/local/sbin/prepare-caddy-tls.sh
```

### `/usr/local/sbin/hecate-compose-up.sh`

Pulls images (falls back to local if the registry is unreachable), recreates containers, and prunes unused images. PostgreSQL volumes are never pruned.

```bash
sudo tee /usr/local/sbin/hecate-compose-up.sh >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail

APP_DIR="/opt/hecate"
ENV_FILE="/opt/hecate/.env"
COMPOSE_FILE="/opt/hecate/docker-compose.yml"
PROJECT="hecate"

cd "${APP_DIR}"

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

pull_or_use_local() {
  local image="$1"
  echo "hecate-compose-up: pulling ${image}" >&2
  if docker pull "${image}"; then
    return 0
  fi
  echo "hecate-compose-up: registry pull failed for ${image}" >&2
  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "hecate-compose-up: using local image ${image}" >&2
    return 0
  fi
  echo "hecate-compose-up: no local image available for ${image}" >&2
  return 1
}

IMAGES=(
  "${HECATE_API_IMAGE}"
  "${HECATE_MCP_IMAGE}"
  postgres:16-alpine
  caddy:2-alpine
)

for image in "${IMAGES[@]}"; do
  pull_or_use_local "${image}"
done

docker compose --project-name "${PROJECT}" --env-file "${ENV_FILE}" -f "${COMPOSE_FILE}" \
  up -d --remove-orphans --force-recreate --pull never

echo "hecate-compose-up: pruning unused Docker images and build cache" >&2
docker image prune -af
docker builder prune -af
EOF
sudo chmod 0750 /usr/local/sbin/hecate-compose-up.sh
```

### `/usr/local/sbin/hecate-apply-server-update.sh`

Used when an admin requests a server update from the UI (writes a trigger file once the fleet is idle):

```bash
sudo tee /usr/local/sbin/hecate-apply-server-update.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

TRIGGER="/opt/hecate/run/server-update.trigger"

if [ ! -f "${TRIGGER}" ]; then
  exit 0
fi

systemctl restart hecate.service
rm -f "${TRIGGER}"
EOF
sudo chmod 0750 /usr/local/sbin/hecate-apply-server-update.sh
```

## 7. Install systemd units

### `/etc/systemd/system/hecate.service`

```ini
[Unit]
Description=Hecate docker compose stack
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/hecate
ExecStartPre=/usr/local/sbin/prepare-caddy-tls.sh
ExecStart=/usr/local/sbin/hecate-compose-up.sh
ExecStop=/usr/bin/docker compose --project-name hecate --env-file /opt/hecate/.env -f /opt/hecate/docker-compose.yml down
TimeoutStartSec=120
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
```

### Server self-update watcher

`/etc/systemd/system/hecate-update.path`:

```ini
[Unit]
Description=Watch for Hecate server update trigger
After=hecate.service

[Path]
PathExists=/opt/hecate/run/server-update.trigger
PathChanged=/opt/hecate/run/server-update.trigger
Unit=hecate-update.service

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/hecate-update.service`:

```ini
[Unit]
Description=Apply pending Hecate server update
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hecate-apply-server-update.sh
```

`/etc/systemd/system/hecate-update-check.service`:

```ini
[Unit]
Description=Apply pending Hecate server update when trigger file exists
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/hecate-apply-server-update.sh
```

`/etc/systemd/system/hecate-update.timer`:

```ini
[Unit]
Description=Poll for Hecate server update trigger file

[Timer]
OnBootSec=1min
OnUnitActiveSec=10s
AccuracySec=1s
Unit=hecate-update-check.service

[Install]
WantedBy=timers.target
```

Enable units:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hecate.service
sudo systemctl enable --now hecate-update.path
sudo systemctl enable --now hecate-update.timer
```

## 8. TLS renew hook

After Certbot renews, refresh runtime TLS files and restart the stack:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/hecate-reload.sh >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail
/usr/local/sbin/prepare-caddy-tls.sh
systemctl restart hecate.service
EOF
sudo chmod 0750 /etc/letsencrypt/renewal-hooks/deploy/hecate-reload.sh
```

Certbot's system timer handles renewal; the hook restarts `hecate.service` so Caddy picks up the new certs.

## 9. Start and verify

```bash
sudo /usr/local/sbin/prepare-caddy-tls.sh
sudo systemctl restart hecate.service
sudo systemctl status hecate.service
sudo docker compose --project-name hecate --env-file /opt/hecate/.env \
  -f /opt/hecate/docker-compose.yml ps
```

Checks:

```bash
# UI / API
curl -fsS "https://<FQDN>:<HTTPS_PORT>/api/v1/system/version"

# MCP without API key should return 401
curl -sS -X POST "https://<FQDN>:<HTTPS_PORT>/mcp" \
  -H 'Content-Type: application/json' -d '{}'
```

Open `https://<FQDN>:<HTTPS_PORT>/` for the operator UI. MCP clients (Cursor, Claude, Hermes): [mcp-clients.md](mcp-clients.md).

## Day-2 operations

### Pull newer images

Restarting the service pulls configured tags and recreates containers:

```bash
sudo systemctl restart hecate.service
```

To pin a release, set `HECATE_APP_TAG` / image tags in `/opt/hecate/.env`, then restart.

### Database

Migrations run automatically when the API container starts. Before major upgrades, take a Postgres volume snapshot or logical dump. See [backup-migration.md](backup-migration.md).

### Secrets rotation

Rotate `SESSION_SECRET` and `API_KEY_PEPPER` independently. Changing `API_KEY_PEPPER` invalidates existing API key hashes — plan a re-issue. Changing `INTERNAL_TOKEN` requires both API and MCP to restart together (compose restart does this).

## Troubleshooting

### `prepare-caddy-tls: missing fullchain.pem or privkey.pem`

Issue or place certificates under `/etc/letsencrypt/live/<FQDN>/` before starting `hecate.service`.

```bash
sudo ls -la /etc/letsencrypt/live/<FQDN>/
sudo certbot certificates
```

### Wrong certificate hostname

```bash
sudo openssl x509 -in /etc/letsencrypt/live/<FQDN>/fullchain.pem -noout -subject
```

If another stack's cert was copied into `/etc/hecate/tls/`:

```bash
sudo rm -f /etc/hecate/tls/{cert.pem,key.pem,bundle.pem}
sudo /usr/local/sbin/prepare-caddy-tls.sh
sudo systemctl restart hecate.service
```

### Registry pull failures

`hecate-compose-up.sh` falls back to a local image if `docker pull` fails. Confirm `docker login` and that `HECATE_API_IMAGE` / `HECATE_MCP_IMAGE` match published tags.

### Containers not listening publicly on MCP

By design: MCP has no published host port. Only Caddy on `<HTTPS_PORT>` is exposed. Prefer private network or edge auth for MCP; see [SECURITY_NOTES.md](SECURITY_NOTES.md) and [mcp-clients.md](mcp-clients.md).

## Layout on the host

```text
/opt/hecate/
  docker-compose.yml
  Caddyfile
  .env
  releases/              # agent release artifacts (uid 1000)
  command-artifacts/     # command upload/download artifacts (uid 1000)
  run/                   # server-update.trigger (uid 1000)
/etc/hecate/tls/          # runtime cert.pem + key.pem for Caddy
/etc/letsencrypt/live/<FQDN>/
/usr/local/sbin/prepare-caddy-tls.sh
/usr/local/sbin/hecate-compose-up.sh
/usr/local/sbin/hecate-apply-server-update.sh
/etc/systemd/system/hecate.service
/etc/systemd/system/hecate-update.{path,service,timer}
/etc/systemd/system/hecate-update-check.service
```
