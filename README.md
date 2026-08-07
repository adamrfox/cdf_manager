# CDF Manager

A web-based management tool for Qumulo Cloud Data Fabric (CDF) portal relationships. CDF Manager allows you to monitor spoke cluster capacity, manage hub and spoke cluster credentials, create and delete portal relationships, and browse the spoke filesystem with cache visibility — all from a single browser interface.

---

## Features

- **Multi-role access control** — admin, portal_manager, and monitor roles
- **Spoke monitoring** — capacity, usage, and portal relationship status
- **Hub monitoring** — connected spokes and portal health
- **Portal management** — create and delete portal relationships between hub and spoke clusters
- **File browser** — browse spoke filesystems with per-file cache percentage and cached data size
- **Long-lived Qumulo tokens** — uses `/v1/auth/access-tokens/` for persistent authentication (30-day default)
- **Session persistence** — browser sessions survive page refreshes
- **Admin settings** — configurable refresh interval, token expiry, and browser display options

---

## Architecture

```
Browser → nginx (port 3000) → proxy.py (port 8081) → Qumulo clusters (port 8000)
```

- **`cdf-manager.html`** — single-page frontend (HTML/CSS/JS, no build step)
- **`proxy.py`** — Python 3 backend (stdlib only, no pip dependencies)
- **`config.py`** — admin account and runtime settings
- **`state.json`** — per-user spoke/hub/token state (auto-created)
- **`users.json`** — additional users created via the UI (auto-created)
- **`sessions.json`** — active login sessions (auto-created)
- **`settings.json`** — admin-configured settings (auto-created)

---

## Requirements

- Python 3.8+
- nginx
- A Linux server with network access to your Qumulo clusters on **port 8000** (Qumulo REST API)
- Port 3713 (replication) must be open **between hub and spoke Qumulo clusters** — CDF Manager itself does not use this port

Alternatively, skip the Python/nginx setup entirely and run the [Docker image](#docker-deployment) — it only needs Docker.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/adamrfox/cdf_manager.git
cd cdf_manager
```

### 2. Configure the admin account

Edit `config.py` and set a strong admin password:

```python
import hashlib

ADMIN_USERNAME      = "admin"
ADMIN_PASSWORD_HASH = hashlib.sha256("your_password_here".encode()).hexdigest()

APP_SESSION_EXPIRY_SECONDS = 8 * 60 * 60   # 8 hours
QUMULO_TOKEN_EXPIRY_DAYS   = 30

STATE_FILE    = "state.json"
USERS_FILE    = "users.json"
SESSIONS_FILE = "sessions.json"
SETTINGS_FILE = "settings.json"

PROXY_PORT = 8081
```

To generate a password hash:
```bash
python3 -c "import hashlib; print(hashlib.sha256('yourpassword'.encode()).hexdigest())"
```

### 3. Deploy files

```bash
sudo mkdir -p /var/www/cdf_manager
sudo cp proxy.py config.py cdf-manager.html /var/www/cdf_manager/

# nginx's static root below points at this subdirectory, not the app
# directory itself — proxy.py, config.py, and the runtime state files
# (which hold Qumulo access tokens and session tokens!) must never be
# reachable by direct URL. The symlink keeps cdf-manager.html itself as
# the single source of truth — no separate copy to keep in sync.
sudo mkdir -p /var/www/cdf_manager/static
sudo ln -s ../cdf-manager.html /var/www/cdf_manager/static/cdf-manager.html

sudo chown -R www-data:www-data /var/www/cdf_manager
sudo chmod 755 /var/www/cdf_manager
sudo chmod 644 /var/www/cdf_manager/*.py /var/www/cdf_manager/*.html
```

### 4. Configure nginx

Create `/etc/nginx/sites-enabled/cdf-manager`:

```nginx
server {
    listen 3000;

    location /app/ {
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Origin  "*" always;
            add_header Access-Control-Allow-Methods "GET, POST, PATCH, DELETE, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
            return 204;
        }
        proxy_pass         http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header   Host            $host;
        proxy_set_header   X-Real-IP       $remote_addr;
        proxy_read_timeout 30s;
        add_header Access-Control-Allow-Origin  "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, PATCH, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
    }

    location /proxy {
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Origin  "*" always;
            add_header Access-Control-Allow-Methods "POST, GET, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
            return 204;
        }
        proxy_pass         http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header   Host            $host;
        proxy_read_timeout 30s;
        add_header Access-Control-Allow-Origin  "*" always;
        add_header Access-Control-Allow-Methods "POST, GET, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
    }

    location /health {
        proxy_pass http://127.0.0.1:8081/health;
    }

    location / {
        root /var/www/cdf_manager/static;   # only cdf-manager.html lives here — see step 3
        index cdf-manager.html;
        try_files $uri $uri/ =404;
    }
}
```

> **Security note:** an earlier version of this README (and of the geonosis
> deployment) pointed `root` directly at `/var/www/cdf_manager`, which made
> `proxy.py`, `config.py`, and the runtime state files — `state.json` in
> particular, which holds live Qumulo access tokens — fetchable by anyone
> who could reach the port, e.g. `GET /state.json`. If you deployed from an
> older copy of this doc, check `curl http://your-server:3000/state.json`
> and fix your nginx config's `root` if it returns anything but a 404.

Test and reload nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 5. Install the systemd service

Create `/etc/systemd/system/cdf-manager.service`:

```ini
[Unit]
Description=CDF Manager Proxy
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/cdf_manager
ExecStart=/usr/bin/python3 /var/www/cdf_manager/proxy.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable cdf-manager
sudo systemctl start cdf-manager
sudo systemctl status cdf-manager
```

### 6. Access the application

Open a browser and navigate to:
```
http://your-server:3000/cdf-manager.html
```

Log in with the admin credentials you configured in `config.py`.

---

## Docker Deployment

A single container runs nginx and proxy.py together, as an alternative to
the manual install above — no host nginx or systemd setup required.

> **This is how geonosis is deployed** (as of the 2026-08-07 cutover from
> the old bare-metal systemd service): container name `cdf-manager`, data
> volume `/var/www/cdf-manager-data`, published on host port 3000. The
> host's own nginx no longer has a server block for this app — the
> container's own nginx owns port 3000 directly. See
> [Updating](#updating) for the exact redeploy command.

### 1. Build the image

```bash
git clone https://github.com/adamrfox/cdf_manager.git
cd cdf_manager
docker build -t cdf-manager .
```

### 2. Run it

```bash
mkdir -p /var/www/cdf-manager-data
docker run -d --name cdf-manager \
  --restart unless-stopped \
  -p 3000:80 \
  -e ADMIN_PASSWORD=your_password_here \
  -v /var/www/cdf-manager-data:/data \
  cdf-manager
```

Bind-mount a real host directory to `/data` — it holds `config.py`
(generated from the env vars below on first boot) and the app's runtime
state (`state.json`, `users.json`, `sessions.json`, `settings.json`), all
of which need to survive container recreation and image upgrades.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `ADMIN_USERNAME` | `admin` | Built-in admin account username |
| `ADMIN_PASSWORD` | — | Plaintext admin password, hashed on first boot. Required unless `ADMIN_PASSWORD_HASH` is set. |
| `ADMIN_PASSWORD_HASH` | — | Pre-computed SHA-256 hash (`python3 -c "import hashlib; print(hashlib.sha256(b'...').hexdigest())"`) — takes precedence over `ADMIN_PASSWORD` if both are set |
| `APP_SESSION_EXPIRY_SECONDS` | `28800` (8h) | App login session lifetime |
| `QUMULO_TOKEN_EXPIRY_DAYS` | `30` | Qumulo access token lifetime |

These are only read on the **first boot**, when `/data/config.py` doesn't
exist yet. After that the container leaves `config.py` alone — this is
intentional: changing the admin password through the UI rewrites
`config.py` in place, and that change needs to survive the next container
restart rather than being silently reverted by the original env var. To
reset the admin password, delete `config.py` from the mounted `/data`
directory and restart the container (or edit `ADMIN_PASSWORD_HASH` in
`/data/config.py` directly, same as the bare-metal
[Reset admin password](#reset-admin-password) instructions).

### Access the application

```
http://your-docker-host:3000/
```

### Updating

```bash
git pull
docker build -t cdf-manager .
docker stop cdf-manager && docker rm cdf-manager
docker run -d --name cdf-manager --restart unless-stopped -p 3000:80 \
  -v /var/www/cdf-manager-data:/data cdf-manager
```
No env vars needed on subsequent runs — `config.py` already exists in `/data`.

### Logs and health

```bash
docker logs -f cdf-manager
docker inspect --format='{{.State.Health.Status}}' cdf-manager
curl http://localhost:3000/health
```

---

## User Roles

| Capability | monitor | portal_manager | admin |
|---|---|---|---|
| View spokes, hubs, portals | ✓ | ✓ | ✓ |
| Add / remove spoke clusters | ✓ | ✓ | ✓ |
| Add / remove hub clusters | ✓ | ✓ | ✓ |
| Browse spoke filesystem | ✓ | ✓ | ✓ |
| Create / delete portal relationships | — | ✓ | ✓ |
| Manage users and roles | — | — | ✓ |
| Change settings | — | — | ✓ |

---

## First-Time Setup

### Add a spoke cluster

1. Go to the **Spokes** tab and click **+ ADD SPOKE**
2. Enter a display name and the cluster's IP address
3. Click **ADD SPOKE** — the authentication dialog opens automatically
4. Enter Qumulo credentials (admin or any user with API access)
5. A 30-day access token is stored — credentials are never saved

### Add a hub cluster

1. Go to the **Hubs** tab and click **+ ADD HUB**
2. Enter a display name and the cluster's IP address
3. Authenticate with Qumulo credentials

Hubs are also auto-discovered when a spoke with existing portal relationships is authenticated — they appear on the Hubs tab ready for credential entry.

### Create a portal relationship

1. Ensure both the hub and spoke clusters are added and authenticated
2. Go to the **Portals** tab and click **+ CREATE PORTAL**
3. Select (or add inline) the hub and spoke clusters
4. Enter the hub root path and spoke root path
5. Optionally adjust the portal type and replication port (default: 3713)
6. Click **CREATE PORTAL** — the app performs the full 4-step creation and authorization automatically

### Browse a spoke filesystem

1. Go to the **Browser** tab
2. Select an authenticated spoke and a portal root path
3. Navigate directories by clicking folders; use the breadcrumb to go back
4. Files show: size, cache percentage, and cached data amount
5. Files outside any portal root are marked **NON-PORTAL** and cache stats are not shown

---

## Admin Settings

Access via the **⚙ SETTINGS** button (admin only):

| Setting | Default | Description |
|---|---|---|
| Refresh interval | 30s | How often spoke/hub data refreshes automatically |
| Token expiry | 30 days | How long Qumulo access tokens are valid |
| Hide non-portal files | Off | Hide local filesystem files in the browser |

---

## Monitoring

View logs:
```bash
sudo journalctl -u cdf-manager -f
```

Health check:
```bash
curl http://localhost:3000/health
```

---

## Data Files

These files are created automatically in `/var/www/cdf_manager/` and should **not** be committed to version control:

| File | Contents |
|---|---|
| `state.json` | Per-user spoke/hub configurations and Qumulo tokens |
| `users.json` | Non-admin users created via the UI |
| `sessions.json` | Active login sessions |
| `settings.json` | Admin-configured application settings |

Add to `.gitignore`:
```
state.json
users.json
sessions.json
settings.json
*.bak
```

---

## Security Notes

- Qumulo credentials are **never stored** — only the resulting access tokens
- Access tokens are stored in `state.json` with a configurable expiry (default 30 days)
- App session tokens are stored in `sessions.json` and expire after 8 hours
- SSL verification is disabled for Qumulo API calls to support self-signed certificates
- The admin password is stored as a SHA-256 hash in `config.py`
- It is recommended to run behind a VPN or restrict access to trusted networks

---

## Troubleshooting

**502 Bad Gateway** — proxy.py is not running:
```bash
sudo systemctl status cdf-manager
sudo journalctl -u cdf-manager -n 20
```

**401 on cluster calls** — Qumulo token has expired, click **🔑 RE-AUTH** on the affected card.

**Too many access tokens error** — the proxy automatically cleans up old tokens before creating new ones. If this persists, manually delete tokens:
```bash
TOKEN=$(curl -sk -X POST https://CLUSTER:8000/v1/session/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"PASSWORD"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['bearer_token'])")

curl -sk https://CLUSTER:8000/v1/auth/access-tokens/ -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
curl -sk -X DELETE https://CLUSTER:8000/v1/auth/access-tokens/TOKEN_ID -H "Authorization: Bearer $TOKEN"
```

**Portal stays PENDING** — ensure TCP port 3713 is open **between the hub and spoke Qumulo clusters** in both directions. CDF Manager itself does not need access to port 3713.

**403 on page load** — check file permissions:
```bash
sudo chown -R www-data:www-data /var/www/cdf_manager
```

### Reset admin password

```bash
python3 -c "import hashlib; print(hashlib.sha256('newpassword'.encode()).hexdigest())"
```
Bare metal — edit `ADMIN_PASSWORD_HASH` in `/var/www/cdf_manager/config.py`, then `sudo systemctl restart cdf-manager`.
Docker — edit `ADMIN_PASSWORD_HASH` in `config.py` inside the mounted `/data` volume, then `docker restart cdf-manager`.
