#!/usr/bin/env python3
"""
proxy.py — CDF Manager proxy + API server
------------------------------------------
Roles:
  admin          — full access: user mgmt, role assignment, portal ops, spoke ops
  portal_manager — hub + spoke mgmt, create/delete portal relationships
  monitor        — spoke mgmt, view-only portal data

Endpoints:
  POST   /app/login                      — log in
  POST   /app/logout                     — log out
  GET    /app/me                         — current user info

  GET    /app/spokes                     — list user's spokes
  POST   /app/spokes                     — add a spoke
  DELETE /app/spokes/{id}                — remove a spoke
  POST   /app/spokes/{id}/auth           — authenticate spoke

  GET    /app/hubs                       — list user's hubs       [portal_manager+]
  POST   /app/hubs                       — add a hub              [portal_manager+]
  DELETE /app/hubs/{id}                  — remove a hub           [portal_manager+]
  POST   /app/hubs/{id}/auth             — authenticate hub       [portal_manager+]

  GET    /app/portals/{spoke_id}         — list portals on a spoke
  POST   /app/portals                    — create portal relationship [portal_manager+]
  DELETE /app/portals/{spoke_id}/{pid}   — delete portal relationship [portal_manager+]

  GET    /app/users                      — list users             [admin]
  POST   /app/users                      — create user            [admin]
  PATCH  /app/users/{username}           — update role            [admin]
  DELETE /app/users/{username}           — delete user            [admin]

  POST   /proxy                          — proxy Qumulo API call
  GET    /health                         — health check
"""

import json, sys, os, ssl, uuid, hashlib, secrets
import urllib.request, urllib.error, http.server
from datetime import datetime, timedelta, timezone

# ── Load config ────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import config
    ADMIN_USERNAME           = config.ADMIN_USERNAME
    ADMIN_PASSWORD_HASH      = config.ADMIN_PASSWORD_HASH
    APP_SESSION_EXPIRY       = config.APP_SESSION_EXPIRY_SECONDS
    QUMULO_TOKEN_EXPIRY_DAYS = config.QUMULO_TOKEN_EXPIRY_DAYS
    STATE_FILE               = config.STATE_FILE
    USERS_FILE               = config.USERS_FILE
    PORT                     = config.PROXY_PORT
except ImportError:
    print("WARNING: config.py not found, using defaults")
    ADMIN_USERNAME           = "admin"
    ADMIN_PASSWORD_HASH      = hashlib.sha256("admin".encode()).hexdigest()
    APP_SESSION_EXPIRY       = 8 * 3600
    QUMULO_TOKEN_EXPIRY_DAYS = 30
    STATE_FILE               = "state.json"
    USERS_FILE               = "users.json"
    PORT                     = 8081

ROLES = ("monitor", "portal_manager")

# ── SSL context ────────────────────────────────────────────────────────
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

# ── Sessions ───────────────────────────────────────────────────────────
sessions = {}

# ── User store ─────────────────────────────────────────────────────────
def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                return json.load(f)
        except Exception as e:
            print(f"  WARNING: Could not load users: {e}")
    return {}

def save_users(users):
    to_save = {k: v for k, v in users.items() if k != ADMIN_USERNAME}
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(to_save, f, indent=2)
    except Exception as e:
        print(f"  WARNING: Could not save users: {e}")

def get_all_users():
    users = load_users()
    users[ADMIN_USERNAME] = {
        "password_hash": ADMIN_PASSWORD_HASH,
        "role":          "admin",
        "created":       "built-in",
    }
    return users

def check_password(username, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    u = get_all_users().get(username)
    return u and u["password_hash"] == hashed

def get_role(username):
    if username == ADMIN_USERNAME:
        return "admin"
    u = load_users().get(username, {})
    return u.get("role", "monitor")

def is_admin(username):
    return username == ADMIN_USERNAME

def can_manage_portals(username):
    return get_role(username) in ("admin", "portal_manager")

# ── State persistence ──────────────────────────────────────────────────
# state.json structure:
# {
#   "username": {
#     "spokes": { "id": { id, name, host, added, token, token_expires } },
#     "hubs":   { "id": { id, name, host, added, token, token_expires } }
#   }
# }

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception as e:
            print(f"  WARNING: Could not load state: {e}")
    return {}

def save_state(state):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        print(f"  WARNING: Could not save state: {e}")

app_state = load_state()

def get_user_state(username):
    if username not in app_state:
        app_state[username] = {"spokes": {}, "hubs": {}}
    # migrate old entries that lack hubs key
    if "hubs" not in app_state[username]:
        app_state[username]["hubs"] = {}
    return app_state[username]

# ── Session helpers ────────────────────────────────────────────────────
def create_session(username):
    token   = secrets.token_hex(32)
    expires = datetime.now(timezone.utc) + timedelta(seconds=APP_SESSION_EXPIRY)
    sessions[token] = {"username": username, "expires": expires.isoformat()}
    return token, expires.isoformat()

def validate_session(token):
    if not token or token not in sessions:
        return None
    s = sessions[token]
    if datetime.fromisoformat(s["expires"]) < datetime.now(timezone.utc):
        del sessions[token]
        return None
    return s["username"]

def get_bearer(headers):
    auth = headers.get("Authorization", "")
    return auth[7:] if auth.startswith("Bearer ") else None

# ── Token expiry helpers ───────────────────────────────────────────────
def make_expiry():
    return (datetime.now(timezone.utc) + timedelta(days=QUMULO_TOKEN_EXPIRY_DAYS)).isoformat()

def is_expired(iso_str):
    if not iso_str:
        return True
    try:
        return datetime.fromisoformat(iso_str) < datetime.now(timezone.utc)
    except Exception:
        return True

def cluster_summary(cid, c):
    return {
        "id":            cid,
        "name":          c.get("name", cid),
        "host":          c.get("host", ""),
        "added":         c.get("added", ""),
        "has_token":     bool(c.get("token")),
        "token_expires": c.get("token_expires"),
        "token_expired": is_expired(c.get("token_expires")) if c.get("token") else True,
    }

# ── Qumulo API forwarding ──────────────────────────────────────────────
def qumulo_request(host, path, method, token, body):
    if ":" not in host:
        host = host + ":8000"
    url     = f"https://{host}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    print(f"  --> {method} https://{host}{path}")
    if token:  print(f"      Auth: Bearer {token[:12]}...")
    else:       print(f"      Auth: NONE")
    if body:
        safe = {k: ("***" if k == "password" else v) for k, v in (body.items() if isinstance(body, dict) else {})}
        print(f"      Body: {json.dumps(safe)}")

    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
            raw = resp.read()
            print(f"  <-- {resp.status} OK")
            try:    return resp.status, json.loads(raw)
            except: return resp.status, {"__raw": raw.decode(errors="replace")}
    except urllib.error.HTTPError as e:
        raw = e.read()
        print(f"  <-- {e.code} ERROR")
        try:    err_body = json.loads(raw)
        except: err_body = {"__raw": raw.decode(errors="replace")}
        print(f"      Response: {json.dumps(err_body)}")
        err_body["status"] = e.code
        return e.code, err_body
    except urllib.error.URLError as e:
        print(f"  <-- NETWORK ERROR: {e.reason}")
        return 502, {"__proxy_error": str(e.reason), "status": 502}
    except Exception as e:
        print(f"  <-- EXCEPTION: {e}")
        return 500, {"__proxy_error": str(e), "status": 500}

def get_cluster_token(username, cluster_type, cluster_id):
    """Retrieve stored token for a spoke or hub, checking expiry."""
    user    = get_user_state(username)
    store   = user["spokes"] if cluster_type == "spoke" else user["hubs"]
    cluster = store.get(cluster_id)
    if not cluster:
        return None, f"{cluster_type.capitalize()} {cluster_id} not found"
    token = cluster.get("token")
    if not token:
        return None, f"{cluster_type.capitalize()} has no token — authenticate first"
    if is_expired(cluster.get("token_expires")):
        return None, f"{cluster_type.capitalize()} token expired — re-authenticate"
    return token, None

# ── HTTP Handler ───────────────────────────────────────────────────────
class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args): pass

    def send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type",                 "application/json")
        self.send_header("Content-Length",               str(len(body)))
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if not length: return {}
        try:    return json.loads(self.rfile.read(length))
        except: return {}

    def require_session(self):
        token    = get_bearer(self.headers)
        username = validate_session(token)
        if not username:
            self.send_json(401, {"error": "Invalid or expired session. Please log in again."})
        return username

    def require_admin(self):
        username = self.require_session()
        if username and not is_admin(username):
            self.send_json(403, {"error": "Admin access required."})
            return None
        return username

    def require_portal_manager(self):
        username = self.require_session()
        if username and not can_manage_portals(username):
            self.send_json(403, {"error": "Portal Manager role required."})
            return None
        return username

    def auth_cluster(self, username, host, qu_user, qu_pass):
        """Authenticate to a Qumulo cluster and return (token, expires, error)."""
        status, data = qumulo_request(host, "/v1/session/login", "POST", None,
                                      {"username": qu_user, "password": qu_pass})
        if status != 200:
            desc = data.get("description") or data.get("__raw") or "Authentication failed"
            return None, None, f"Qumulo auth failed: {desc}"
        token = data.get("bearer_token") or data.get("key") or data.get("token")
        if not token:
            return None, None, f"No token in response: {json.dumps(data)}"
        return token, make_expiry(), None

    # ── GET ────────────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/health":
            self.send_json(200, {"status": "ok", "app": "CDF Manager"})
            return

        # Current user info
        if path == "/app/me":
            username = self.require_session()
            if not username: return
            self.send_json(200, {
                "username": username,
                "role":     get_role(username),
                "is_admin": is_admin(username),
                "can_manage_portals": can_manage_portals(username),
            })
            return

        # List spokes
        if path == "/app/spokes":
            username = self.require_session()
            if not username: return
            user = get_user_state(username)
            self.send_json(200, {"spokes": [cluster_summary(k, v) for k, v in user["spokes"].items()]})
            return

        # List hubs
        if path == "/app/hubs":
            username = self.require_portal_manager()
            if not username: return
            user = get_user_state(username)
            self.send_json(200, {"hubs": [cluster_summary(k, v) for k, v in user["hubs"].items()]})
            return

        # List portal relationships on a spoke
        if path.startswith("/app/portals/"):
            username = self.require_session()
            if not username: return
            spoke_id = path.split("/")[3]
            user     = get_user_state(username)
            spoke    = user["spokes"].get(spoke_id)
            if not spoke:
                self.send_json(404, {"error": "Spoke not found"})
                return
            token, err = get_cluster_token(username, "spoke", spoke_id)
            if err:
                self.send_json(401, {"error": err})
                return
            # Fetch from both portal endpoints
            s1, spokes_data = qumulo_request(spoke["host"], "/v1/portal/spokes/",       "GET", token, None)
            s2, fs_data     = qumulo_request(spoke["host"], "/v1/portal/file-systems/", "GET", token, None)
            self.send_json(200, {
                "spokes":       spokes_data if s1 < 400 else {"error": spokes_data},
                "file_systems": fs_data     if s2 < 400 else {"error": fs_data},
            })
            return

        # List users (admin only)
        if path == "/app/users":
            username = self.require_admin()
            if not username: return
            result = []
            for uname, udata in get_all_users().items():
                result.append({
                    "username": uname,
                    "role":     udata.get("role", "monitor"),
                    "created":  udata.get("created", "—"),
                    "is_admin": uname == ADMIN_USERNAME,
                    "built_in": uname == ADMIN_USERNAME,
                })
            self.send_json(200, {"users": result})
            return

        self.send_json(404, {"error": "Not found"})

    # ── POST ───────────────────────────────────────────────────────────
    def do_POST(self):
        path    = self.path.split("?")[0]
        payload = self.read_json()
        print(f"\n[{self.client_address[0]}] POST {path}")

        # Login
        if path == "/app/login":
            username = payload.get("username", "")
            password = payload.get("password", "")
            if not check_password(username, password):
                self.send_json(401, {"error": "Invalid username or password."})
                return
            token, expires = create_session(username)
            role = get_role(username)
            print(f"  Login: {username} ({role})")
            self.send_json(200, {
                "session_token":      token,
                "expires":            expires,
                "username":           username,
                "role":               role,
                "is_admin":           is_admin(username),
                "can_manage_portals": can_manage_portals(username),
            })
            return

        # Logout
        if path == "/app/logout":
            token = get_bearer(self.headers)
            if token and token in sessions:
                del sessions[token]
            self.send_json(200, {"ok": True})
            return

        # Create user (admin only)
        if path == "/app/users":
            username = self.require_admin()
            if not username: return
            new_user = payload.get("username", "").strip()
            password = payload.get("password", "")
            role     = payload.get("role", "monitor")
            if not new_user or not password:
                self.send_json(400, {"error": "username and password are required."})
                return
            if role not in ROLES:
                self.send_json(400, {"error": f"role must be one of: {', '.join(ROLES)}"})
                return
            if new_user == ADMIN_USERNAME:
                self.send_json(400, {"error": "Cannot create a user with the admin username."})
                return
            users = load_users()
            if new_user in users:
                self.send_json(409, {"error": f"User '{new_user}' already exists."})
                return
            users[new_user] = {
                "password_hash": hashlib.sha256(password.encode()).hexdigest(),
                "role":          role,
                "created":       datetime.now(timezone.utc).isoformat(),
            }
            save_users(users)
            print(f"  Created user: {new_user} role={role} (by {username})")
            self.send_json(200, {"ok": True, "username": new_user, "role": role})
            return

        # Add a spoke
        if path == "/app/spokes":
            username = self.require_session()
            if not username: return
            host = payload.get("host", "").strip()
            name = payload.get("name", "").strip() or host
            if not host:
                self.send_json(400, {"error": "host is required"})
                return
            user = get_user_state(username)
            sid  = str(uuid.uuid4())[:8]
            user["spokes"][sid] = {
                "id": sid, "name": name, "host": host,
                "added": datetime.now(timezone.utc).isoformat(),
                "token": None, "token_expires": None,
            }
            save_state(app_state)
            print(f"  Added spoke: {name} ({host}) for {username}")
            self.send_json(200, {"id": sid, "name": name, "host": host})
            return

        # Authenticate a spoke
        if path.startswith("/app/spokes/") and path.endswith("/auth"):
            username = self.require_session()
            if not username: return
            sid  = path.split("/")[3]
            user = get_user_state(username)
            if sid not in user["spokes"]:
                self.send_json(404, {"error": "Spoke not found"})
                return
            spoke = user["spokes"][sid]
            token, expires, err = self.auth_cluster(username, spoke["host"],
                                                    payload.get("username", ""),
                                                    payload.get("password", ""))
            if err:
                self.send_json(401, {"error": err})
                return
            spoke["token"] = token; spoke["token_expires"] = expires
            save_state(app_state)
            print(f"  Spoke {sid} authenticated, expires {expires}")
            self.send_json(200, {"ok": True, "token_expires": expires})
            return

        # Add a hub
        if path == "/app/hubs":
            username = self.require_portal_manager()
            if not username: return
            host = payload.get("host", "").strip()
            name = payload.get("name", "").strip() or host
            if not host:
                self.send_json(400, {"error": "host is required"})
                return
            user = get_user_state(username)
            hid  = str(uuid.uuid4())[:8]
            user["hubs"][hid] = {
                "id": hid, "name": name, "host": host,
                "added": datetime.now(timezone.utc).isoformat(),
                "token": None, "token_expires": None,
            }
            save_state(app_state)
            print(f"  Added hub: {name} ({host}) for {username}")
            self.send_json(200, {"id": hid, "name": name, "host": host})
            return

        # Authenticate a hub
        if path.startswith("/app/hubs/") and path.endswith("/auth"):
            username = self.require_portal_manager()
            if not username: return
            hid  = path.split("/")[3]
            user = get_user_state(username)
            if hid not in user["hubs"]:
                self.send_json(404, {"error": "Hub not found"})
                return
            hub = user["hubs"][hid]
            token, expires, err = self.auth_cluster(username, hub["host"],
                                                    payload.get("username", ""),
                                                    payload.get("password", ""))
            if err:
                self.send_json(401, {"error": err})
                return
            hub["token"] = token; hub["token_expires"] = expires
            save_state(app_state)
            print(f"  Hub {hid} authenticated, expires {expires}")
            self.send_json(200, {"ok": True, "token_expires": expires})
            return

        # Create a portal relationship
        if path == "/app/portals":
            username = self.require_portal_manager()
            if not username: return

            spoke_id    = payload.get("spoke_id", "")
            hub_id      = payload.get("hub_id", "")
            spoke_root  = payload.get("spoke_root", "")
            hub_root    = payload.get("hub_root", "")

            if not all([spoke_id, hub_id, spoke_root, hub_root]):
                self.send_json(400, {"error": "spoke_id, hub_id, spoke_root, and hub_root are required"})
                return

            user = get_user_state(username)
            spoke = user["spokes"].get(spoke_id)
            hub   = user["hubs"].get(hub_id)
            if not spoke: self.send_json(404, {"error": "Spoke not found"}); return
            if not hub:   self.send_json(404, {"error": "Hub not found"});   return

            spoke_token, err = get_cluster_token(username, "spoke", spoke_id)
            if err: self.send_json(401, {"error": f"Spoke: {err}"}); return
            hub_token, err = get_cluster_token(username, "hub", hub_id)
            if err: self.send_json(401, {"error": f"Hub: {err}"}); return

            # Step 1: get hub cluster info to obtain hub_id UUID
            s1, hub_info = qumulo_request(hub["host"], "/v1/cluster/settings", "GET", hub_token, None)
            if s1 >= 400:
                self.send_json(s1, {"error": "Could not fetch hub cluster info", "detail": hub_info})
                return
            hub_cluster_id = hub_info.get("cluster_id") or hub_info.get("guid") or hub_info.get("id")

            # Step 2: create the spoke relationship on the spoke cluster
            spoke_body = {
                "spoke_root":       spoke_root,
                "hub_address":      hub["host"].split(":")[0],
                "hub_port":         int(hub["host"].split(":")[1]) if ":" in hub["host"] else 8000,
                "hub_root":         hub_root,
            }
            s2, result = qumulo_request(spoke["host"], "/v2/portal/spokes/", "POST", spoke_token, spoke_body)
            if s2 >= 400:
                self.send_json(s2, {"error": "Failed to create portal relationship", "detail": result})
                return

            print(f"  Portal created: spoke {spoke_id} -> hub {hub_id}")
            self.send_json(200, {"ok": True, "portal": result})
            return

        # Proxy a Qumulo API call
        if path == "/proxy":
            username = self.require_session()
            if not username: return
            host         = payload.get("host", "")
            api_path     = payload.get("path", "")
            method       = payload.get("method", "GET").upper()
            spoke_id     = payload.get("spoke_id", "")
            hub_id       = payload.get("hub_id", "")
            body         = payload.get("body", None)
            token        = payload.get("token", "")

            if not host or not api_path:
                self.send_json(400, {"__proxy_error": "Missing host or path"})
                return

            if spoke_id:
                token, err = get_cluster_token(username, "spoke", spoke_id)
                if err: self.send_json(401, {"__proxy_error": err}); return
            elif hub_id:
                token, err = get_cluster_token(username, "hub", hub_id)
                if err: self.send_json(401, {"__proxy_error": err}); return

            status, result = qumulo_request(host, api_path, method, token, body)
            self.send_json(200 if status < 400 else status, result)
            return

        self.send_json(404, {"error": "Not found"})

    # ── PATCH ──────────────────────────────────────────────────────────
    def do_PATCH(self):
        path    = self.path.split("?")[0]
        payload = self.read_json()
        print(f"\n[{self.client_address[0]}] PATCH {path}")

        # Update user role (admin only)
        if path.startswith("/app/users/"):
            admin = self.require_admin()
            if not admin: return
            target = path.split("/")[3]
            if target == ADMIN_USERNAME:
                self.send_json(400, {"error": "Cannot change the built-in admin's role."})
                return
            new_role = payload.get("role", "")
            if new_role not in ROLES:
                self.send_json(400, {"error": f"role must be one of: {', '.join(ROLES)}"})
                return
            users = load_users()
            if target not in users:
                self.send_json(404, {"error": f"User '{target}' not found."})
                return
            users[target]["role"] = new_role
            save_users(users)
            print(f"  Updated {target} role -> {new_role} (by {admin})")
            self.send_json(200, {"ok": True, "username": target, "role": new_role})
            return

        self.send_json(404, {"error": "Not found"})

    # ── DELETE ─────────────────────────────────────────────────────────
    def do_DELETE(self):
        path = self.path.split("?")[0]
        print(f"\n[{self.client_address[0]}] DELETE {path}")

        # Delete spoke
        if path.startswith("/app/spokes/"):
            username = self.require_session()
            if not username: return
            sid  = path.split("/")[3]
            user = get_user_state(username)
            if sid not in user["spokes"]:
                self.send_json(404, {"error": "Spoke not found"})
                return
            name = user["spokes"][sid].get("name", sid)
            del user["spokes"][sid]
            save_state(app_state)
            print(f"  Removed spoke {sid} ({name}) for {username}")
            self.send_json(200, {"ok": True})
            return

        # Delete hub
        if path.startswith("/app/hubs/"):
            username = self.require_portal_manager()
            if not username: return
            hid  = path.split("/")[3]
            user = get_user_state(username)
            if hid not in user["hubs"]:
                self.send_json(404, {"error": "Hub not found"})
                return
            name = user["hubs"][hid].get("name", hid)
            del user["hubs"][hid]
            save_state(app_state)
            print(f"  Removed hub {hid} ({name}) for {username}")
            self.send_json(200, {"ok": True})
            return

        # Delete a portal relationship
        if path.startswith("/app/portals/"):
            username = self.require_portal_manager()
            if not username: return
            parts    = path.split("/")   # ['', 'app', 'portals', spoke_id, portal_id]
            if len(parts) < 5:
                self.send_json(400, {"error": "Usage: DELETE /app/portals/{spoke_id}/{portal_id}"}); return
            spoke_id  = parts[3]
            portal_id = parts[4]
            user  = get_user_state(username)
            spoke = user["spokes"].get(spoke_id)
            if not spoke: self.send_json(404, {"error": "Spoke not found"}); return
            token, err = get_cluster_token(username, "spoke", spoke_id)
            if err: self.send_json(401, {"error": err}); return
            status, result = qumulo_request(spoke["host"],
                                            f"/v2/portal/spokes/{portal_id}",
                                            "DELETE", token, None)
            if status >= 400:
                self.send_json(status, {"error": "Failed to delete portal", "detail": result})
                return
            print(f"  Portal {portal_id} deleted from spoke {spoke_id}")
            self.send_json(200, {"ok": True})
            return

        # Delete user (admin only)
        if path.startswith("/app/users/"):
            admin = self.require_admin()
            if not admin: return
            target = path.split("/")[3]
            if target == ADMIN_USERNAME:
                self.send_json(400, {"error": "The built-in admin account cannot be deleted."})
                return
            users = load_users()
            if target not in users:
                self.send_json(404, {"error": f"User '{target}' not found."})
                return
            del users[target]
            save_users(users)
            if target in app_state:
                del app_state[target]
                save_state(app_state)
            print(f"  Deleted user: {target} (by {admin})")
            self.send_json(200, {"ok": True})
            return

        self.send_json(404, {"error": "Not found"})


# ── Entry point ────────────────────────────────────────────────────────
def run():
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", PORT))
        sock.close()
    except OSError as e:
        print(f"\n  ERROR: Cannot bind to port {PORT}: {e}\n")
        sys.exit(1)

    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"""
  ╔══════════════════════════════════════════════════╗
  ║   CDF Manager Proxy  —  port {PORT}                ║
  ║   Admin account    : {ADMIN_USERNAME:<25} ║
  ║   SSL verification : DISABLED                   ║
  ║   State file       : {STATE_FILE:<25} ║
  ║   Users file       : {USERS_FILE:<25} ║
  ║   Press Ctrl-C to stop                          ║
  ╚══════════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Proxy stopped.")

if __name__ == "__main__":
    run()
