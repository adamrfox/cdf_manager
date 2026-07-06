#!/usr/bin/env python3
"""
proxy.py — Qumulo Monitor proxy + API server
---------------------------------------------
Endpoints:
  POST   /app/login              — log into the app
  POST   /app/logout             — invalidate session
  GET    /app/spokes             — list user's spokes
  POST   /app/spokes             — add a spoke
  DELETE /app/spokes/{id}        — remove a spoke
  POST   /app/spokes/{id}/auth   — authenticate to a spoke cluster
  GET    /app/users              — list users (admin only)
  POST   /app/users              — create a user (admin only)
  DELETE /app/users/{username}   — delete a user (admin only)
  POST   /proxy                  — forward API call to a Qumulo cluster
  GET    /health                 — health check
"""

import json, sys, os, ssl, uuid, hashlib, secrets, urllib.request, urllib.error, http.server
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

# ── SSL context ────────────────────────────────────────────────────────
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

# ── Session store ──────────────────────────────────────────────────────
sessions = {}

# ── User store ─────────────────────────────────────────────────────────
# users.json: { "username": { "password_hash": "...", "created": "ISO" } }
# The admin account from config.py is always injected at runtime and never written to disk.

def load_users():
    users = {}
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                users = json.load(f)
        except Exception as e:
            print(f"  WARNING: Could not load users: {e}")
    return users

def save_users(users):
    # Never persist the built-in admin — it lives only in config.py
    to_save = {k: v for k, v in users.items() if k != ADMIN_USERNAME}
    try:
        with open(USERS_FILE, "w") as f:
            json.dump(to_save, f, indent=2)
    except Exception as e:
        print(f"  WARNING: Could not save users: {e}")

def get_all_users():
    """Return combined dict of config admin + users.json accounts."""
    users = load_users()
    users[ADMIN_USERNAME] = {"password_hash": ADMIN_PASSWORD_HASH, "created": "built-in"}
    return users

def check_password(username, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    users  = get_all_users()
    u = users.get(username)
    return u and u["password_hash"] == hashed

def is_admin(username):
    return username == ADMIN_USERNAME

# ── State persistence ──────────────────────────────────────────────────
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
        app_state[username] = {"spokes": {}}
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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
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

    # ── GET ────────────────────────────────────────────────────────────
    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/health":
            self.send_json(200, {"status": "ok"})
            return

        # List spokes
        if path == "/app/spokes":
            username = self.require_session()
            if not username: return
            user   = get_user_state(username)
            spokes = []
            now    = datetime.now(timezone.utc)
            for sid, s in user["spokes"].items():
                exp     = s.get("token_expires")
                expired = True
                if exp:
                    try: expired = datetime.fromisoformat(exp) < now
                    except: pass
                spokes.append({
                    "id":            sid,
                    "name":          s.get("name", sid),
                    "host":          s.get("host", ""),
                    "added":         s.get("added", ""),
                    "has_token":     bool(s.get("token")),
                    "token_expires": exp,
                    "token_expired": expired,
                })
            self.send_json(200, {"spokes": spokes})
            return

        # List users (admin only)
        if path == "/app/users":
            username = self.require_admin()
            if not username: return
            all_users = get_all_users()
            result = []
            for uname, udata in all_users.items():
                result.append({
                    "username": uname,
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

        # App login
        if path == "/app/login":
            username = payload.get("username", "")
            password = payload.get("password", "")
            if not check_password(username, password):
                self.send_json(401, {"error": "Invalid username or password."})
                return
            token, expires = create_session(username)
            print(f"  App login: {username}")
            self.send_json(200, {
                "session_token": token,
                "expires":       expires,
                "username":      username,
                "is_admin":      is_admin(username),
            })
            return

        # App logout
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
            if not new_user or not password:
                self.send_json(400, {"error": "username and password are required."})
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
                "created":       datetime.now(timezone.utc).isoformat(),
            }
            save_users(users)
            print(f"  Created user: {new_user} (by {username})")
            self.send_json(200, {"ok": True, "username": new_user})
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
                "id":            sid,
                "name":          name,
                "host":          host,
                "added":         datetime.now(timezone.utc).isoformat(),
                "token":         None,
                "token_expires": None,
            }
            save_state(app_state)
            print(f"  Added spoke: {name} ({host}) for {username}")
            self.send_json(200, {"id": sid, "name": name, "host": host})
            return

        # Authenticate to a spoke
        if path.startswith("/app/spokes/") and path.endswith("/auth"):
            username = self.require_session()
            if not username: return
            sid  = path.split("/")[3]
            user = get_user_state(username)
            if sid not in user["spokes"]:
                self.send_json(404, {"error": "Spoke not found"})
                return
            spoke   = user["spokes"][sid]
            host    = spoke["host"]
            qu_user = payload.get("username", "")
            qu_pass = payload.get("password", "")
            status, data = qumulo_request(host, "/v1/session/login", "POST", None,
                                          {"username": qu_user, "password": qu_pass})
            if status != 200:
                desc = data.get("description") or data.get("__raw") or "Authentication failed"
                self.send_json(status, {"error": f"Qumulo auth failed: {desc}"})
                return
            token = data.get("bearer_token") or data.get("key") or data.get("token")
            if not token:
                self.send_json(500, {"error": f"No token in response: {json.dumps(data)}"})
                return
            expires = (datetime.now(timezone.utc) + timedelta(days=QUMULO_TOKEN_EXPIRY_DAYS)).isoformat()
            spoke["token"]         = token
            spoke["token_expires"] = expires
            save_state(app_state)
            print(f"  Spoke {sid} authenticated, token expires {expires}")
            self.send_json(200, {"ok": True, "token_expires": expires})
            return

        # Proxy Qumulo API call
        if path == "/proxy":
            username = self.require_session()
            if not username: return
            host     = payload.get("host", "")
            api_path = payload.get("path", "")
            method   = payload.get("method", "GET").upper()
            token    = payload.get("token", "")
            spoke_id = payload.get("spoke_id", "")
            body     = payload.get("body", None)
            if not host or not api_path:
                self.send_json(400, {"__proxy_error": "Missing host or path"})
                return
            if spoke_id:
                user  = get_user_state(username)
                spoke = user["spokes"].get(spoke_id)
                if not spoke:
                    self.send_json(404, {"__proxy_error": f"Spoke {spoke_id} not found"})
                    return
                token = spoke.get("token") or ""
                if not token:
                    self.send_json(401, {"__proxy_error": "Spoke has no token — authenticate first"})
                    return
                exp = spoke.get("token_expires")
                if exp:
                    try:
                        if datetime.fromisoformat(exp) < datetime.now(timezone.utc):
                            self.send_json(401, {"__proxy_error": "Spoke token expired — re-authenticate"})
                            return
                    except: pass
            status, result = qumulo_request(host, api_path, method, token, body)
            self.send_json(200 if status < 400 else status, result)
            return

        self.send_json(404, {"error": "Not found"})

    # ── DELETE ─────────────────────────────────────────────────────────
    def do_DELETE(self):
        path = self.path.split("?")[0]
        print(f"\n[{self.client_address[0]}] DELETE {path}")

        # Delete a spoke
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

        # Delete a user (admin only)
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
            # Also remove their spoke state
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
  ╔═══════════════════════════════════════════════╗
  ║   Qumulo Monitor Proxy  —  port {PORT}           ║
  ║   Admin account    : {ADMIN_USERNAME:<22} ║
  ║   SSL verification : DISABLED                ║
  ║   State file       : {STATE_FILE:<22} ║
  ║   Users file       : {USERS_FILE:<22} ║
  ║   Press Ctrl-C to stop                       ║
  ╚═══════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Proxy stopped.")

if __name__ == "__main__":
    run()
