"""
config.py — CDF Manager configuration
--------------------------------------
Defines the built-in admin account and runtime settings.
Additional users are managed via the web UI and stored in users.json.

To generate a password hash:
    python3 -c "import hashlib; print(hashlib.sha256('yourpassword'.encode()).hexdigest())"
"""

import hashlib

# ── INITIAL ADMIN ACCOUNT ──────────────────────────────────────────────
# Built-in — always available, cannot be deleted or have its role changed.
# CHANGE THE PASSWORD before deploying!
ADMIN_USERNAME        = "admin"
ADMIN_PASSWORD_HASH   = "250fa54d30e123cb149523751b2b8d24deb4fa3d18c13fe0499c67f26f47153e"

# ── SESSION SETTINGS ───────────────────────────────────────────────────
APP_SESSION_EXPIRY_SECONDS = 8 * 60 * 60   # 8 hours
QUMULO_TOKEN_EXPIRY_DAYS   = 30

# ── FILE PATHS ─────────────────────────────────────────────────────────
STATE_FILE    = "state.json"    # spoke/hub/token state per user
USERS_FILE    = "users.json"    # created users + roles
SESSIONS_FILE = "sessions.json" # persisted login sessions
SETTINGS_FILE = "settings.json" # app settings

# ── NETWORK ────────────────────────────────────────────────────────────
PROXY_PORT  = 8081
