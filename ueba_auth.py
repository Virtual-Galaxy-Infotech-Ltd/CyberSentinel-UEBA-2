"""
ueba_auth.py — SSO login, session and role layer for the UEBA dashboard.

The dashboard has historically had no authentication at all: open `CORS(app)`,
bound to 0.0.0.0:3026, every endpoint anonymous. This module is the first half
of closing that — it accepts a signed JWT minted by the SIEM, provisions the
user on first sight, and issues a server-side session.

SCOPE — HS256 only, for now
---------------------------
Only the shared-secret (HS256) path is implemented and reachable. The RS256 /
JWKS path is what the SIEM team will eventually want, but it needs three things
we do not have yet: the cert PEM carrying `IP:103.252.168.197` in its SAN, a
confirmed JWKS URL, and a confirmed SIEM hostname. `algorithm: RS256` is
therefore rejected at config load with an explicit error rather than silently
falling back to something weaker.

SAFETY — enforcement is OFF by default
--------------------------------------
`auth.enforce` defaults to False. With it off this module registers its own
endpoints and will happily mint sessions, but it does NOT gate any pre-existing
API route. That means deploying this file cannot lock the SOC out of a live
dashboard. Turning enforcement on is a deliberate, separate step once an SSO
round-trip has been proven end to end (`/api/sso/ping` reports readiness).

Degrades gracefully when PyJWT is absent, matching the optional-dependency
convention used across this codebase (hdbscan, geoip2, orjson).
"""

from __future__ import annotations

import functools
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, current_app, g, jsonify, request

log = logging.getLogger("ueba.auth")

try:
    import jwt as _jwt
    from jwt import PyJWTError
    JWT_AVAILABLE = True
except ImportError:  # pragma: no cover - degrade like the rest of the codebase
    _jwt = None
    PyJWTError = Exception
    JWT_AVAILABLE = False
    log.warning("PyJWT not installed — SSO disabled. Install: pip install 'pyjwt>=2.8,<3.0'")


# ── Role model ────────────────────────────────────────────────────────────────
# Ordered weakest → strongest; `role_at_least` compares by index so a route
# gated on "analyst" also admits "admin".
ROLES = ("viewer", "analyst", "admin")
_ROLE_RANK = {r: i for i, r in enumerate(ROLES)}


DEFAULTS = {
    "enabled":          False,      # master switch for the whole module
    "enforce":          False,      # gate pre-existing API routes (see module docstring)
    "algorithm":        "HS256",
    "secret_env":       "UEBA_SSO_SECRET",
    "issuer":           "",         # required when enabled — verified against `iss`
    "audience":         "",         # required when enabled — verified against `aud`
                                    # (str, or list[str] to accept several)
    "leeway_secs":      60,         # clock skew tolerance for exp/nbf/iat
    "max_token_age_secs": 300,      # reject an SSO assertion older than this even if exp is generous
    "session_ttl_secs": 28800,      # 8h
    "session_idle_secs": 3600,      # revoke after 1h of no use
    "cookie_name":      "ueba_session",
    "cookie_secure":    False,      # set true once the dashboard is behind TLS
    "cookie_samesite":  "Lax",
    "auth_db":          "/root/NEW_DRIVE/aditya_ueba/profiles/ueba_auth.db",
    "default_role":     "viewer",
    "role_claim":       "roles",    # claim holding a list[str] or space/comma-joined str
    "role_map":         {},         # {siem_group: ueba_role}
    "allow_jit":        True,       # provision unknown-but-valid subjects on first login
    # Never gated, even with enforce on. /api/health is here so the watchdog
    # (which probes it every 2 min) keeps working without a credential.
    "public_paths": [
        "/api/health",
        "/api/sso/ping",
        "/auth/sso",
        "/api/auth/sso/exchange",
    ],
}


class AuthConfigError(RuntimeError):
    """Raised at startup for a configuration that would be unsafe to run."""


# ── Config ────────────────────────────────────────────────────────────────────

def load_auth_config(raw_cfg: dict | None) -> dict:
    """Layer the `auth:` block of ueba_config.yaml onto DEFAULTS and validate."""
    cfg = dict(DEFAULTS)
    cfg["role_map"] = dict(DEFAULTS["role_map"])
    cfg["public_paths"] = list(DEFAULTS["public_paths"])

    block = {}
    if isinstance(raw_cfg, dict):
        block = raw_cfg.get("auth") or {}
    if isinstance(block, dict):
        for k, v in block.items():
            if k == "role_map" and isinstance(v, dict):
                cfg["role_map"].update(v)
            elif k == "public_paths" and isinstance(v, list):
                cfg["public_paths"] = list(v)
            else:
                cfg[k] = v

    if not cfg["enabled"]:
        return cfg

    alg = str(cfg["algorithm"]).upper()
    if alg != "HS256":
        # Explicitly refuse rather than degrade: an operator who sets RS256
        # expecting asymmetric verification must not silently get something else.
        raise AuthConfigError(
            f"auth.algorithm={alg!r} is not implemented. Only HS256 is supported "
            "today; the RS256/JWKS path is blocked pending the SIEM team's cert "
            "PEM (needs IP:103.252.168.197 in SAN), JWKS URL and SIEM host."
        )
    cfg["algorithm"] = alg

    if not cfg["issuer"] or not cfg["audience"]:
        raise AuthConfigError(
            "auth.issuer and auth.audience are both required when auth.enabled "
            "is true — without them a token minted for any other service would "
            "be accepted here."
        )
    if cfg["default_role"] not in _ROLE_RANK:
        raise AuthConfigError(f"auth.default_role={cfg['default_role']!r} not one of {ROLES}")
    for grp, role in cfg["role_map"].items():
        if role not in _ROLE_RANK:
            raise AuthConfigError(f"auth.role_map[{grp!r}]={role!r} not one of {ROLES}")
    return cfg


def get_secret(cfg: dict) -> str | None:
    """Read the shared signing secret from the environment (never from YAML)."""
    return os.environ.get(cfg.get("secret_env") or "UEBA_SSO_SECRET") or None


# ── Store ─────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    sub          TEXT PRIMARY KEY,
    username     TEXT,
    email        TEXT,
    display_name TEXT,
    role         TEXT NOT NULL DEFAULT 'viewer',
    role_pinned  INTEGER NOT NULL DEFAULT 0,
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    last_login   TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash   TEXT PRIMARY KEY,
    sub          TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    remote_addr  TEXT,
    user_agent   TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_sub ON sessions(sub);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
-- Replay guard: an SSO assertion is single-use. Rows expire with the token.
CREATE TABLE IF NOT EXISTS used_assertions (
    jti        TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_used_exp ON used_assertions(expires_at);
"""


# ── Local password authentication ────────────────────────────────────────────
#
# Local accounts exist so UEBA can run without CyberSentinel SIEM in front of it.
# They coexist with SSO rather than replacing it: an SSO user and a local user are
# both just rows in `users`, distinguished by the `sub` prefix, and both end up
# holding an ordinary session cookie. Everything downstream — roles, capability
# gating, the audit trail — is identical either way.
#
# scrypt, from the standard library, is the KDF. bcrypt/argon2/passlib are not
# installed and adding a dependency to a box shared with other teams is not worth
# it when Python ships a memory-hard KDF that is fit for exactly this.
#
# N is kept at 2**14 so one hash stays under hashlib's default 32 MB maxmem and a
# burst of login attempts cannot be turned into a memory-pressure DoS. Brute force
# is handled by lockout below, not by making a single hash punitively slow.
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024

LOCAL_SUB_PREFIX = "local:"
MAX_FAILED_LOGINS = 5
LOCKOUT_SECS = 15 * 60
# Lowered from 12 at the operator's request: 6 is the floor, i.e. anything
# longer than five characters is accepted. Worth knowing what that costs — a
# 6-character password is brute-forceable offline in seconds if the auth DB is
# ever read, and scrypt only slows that down, it does not stop it. The controls
# that still stand between an attacker and an account are MAX_FAILED_LOGINS and
# LOCKOUT_SECS above, which throttle guessing over the network; they do nothing
# for an attacker who has the file. Raise this back towards 12 when the estate
# allows it.
MIN_PASSWORD_LEN = 6

# Username rules. Tighter than passwords on purpose: a username is not a secret,
# but it IS what local_sub() turns into a primary key, so it has to survive being
# lowercased, put in a URL path and read aloud over a phone.
MIN_USERNAME_LEN = 3
MAX_USERNAME_LEN = 32
# `@` is allowed because this estate already uses email-shaped identities, and a
# local account should be able to match the name its owner is known by.
_USERNAME_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@")


def local_sub(username: str) -> str:
    """`sub` for a local account. Prefixed so it can never collide with an
    SSO subject claim, which is issued by the SIEM and outside our control."""
    return LOCAL_SUB_PREFIX + username.strip().lower()


def is_local_sub(sub: str) -> bool:
    return (sub or "").startswith(LOCAL_SUB_PREFIX)


def hash_password(password: str) -> str:
    """scrypt$N$r$p$salt_b64$hash_b64 — self-describing so the parameters can be
    raised later without invalidating existing hashes."""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N,
                        r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
                        maxmem=_SCRYPT_MAXMEM)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time check. Returns False on any malformed hash rather than
    raising — a corrupt row must fail closed, not 500 the login endpoint."""
    if not stored:
        return False
    try:
        scheme, n, r, pp, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode("utf-8"),
                            salt=base64.b64decode(salt_b64),
                            n=int(n), r=int(r), p=int(pp),
                            dklen=len(base64.b64decode(hash_b64)),
                            maxmem=_SCRYPT_MAXMEM)
        return secrets.compare_digest(dk, base64.b64decode(hash_b64))
    except Exception:
        return False


def password_problem(password: str) -> str | None:
    """Why this password is unacceptable, or None. Deliberately length-first:
    a length floor buys more than composition rules do."""
    if not password or len(password) < MIN_PASSWORD_LEN:
        return f"password must be at least {MIN_PASSWORD_LEN} characters"
    if password.strip() != password:
        return "password must not start or end with whitespace"
    return None


def username_problem(username: str) -> str | None:
    """Why this username is unacceptable, or None.

    Note what this does NOT check: whether the name is free. That is a race the
    database has to settle, so it is enforced by the `sub` primary key inside
    rename_local_user() / create_local_user() rather than here.
    """
    u = (username or "").strip()
    if len(u) < MIN_USERNAME_LEN:
        return f"username must be at least {MIN_USERNAME_LEN} characters"
    if len(u) > MAX_USERNAME_LEN:
        return f"username must be at most {MAX_USERNAME_LEN} characters"
    if not set(u) <= _USERNAME_CHARS:
        return ("username may use only letters, digits, dot, underscore "
                "and hyphen")
    if not (u[0].isalnum() and u[-1].isalnum()):
        return "username must start and end with a letter or digit"
    return None


class AuthStore:
    """SQLite-backed identity + session store.

    Separate DB from profiles/user_profiles.db on purpose: that one holds
    behavioural baselines keyed on observed entity names and is rewritten by
    the engine at speed. Identity has a different lifecycle, a different
    blast radius, and different backup needs.
    """

    # Columns added after the SSO-only schema shipped. ALTER TABLE rather than
    # editing _SCHEMA, because _SCHEMA only runs CREATE TABLE IF NOT EXISTS and
    # would silently skip an existing deployment's users table.
    _MIGRATIONS = (
        ("password_hash",   "TEXT"),
        ("password_set_at", "TEXT"),
        ("failed_logins",   "INTEGER NOT NULL DEFAULT 0"),
        ("locked_until",    "INTEGER NOT NULL DEFAULT 0"),
    )

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        have = {r["name"] for r in self._conn.execute("PRAGMA table_info(users)")}
        for col, decl in self._MIGRATIONS:
            if col not in have:
                self._conn.execute(f"ALTER TABLE users ADD COLUMN {col} {decl}")

    # -- users ------------------------------------------------------------
    def get_user(self, sub: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE sub = ?", (sub,)).fetchone()
        return dict(row) if row else None

    def upsert_user(self, sub: str, username: str, email: str,
                    display_name: str, role: str) -> dict:
        """Create on first sight, refresh profile fields on later logins.

        `role_pinned` lets an admin override the SIEM-derived role locally
        (`UPDATE users SET role=?, role_pinned=1`); once pinned, later logins
        keep the local role instead of re-deriving it from the token claims.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute("SELECT sub, role_pinned FROM users WHERE sub = ?", (sub,))
            existing = cur.fetchone()
            if existing is None:
                self._conn.execute(
                    "INSERT INTO users (sub, username, email, display_name, role, "
                    "created_at, last_login) VALUES (?,?,?,?,?,?,?)",
                    (sub, username, email, display_name, role, now, now),
                )
            elif existing["role_pinned"]:
                self._conn.execute(
                    "UPDATE users SET username=?, email=?, display_name=?, last_login=? "
                    "WHERE sub=?", (username, email, display_name, now, sub))
            else:
                self._conn.execute(
                    "UPDATE users SET username=?, email=?, display_name=?, role=?, "
                    "last_login=? WHERE sub=?",
                    (username, email, display_name, role, now, sub))
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM users WHERE sub = ?", (sub,)).fetchone()
        return dict(row)

    # -- local accounts ---------------------------------------------------
    def create_local_user(self, username: str, password: str, role: str,
                          display_name: str = "", email: str = "") -> dict:
        """Create a password account. Raises ValueError if the name is taken."""
        sub = local_sub(username)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if self._conn.execute("SELECT 1 FROM users WHERE sub=?", (sub,)).fetchone():
                raise ValueError(f"user {username!r} already exists")
            self._conn.execute(
                "INSERT INTO users (sub, username, email, display_name, role, "
                "role_pinned, active, created_at, password_hash, password_set_at) "
                "VALUES (?,?,?,?,?,1,1,?,?,?)",
                (sub, username, email, display_name or username, role, now,
                 hash_password(password), now))
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM users WHERE sub=?", (sub,)).fetchone()
        return dict(row)

    def set_password(self, sub: str, password: str) -> bool:
        """Set a password and clear any lockout. Also used for admin resets."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE users SET password_hash=?, password_set_at=?, "
                "failed_logins=0, locked_until=0 WHERE sub=?",
                (hash_password(password), now, sub))
            self._conn.commit()
        return cur.rowcount > 0

    def rename_local_user(self, old_sub: str, new_username: str) -> dict | None:
        """Rename a local account, carrying its sessions with it.

        This has to move the primary key, not just relabel the row. A local
        account's `sub` is DERIVED from its name by local_sub(), and
        verify_login() looks an account up by that derived key rather than by
        the username column — so updating `username` alone would leave the user
        able to sign in only under their old name, which is the opposite of what
        they asked for.

        sessions.sub is a foreign key in all but name, so it moves in the same
        transaction. Without that, renaming yourself would sign you out of every
        device you own as a side effect.

        Returns the updated row, or None if old_sub does not exist. Raises
        ValueError if the new name is taken — the `sub` primary key is what
        settles that race, not a prior SELECT.
        """
        new_sub = local_sub(new_username)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE sub=?", (old_sub,)).fetchone()
            if row is None:
                return None
            old = dict(row)
            if new_sub != old_sub and self._conn.execute(
                    "SELECT 1 FROM users WHERE sub=?", (new_sub,)).fetchone():
                raise ValueError(f"the name {new_username!r} is already taken")
            # display_name is seeded from the username at creation. Carry it
            # along only while it still mirrors the old name — if the user set
            # it to something of their own, that is theirs to keep.
            disp = old.get("display_name")
            new_disp = (new_username
                        if (not disp or disp == old.get("username")) else disp)
            try:
                self._conn.execute(
                    "UPDATE users SET sub=?, username=?, display_name=? WHERE sub=?",
                    (new_sub, new_username, new_disp, old_sub))
                self._conn.execute(
                    "UPDATE sessions SET sub=? WHERE sub=?", (new_sub, old_sub))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            out = self._conn.execute(
                "SELECT * FROM users WHERE sub=?", (new_sub,)).fetchone()
        return dict(out) if out else None

    def verify_login(self, username: str, password: str) -> tuple[dict | None, str]:
        """(user, reason). user is None unless the password is correct AND the
        account is active and unlocked.

        A wrong password and an unknown username must cost the same and say the
        same thing, or the endpoint becomes a username oracle. The dummy hash on
        the miss path is what keeps the timing comparable.
        """
        sub = local_sub(username)
        now = int(time.time())
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE sub=?", (sub,)).fetchone()
            user = dict(row) if row else None

        if user is None:
            verify_password(password, hash_password("timing-equaliser"))
            return None, "invalid credentials"
        if not user.get("active"):
            return None, "account disabled"
        if (user.get("locked_until") or 0) > now:
            left = int((user["locked_until"] - now) / 60) + 1
            return None, f"account locked, try again in {left} min"
        if not user.get("password_hash"):
            return None, "no password set for this account"

        if not verify_password(password, user["password_hash"]):
            with self._lock:
                fails = (user.get("failed_logins") or 0) + 1
                lock_to = now + LOCKOUT_SECS if fails >= MAX_FAILED_LOGINS else 0
                self._conn.execute(
                    "UPDATE users SET failed_logins=?, locked_until=? WHERE sub=?",
                    (fails, lock_to, sub))
                self._conn.commit()
            if lock_to:
                return None, "too many failed attempts, account locked"
            return None, "invalid credentials"

        with self._lock:
            self._conn.execute(
                "UPDATE users SET failed_logins=0, locked_until=0, last_login=? "
                "WHERE sub=?", (datetime.now(timezone.utc).isoformat(), sub))
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM users WHERE sub=?", (sub,)).fetchone()
        return dict(row), "ok"

    def list_users(self) -> list[dict]:
        """Every account, local and SSO. Never returns password material."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT sub, username, email, display_name, role, role_pinned, "
                "active, created_at, last_login, locked_until, failed_logins, "
                "(password_hash IS NOT NULL) AS has_password "
                "FROM users ORDER BY username").fetchall()
        return [dict(r) for r in rows]

    def update_user(self, sub: str, *, role: str | None = None,
                    active: int | None = None, display_name: str | None = None,
                    email: str | None = None, unlock: bool = False) -> dict | None:
        sets, args = [], []
        if role is not None:
            # Pin it: an admin's explicit choice must survive the next SSO login,
            # which would otherwise re-derive the role from the token claims.
            sets += ["role=?", "role_pinned=1"]; args.append(role)
        if active is not None:       sets.append("active=?");       args.append(int(active))
        if display_name is not None: sets.append("display_name=?"); args.append(display_name)
        if email is not None:        sets.append("email=?");        args.append(email)
        if unlock:                   sets += ["locked_until=0", "failed_logins=0"]
        if not sets:
            return self.get_user(sub)
        args.append(sub)
        with self._lock:
            self._conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE sub=?", args)
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM users WHERE sub=?", (sub,)).fetchone()
        return dict(row) if row else None

    def delete_user(self, sub: str) -> bool:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE sub=?", (sub,))
            cur = self._conn.execute("DELETE FROM users WHERE sub=?", (sub,))
            self._conn.commit()
        return cur.rowcount > 0

    def count_active_admins(self) -> int:
        """Guards the last-admin checks: locking yourself out of your own
        console is a support call, not a security feature."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1"
            ).fetchone()
        return int(row["n"] if row else 0)

    # -- sessions ---------------------------------------------------------
    @staticmethod
    def _hash(token: str) -> str:
        # Store only the hash: a leaked DB must not yield usable session cookies.
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(self, sub: str, ttl: int, remote_addr: str, user_agent: str) -> str:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "INSERT INTO sessions (token_hash, sub, created_at, expires_at, "
                "last_seen, remote_addr, user_agent) VALUES (?,?,?,?,?,?,?)",
                (self._hash(token), sub, now, now + ttl, now,
                 remote_addr[:64], user_agent[:256]),
            )
            self._conn.commit()
        return token

    def touch_session(self, token: str, idle_secs: int) -> dict | None:
        """Validate a session cookie and slide its idle window."""
        now = int(time.time())
        th = self._hash(token)
        with self._lock:
            row = self._conn.execute(
                "SELECT s.sub, s.expires_at, s.last_seen, u.role, u.username, "
                "u.display_name, u.email, u.active FROM sessions s "
                "JOIN users u ON u.sub = s.sub WHERE s.token_hash = ?", (th,)
            ).fetchone()
            if row is None:
                return None
            if row["expires_at"] <= now:
                self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
                self._conn.commit()
                return None
            if idle_secs > 0 and (now - row["last_seen"]) > idle_secs:
                self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (th,))
                self._conn.commit()
                return None
            if not row["active"]:
                return None
            self._conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?",
                               (now, th))
            self._conn.commit()
        return {"sub": row["sub"], "role": row["role"], "username": row["username"],
                "display_name": row["display_name"], "email": row["email"]}

    def revoke_session(self, token: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (self._hash(token),))
            self._conn.commit()

    def revoke_all_for(self, sub: str) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM sessions WHERE sub = ?", (sub,))
            self._conn.commit()
            return cur.rowcount

    # -- replay guard ------------------------------------------------------
    def claim_assertion(self, jti: str, expires_at: int) -> bool:
        """Record a one-time-use assertion id. False if already spent."""
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO used_assertions (jti, expires_at) VALUES (?,?)",
                    (jti, expires_at))
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def purge_expired(self) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            self._conn.execute("DELETE FROM used_assertions WHERE expires_at <= ?", (now,))
            self._conn.commit()

    def stats(self) -> dict:
        now = int(time.time())
        with self._lock:
            users = self._conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
            live = self._conn.execute(
                "SELECT COUNT(*) c FROM sessions WHERE expires_at > ?", (now,)).fetchone()["c"]
        return {"users": users, "active_sessions": live}


# ── Token verification ────────────────────────────────────────────────────────

def _extract_roles(claims: dict, role_claim: str) -> list[str]:
    """Pull group/role strings out of the claim, tolerating the usual shapes."""
    raw = claims.get(role_claim)
    if raw is None:
        return []
    if isinstance(raw, str):
        return [p for p in raw.replace(",", " ").split() if p]
    if isinstance(raw, (list, tuple)):
        return [str(p) for p in raw if p]
    return []


def map_role(claims: dict, cfg: dict) -> str:
    """Map SIEM groups → a UEBA role, taking the STRONGEST match.

    Unmapped groups fall through to default_role rather than being rejected,
    so adding a new SIEM group cannot lock out its members; it just gives them
    the least privilege until an operator maps it.
    """
    groups = _extract_roles(claims, cfg.get("role_claim") or "roles")
    role_map = cfg.get("role_map") or {}
    best = cfg.get("default_role") or "viewer"
    for grp in groups:
        mapped = role_map.get(grp)
        if mapped and _ROLE_RANK[mapped] > _ROLE_RANK[best]:
            best = mapped
    return best


def verify_sso_token(token: str, cfg: dict, secret: str) -> dict:
    """Verify an HS256 SSO assertion. Raises ValueError with a safe message."""
    if not JWT_AVAILABLE:
        raise ValueError("PyJWT is not installed on this host")
    try:
        claims = _jwt.decode(
            token,
            secret,
            algorithms=["HS256"],          # pinned — never trust the header's alg
            issuer=cfg["issuer"],
            # May be a single string or a list. PyJWT accepts the token if its
            # `aud` matches ANY entry, which lets us honour two audience values
            # at once while the SIEM migrates from one to another — without ever
            # turning audience checking off.
            audience=cfg["audience"],
            leeway=int(cfg.get("leeway_secs") or 0),
            options={
                "require": ["exp", "iat", "iss", "aud", "sub"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except PyJWTError as e:
        # Message is deliberately coarse in the response; detail goes to the log.
        #
        # Re-decode WITHOUT verification purely to report WHICH claim disagreed.
        # "Audience doesn't match" on its own is unactionable: it never says what
        # the SIEM actually sent, so nobody can tell whose side is wrong. This is
        # safe — iss/aud/sub are public, non-secret claims, the signature is NOT
        # checked here, and nothing decoded in this branch is ever trusted or
        # returned to the caller. It exists so the next failed exchange names the
        # exact mismatch instead of costing another round-trip with the SIEM team.
        detail = ""
        try:
            seen = _jwt.decode(token, options={"verify_signature": False})
            detail = (" | token had iss=%r aud=%r sub=%r; this dashboard expects"
                      " iss=%r aud=%r"
                      % (seen.get("iss"), seen.get("aud"), seen.get("sub"),
                         cfg.get("issuer"), cfg.get("audience")))
        except Exception:
            pass
        log.warning("SSO token rejected: %s%s", e, detail)
        raise ValueError("token verification failed") from e

    sub = str(claims.get("sub") or "").strip()
    if not sub:
        raise ValueError("token has an empty sub")

    # Independently bound assertion age. A SIEM that mints exp=+24h would
    # otherwise hand out a token usable as a bearer credential all day.
    max_age = int(cfg.get("max_token_age_secs") or 0)
    if max_age > 0:
        iat = int(claims.get("iat") or 0)
        age = int(time.time()) - iat
        if age > max_age + int(cfg.get("leeway_secs") or 0):
            raise ValueError("assertion too old")
    return claims


# ── Blueprint ─────────────────────────────────────────────────────────────────

bp = Blueprint("ueba_auth", __name__)

_STATE: dict = {"cfg": dict(DEFAULTS), "store": None, "secret": None}


def _cfg() -> dict:
    return _STATE["cfg"]


def _store() -> AuthStore | None:
    return _STATE["store"]


def is_ready() -> tuple[bool, str]:
    """Can we actually complete an SSO exchange right now?"""
    cfg = _cfg()
    if not cfg.get("enabled"):
        return False, "auth.enabled is false"
    if not JWT_AVAILABLE:
        return False, "PyJWT not installed"
    if not _STATE["secret"]:
        return False, f"{cfg.get('secret_env')} is not set in the environment"
    if _store() is None:
        return False, "auth store failed to initialise"
    return True, "ready"


def can_authenticate() -> tuple[bool, str]:
    """Is there ANY way for a human to log in right now?

    Enforcement is safe only if at least one path works. SSO readiness alone is
    no longer the test: a standalone deployment authenticates entirely with local
    accounts and may have no SIEM at all.
    """
    sso_ok, sso_why = is_ready()
    if sso_ok:
        return True, "SSO ready"
    store = _store()
    if store is None:
        return False, f"no auth store, and SSO not ready ({sso_why})"
    admins = [u for u in store.list_users()
              if u.get("role") == "admin" and u.get("active") and u.get("has_password")]
    if admins:
        return True, f"{len(admins)} local admin account(s)"
    return False, (f"SSO not ready ({sso_why}) and no active local admin "
                   f"with a password exists")


def current_user() -> dict | None:
    """The authenticated user for this request, or None."""
    if hasattr(g, "_ueba_user"):
        return g._ueba_user
    user = None
    store = _store()
    if store is not None and _cfg().get("enabled"):
        tok = request.cookies.get(_cfg().get("cookie_name") or "ueba_session")
        if tok:
            user = store.touch_session(tok, int(_cfg().get("session_idle_secs") or 0))
    g._ueba_user = user
    return user


def is_enforcing() -> bool:
    """True when auth.enforce is on, i.e. when roles actually gate anything.

    Callers outside this module need this to answer "is RBAC live?" without
    reaching into _cfg(). While it is False every gate is deliberately a no-op.
    """
    return bool(_cfg().get("enforce"))


def role_at_least(user: dict | None, minimum: str) -> bool:
    if not user:
        return False
    return _ROLE_RANK.get(user.get("role", ""), -1) >= _ROLE_RANK.get(minimum, 99)


def require_role(minimum: str = "viewer"):
    """Gate a route on a minimum role.

    A no-op while auth.enforce is off, so the decorator can be applied to
    routes ahead of the cutover without changing behaviour.
    """
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            if not _cfg().get("enforce"):
                return fn(*a, **kw)
            user = current_user()
            if user is None:
                return jsonify({"error": "authentication required"}), 401
            if not role_at_least(user, minimum):
                return jsonify({"error": "insufficient role",
                                "required": minimum,
                                "have": user.get("role")}), 403
            return fn(*a, **kw)
        return wrapper
    return deco


# Always reachable, even with enforcement on and whatever public_paths says.
# These are the endpoints you need in order to authenticate at all, plus the
# health probe the watchdog uses. Overriding auth.public_paths in the config
# replaces the defaults wholesale, so without this floor a single config edit
# could make login unreachable and lock everyone out of their own console.
ALWAYS_PUBLIC = (
    "/api/health",
    "/api/auth/login",       # you cannot log in through a gate that needs a login
    "/api/auth/me",          # lets the SPA discover it is unauthenticated
    "/api/auth/capabilities",
    "/api/sso/ping",
    "/auth/sso",
    "/api/auth/sso/exchange",
)


def _is_public(path: str) -> bool:
    for p in ALWAYS_PUBLIC:
        if path == p or path.startswith(p.rstrip("/") + "/"):
            return True
    for p in _cfg().get("public_paths") or []:
        if path == p or path.startswith(p.rstrip("/") + "/"):
            return True
    return False


def install_request_gate(flask_app) -> None:
    """Global gate. Only bites when auth.enforce is true."""

    @flask_app.before_request
    def _ueba_auth_gate():
        if not _cfg().get("enforce"):
            return None
        if request.method == "OPTIONS":
            return None
        path = request.path or "/"
        if _is_public(path):
            return None
        # Let the SPA shell and its static assets load unauthenticated; the
        # data endpoints behind them are what actually need gating, and the
        # bundle is not a secret. Blocking these would just yield a blank page
        # with no way to reach the login flow.
        if not path.startswith("/api/"):
            return None
        if current_user() is None:
            return jsonify({"error": "authentication required",
                            "login": "/auth/sso"}), 401
        return None


@bp.route("/api/sso/ping")
def sso_ping():
    """Readiness probe for the SSO path. Reports posture, never the secret."""
    cfg = _cfg()
    ready, reason = is_ready()
    store = _store()
    body = {
        "enabled":       bool(cfg.get("enabled")),
        "enforce":       bool(cfg.get("enforce")),
        "ready":         ready,
        "reason":        reason,
        "algorithm":     cfg.get("algorithm"),
        "issuer":        cfg.get("issuer") or None,
        "audience":      cfg.get("audience") or None,
        "jwt_available": JWT_AVAILABLE,
        "secret_present": bool(_STATE["secret"]),
        "secret_env":    cfg.get("secret_env"),
        "roles":         list(ROLES),
        "default_role":  cfg.get("default_role"),
        "mapped_groups": sorted((cfg.get("role_map") or {}).keys()),
        "jit_provisioning": bool(cfg.get("allow_jit")),
    }
    if store is not None:
        body.update(store.stats())
    return jsonify(body)


@bp.route("/api/auth/sso/exchange", methods=["POST"])
def sso_exchange():
    """Trade a SIEM-minted JWT for a dashboard session cookie."""
    cfg = _cfg()
    ready, reason = is_ready()
    if not ready:
        return jsonify({"error": "sso not available", "reason": reason}), 503

    payload = request.get_json(silent=True) or {}
    token = (payload.get("token") or request.form.get("token") or "").strip()
    if not token:
        return jsonify({"error": "missing token"}), 400

    try:
        claims = verify_sso_token(token, cfg, _STATE["secret"])
    except ValueError as e:
        return jsonify({"error": str(e)}), 401

    store = _store()

    # Single-use: an assertion replayed from a proxy log or browser history
    # must not mint a second session.
    jti = str(claims.get("jti") or "")
    if jti:
        if not store.claim_assertion(jti, int(claims.get("exp") or (time.time() + 300))):
            return jsonify({"error": "assertion already used"}), 401

    sub = str(claims["sub"])
    known = store.get_user(sub)
    if known is None and not cfg.get("allow_jit"):
        return jsonify({"error": "unknown subject and JIT provisioning is disabled"}), 403
    if known is not None and not known.get("active", 1):
        return jsonify({"error": "account disabled"}), 403

    role = map_role(claims, cfg)
    user = store.upsert_user(
        sub=sub,
        username=str(claims.get("preferred_username") or claims.get("username") or sub),
        email=str(claims.get("email") or ""),
        display_name=str(claims.get("name") or claims.get("display_name") or ""),
        role=role,
    )

    ttl = int(cfg.get("session_ttl_secs") or 28800)
    sess = store.create_session(
        sub=sub, ttl=ttl,
        remote_addr=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        user_agent=request.headers.get("User-Agent", ""),
    )
    store.purge_expired()

    resp = jsonify({
        "ok": True,
        "user": {"sub": user["sub"], "username": user["username"],
                 "display_name": user["display_name"], "email": user["email"],
                 "role": user["role"]},
        "expires_in": ttl,
        "provisioned": known is None,
    })
    resp.set_cookie(
        cfg.get("cookie_name") or "ueba_session", sess,
        max_age=ttl,
        httponly=True,                                   # not readable from JS
        secure=bool(cfg.get("cookie_secure")),
        samesite=cfg.get("cookie_samesite") or "Lax",
        path="/",
    )
    log.info("SSO login sub=%s role=%s jit=%s", sub, user["role"], known is None)
    return resp


def _set_session_cookie(resp, token: str, ttl: int):
    cfg = _cfg()
    resp.set_cookie(
        cfg.get("cookie_name") or "ueba_session", token,
        max_age=ttl,
        httponly=True,                                   # not readable from JS
        secure=bool(cfg.get("cookie_secure")),
        samesite=cfg.get("cookie_samesite") or "Lax",
        path="/",
    )
    return resp


@bp.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Local username/password login.

    Exists so UEBA can run without CyberSentinel SIEM in front of it. It issues
    exactly the same session cookie as the SSO exchange, so everything
    downstream — roles, capability gating, the audit trail — is unchanged.

    Every failure returns the same shape and a 401; the store equalises timing
    between a wrong password and an unknown user so this cannot be used to
    enumerate accounts.
    """
    store = _store()
    if store is None:
        return jsonify({"ok": False, "error": "auth store unavailable"}), 503

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return jsonify({"ok": False, "error": "username and password required"}), 400

    user, reason = store.verify_login(username, password)
    addr = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if user is None:
        # Logged at WARNING deliberately: repeated failures are exactly what the
        # audit trail (RFP 65) is meant to surface.
        log.warning("local login FAILED user=%r from=%s reason=%s", username, addr, reason)
        return jsonify({"ok": False, "error": reason}), 401

    ttl = int(_cfg().get("session_ttl_secs") or 28800)
    token = store.create_session(
        sub=user["sub"], ttl=ttl, remote_addr=addr,
        user_agent=request.headers.get("User-Agent", ""),
    )
    store.purge_expired()
    log.info("local login ok user=%s role=%s from=%s", user["username"], user["role"], addr)
    resp = jsonify({
        "ok": True,
        "user": {"sub": user["sub"], "username": user["username"],
                 "display_name": user["display_name"], "email": user["email"],
                 "role": user["role"]},
        "expires_in": ttl,
    })
    return _set_session_cookie(resp, token, ttl)


@bp.route("/api/auth/password", methods=["POST"])
def auth_change_password():
    """Change your own password. Requires the current one — a stolen session
    must not be enough to take ownership of the account."""
    store = _store()
    if store is None:
        return jsonify({"ok": False, "error": "auth store unavailable"}), 503
    me = current_user()
    if me is None:
        return jsonify({"ok": False, "error": "authentication required"}), 401
    if not is_local_sub(me.get("sub", "")):
        return jsonify({"ok": False,
                        "error": "SSO accounts change their password in the SIEM"}), 400

    body = request.get_json(silent=True) or {}
    current = body.get("current_password") or ""
    new = body.get("new_password") or ""
    problem = password_problem(new)
    if problem:
        return jsonify({"ok": False, "error": problem}), 400

    ok, _ = store.verify_login(me["username"], current)
    if ok is None:
        log.warning("password change REJECTED for %s (bad current password)", me["sub"])
        return jsonify({"ok": False, "error": "current password is incorrect"}), 403

    store.set_password(me["sub"], new)
    # Every other session for this account dies with the password. Keep this one.
    tok = request.cookies.get(_cfg().get("cookie_name") or "ueba_session")
    store.revoke_all_for(me["sub"])
    ttl = int(_cfg().get("session_ttl_secs") or 28800)
    fresh = store.create_session(
        sub=me["sub"], ttl=ttl,
        remote_addr=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        user_agent=request.headers.get("User-Agent", ""))
    log.info("password changed for %s (other sessions revoked)", me["sub"])
    return _set_session_cookie(jsonify({"ok": True}), fresh, ttl)


@bp.route("/api/auth/username", methods=["POST"])
def auth_change_username():
    """Change your own username. Available to every signed-in local account
    regardless of role — it is your own name, not a privileged setting.

    The current password is required for the same reason it is on the password
    change: a stolen session must not be enough to rename the account. A rename
    is not cosmetic here, because the name is the login identifier — an attacker
    who could change it would lock the real owner out of their own account.

    SSO accounts are refused: their username arrives in the SIEM's token and is
    re-applied on every login, so a local change would silently revert.
    """
    store = _store()
    if store is None:
        return jsonify({"ok": False, "error": "auth store unavailable"}), 503
    me = current_user()
    if me is None:
        return jsonify({"ok": False, "error": "authentication required"}), 401
    if not is_local_sub(me.get("sub", "")):
        return jsonify({"ok": False,
                        "error": "SSO accounts are named by the SIEM, so the "
                                 "username has to change there"}), 400

    body = request.get_json(silent=True) or {}
    new_username = (body.get("new_username") or "").strip()
    current = body.get("current_password") or ""

    problem = username_problem(new_username)
    if problem:
        return jsonify({"ok": False, "error": problem}), 400
    if new_username == me.get("username"):
        return jsonify({"ok": False,
                        "error": "that is already your username"}), 400

    ok, _ = store.verify_login(me["username"], current)
    if ok is None:
        log.warning("username change REJECTED for %s (bad current password)",
                    me["sub"])
        return jsonify({"ok": False, "error": "current password is incorrect"}), 403

    old_sub = me["sub"]
    try:
        u = store.rename_local_user(old_sub, new_username)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 409
    if u is None:
        return jsonify({"ok": False, "error": "no such user"}), 404

    new_sub = u["sub"]
    # Same posture as the password change: keep the session that made the
    # request, drop the rest. The sessions moved with the account above, so
    # without this an old device would keep a live session under the new name
    # having never re-authenticated as it.
    store.revoke_all_for(new_sub)
    ttl = int(_cfg().get("session_ttl_secs") or 28800)
    fresh = store.create_session(
        sub=new_sub, ttl=ttl,
        remote_addr=request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        user_agent=request.headers.get("User-Agent", ""))
    log.info("username changed: %s -> %s (other sessions revoked)",
             old_sub, new_sub)
    return _set_session_cookie(
        jsonify({"ok": True, "user": _safe_user(u)}), fresh, ttl)


@bp.route("/api/auth/me")
def auth_me():
    user = current_user()
    if user is None:
        return jsonify({"authenticated": False, "enforce": bool(_cfg().get("enforce"))}), 200
    return jsonify({"authenticated": True, "user": user,
                    "enforce": bool(_cfg().get("enforce"))})


# ── Admin user management (RFP 23 / 7) ───────────────────────────────────────
# Every route here is admin-only. They are gated locally rather than by the
# dashboard's CAPABILITIES table because this blueprint is registered by
# ueba_auth and must stay usable even if the dashboard module changes shape.

def _safe_user(u: dict) -> dict:
    """A user row fit to send to a browser — never password material."""
    return {
        "sub": u.get("sub"), "username": u.get("username"),
        "email": u.get("email"), "display_name": u.get("display_name"),
        "role": u.get("role"), "active": bool(u.get("active")),
        "is_local": is_local_sub(u.get("sub", "")),
        "has_password": bool(u.get("has_password") or u.get("password_hash")),
        "created_at": u.get("created_at"), "last_login": u.get("last_login"),
        "locked": (u.get("locked_until") or 0) > int(time.time()),
        "failed_logins": u.get("failed_logins") or 0,
    }


@bp.route("/api/auth/users")
@require_role("admin")
def auth_users_list():
    store = _store()
    if store is None:
        return jsonify({"ok": False, "error": "auth store unavailable"}), 503
    return jsonify({"ok": True, "users": [_safe_user(u) for u in store.list_users()],
                    "roles": list(ROLES)})


@bp.route("/api/auth/users", methods=["POST"])
@require_role("admin")
def auth_users_create():
    store = _store()
    if store is None:
        return jsonify({"ok": False, "error": "auth store unavailable"}), 503
    b = request.get_json(silent=True) or {}
    username = (b.get("username") or "").strip()
    password = b.get("password") or ""
    role = (b.get("role") or "viewer").strip()
    if not username:
        return jsonify({"ok": False, "error": "username required"}), 400
    if role not in ROLES:
        return jsonify({"ok": False, "error": f"role must be one of {list(ROLES)}"}), 400
    problem = password_problem(password)
    if problem:
        return jsonify({"ok": False, "error": problem}), 400
    try:
        u = store.create_local_user(username, password, role,
                                    display_name=(b.get("display_name") or "").strip(),
                                    email=(b.get("email") or "").strip())
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 409
    log.info("admin created local user %s role=%s", username, role)
    return jsonify({"ok": True, "user": _safe_user(u)})


@bp.route("/api/auth/users/<path:sub>", methods=["PATCH"])
@require_role("admin")
def auth_users_update(sub):
    store = _store()
    if store is None:
        return jsonify({"ok": False, "error": "auth store unavailable"}), 503
    target = store.get_user(sub)
    if target is None:
        return jsonify({"ok": False, "error": "no such user"}), 404
    b = request.get_json(silent=True) or {}
    role = b.get("role")
    active = b.get("active")
    if role is not None and role not in ROLES:
        return jsonify({"ok": False, "error": f"role must be one of {list(ROLES)}"}), 400

    # Refuse to remove the last way back in. Demoting or disabling the only
    # active admin leaves a console nobody can administer.
    losing_admin = (target.get("role") == "admin" and target.get("active") and
                    ((role is not None and role != "admin") or active is False))
    if losing_admin and store.count_active_admins() <= 1:
        return jsonify({"ok": False,
                        "error": "this is the last active admin — promote another first"}), 409

    u = store.update_user(sub, role=role,
                          active=None if active is None else int(bool(active)),
                          display_name=b.get("display_name"), email=b.get("email"),
                          unlock=bool(b.get("unlock")))
    if b.get("password"):
        problem = password_problem(b["password"])
        if problem:
            return jsonify({"ok": False, "error": problem}), 400
        store.set_password(sub, b["password"])
        # A reset invalidates that user's sessions — otherwise resetting the
        # password of a compromised account leaves the intruder logged in.
        store.revoke_all_for(sub)
    if active is False:
        store.revoke_all_for(sub)
    log.info("admin updated user %s (%s)", sub, ", ".join(
        k for k in ("role", "active", "password", "unlock") if b.get(k) is not None))
    return jsonify({"ok": True, "user": _safe_user(u or {})})


@bp.route("/api/auth/users/<path:sub>", methods=["DELETE"])
@require_role("admin")
def auth_users_delete(sub):
    store = _store()
    if store is None:
        return jsonify({"ok": False, "error": "auth store unavailable"}), 503
    target = store.get_user(sub)
    if target is None:
        return jsonify({"ok": False, "error": "no such user"}), 404
    me = current_user() or {}
    if target["sub"] == me.get("sub"):
        return jsonify({"ok": False, "error": "you cannot delete your own account"}), 409
    if (target.get("role") == "admin" and target.get("active")
            and store.count_active_admins() <= 1):
        return jsonify({"ok": False,
                        "error": "this is the last active admin — promote another first"}), 409
    store.delete_user(sub)
    log.info("admin deleted user %s", sub)
    return jsonify({"ok": True})


@bp.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    cfg = _cfg()
    name = cfg.get("cookie_name") or "ueba_session"
    tok = request.cookies.get(name)
    store = _store()
    if tok and store is not None:
        store.revoke_session(tok)
    resp = jsonify({"ok": True})
    resp.delete_cookie(name, path="/")
    return resp


# The landing page the SIEM redirects to. Kept dependency-free and inline so it
# works before the Vite bundle loads and regardless of build state.
_LANDING_HTML = """<!doctype html>
<meta charset="utf-8">
<title>CyberSentinel UEBA — Signing in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         background:#0b0f17; color:#e6edf6;
         font:15px/1.5 "IBM Plex Sans", system-ui, sans-serif; }
  .card { width:min(92vw,420px); padding:32px; border-radius:14px;
          background:#111826; border:1px solid #1f2a3c; text-align:center; }
  h1 { margin:0 0 6px; font-size:17px; letter-spacing:.02em; }
  p  { margin:0; color:#8b9ab0; font-size:13px; }
  .err { color:#ff6b6b; margin-top:14px; font-size:13px; word-break:break-word; }
  .spin { width:26px; height:26px; margin:0 auto 18px; border-radius:50%;
          border:2px solid #23324a; border-top-color:#4da3ff;
          animation:s .8s linear infinite; }
  @keyframes s { to { transform:rotate(360deg); } }
</style>
<div class="card">
  <div class="spin" id="sp"></div>
  <h1>Signing you in</h1>
  <p id="msg">Verifying your SIEM assertion…</p>
  <div class="err" id="err"></div>
</div>
<script>
(function () {
  // Accept the assertion from the URL fragment first: unlike the query string,
  // a fragment is never sent to the server and so never lands in access logs
  // or proxy logs. ?token= is still honoured for SIEMs that cannot do better.
  var frag = new URLSearchParams((location.hash || "").replace(/^#/, ""));
  var qs   = new URLSearchParams(location.search);
  var token = frag.get("token") || qs.get("token") || "";
  var next  = frag.get("next")  || qs.get("next")  || "/";
  // Only ever redirect somewhere on this origin.
  if (!/^\\/(?!\\/)/.test(next)) next = "/";

  function fail(m) {
    document.getElementById("sp").style.display = "none";
    document.getElementById("msg").textContent = "Sign-in failed";
    document.getElementById("err").textContent = m;
  }
  function goHome() {
    var e = document.getElementById("err");
    var a = document.createElement("div");
    a.style.marginTop = "16px";
    a.innerHTML = '<a href="/" style="color:#4da3ff;text-decoration:none">' +
                  '&larr; Back to the dashboard</a>';
    e.parentNode.appendChild(a);
  }
  if (!token) {
    // Landing here with no assertion is usually NOT a failure: the analyst
    // opened /auth/sso directly, or was bounced here by a 401 that has since
    // been resolved (e.g. enforcement was turned back off). Stranding them on a
    // dead "Sign-in failed" screen with no way back is the worst outcome — it
    // looks like the whole dashboard is down. So: if the dashboard isn't
    // gated, just go there; if it is, say plainly what to do and always offer
    // a link home.
    fetch("/api/auth/me", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (me) {
        if (!me.enforce || me.authenticated) { location.replace(next || "/"); return; }
        fail("Sign in from your SIEM portal to continue.");
        goHome();
      })
      .catch(function () { fail("No SSO assertion was supplied."); goHome(); });
    return;
  }

  fetch("/api/auth/sso/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ token: token })
  }).then(function (r) {
    return r.json().then(function (b) { return { ok: r.ok, body: b }; });
  }).then(function (res) {
    if (!res.ok) { fail(res.body.error || "Verification failed."); return; }
    // Drop the assertion from the address bar before navigating on, so it
    // does not persist in browser history.
    history.replaceState(null, "", "/auth/sso");
    location.replace(next);
  }).catch(function (e) { fail(String(e)); });
})();
</script>
"""


@bp.route("/auth/sso")
def sso_landing():
    return Response(_LANDING_HTML, mimetype="text/html")


def init_auth(flask_app, raw_cfg: dict | None) -> dict:
    """Wire the auth module into a Flask app. Returns the effective config.

    Raises AuthConfigError for an unsafe config — that is deliberate: a
    misconfigured auth layer should stop the server at boot, not run open.
    """
    cfg = load_auth_config(raw_cfg)
    _STATE["cfg"] = cfg
    _STATE["secret"] = get_secret(cfg)

    if cfg.get("enabled"):
        try:
            _STATE["store"] = AuthStore(cfg["auth_db"])
        except Exception as e:
            log.error("auth store init failed (%s): SSO will report not-ready", e)
            _STATE["store"] = None

        if cfg.get("enforce"):
            ok, why = can_authenticate()
            if not ok:
                # Refuse to run "enforcing but unable to authenticate anyone" —
                # that is a self-inflicted outage, not a security posture.
                raise AuthConfigError(
                    f"auth.enforce is true but nobody could log in: {why}. "
                    "Create a local admin (python3 ueba_auth.py create-admin) "
                    "or fix SSO, or set auth.enforce: false."
                )

    flask_app.register_blueprint(bp)
    install_request_gate(flask_app)

    ready, reason = is_ready()
    log.info("auth: enabled=%s enforce=%s ready=%s (%s)",
             cfg.get("enabled"), cfg.get("enforce"), ready, reason)
    return cfg


# ── CLI ──────────────────────────────────────────────────────────────────────
#
# The bootstrap and recovery path. Deliberately the ONLY way the first admin can
# come into existence: a security product that ships with default credentials is
# a liability, and one whose only admin lives behind the login it guards is a
# support call waiting to happen.
#
#   python3 ueba_auth.py create-admin  --username alice
#   python3 ueba_auth.py set-password  --username alice
#   python3 ueba_auth.py set-role      --username alice --role analyst
#   python3 ueba_auth.py unlock        --username alice
#   python3 ueba_auth.py list-users
#   python3 ueba_auth.py check

import getpass
import sys


def _cli_store(args):
    cfg = dict(DEFAULTS)
    raw = None
    if args.config:
        try:
            import yaml
            with open(args.config, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
        except Exception as e:
            print(f"warning: could not read {args.config}: {e}", file=sys.stderr)
    if raw:
        cfg = load_auth_config(raw)
    db = args.db or cfg["auth_db"]
    _STATE["cfg"] = cfg
    _STATE["store"] = AuthStore(db)
    return _STATE["store"], db


def _prompt_password(confirm=True) -> str:
    pw = getpass.getpass("Password: ")
    problem = password_problem(pw)
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        raise SystemExit(2)
    if confirm and getpass.getpass("Confirm password: ") != pw:
        print("error: passwords do not match", file=sys.stderr)
        raise SystemExit(2)
    return pw


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="UEBA local account administration")
    ap.add_argument("--config", default="ueba_config.yaml",
                    help="ueba_config.yaml, to locate auth.auth_db")
    ap.add_argument("--db", default=None, help="override the auth DB path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, helptext in (("create-admin", "create a local admin account"),
                           ("set-password", "set or reset a password"),
                           ("unlock",       "clear a lockout and failed-login count")):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--username", required=True)

    sp = sub.add_parser("create-user", help="create a local account with a role")
    sp.add_argument("--username", required=True)
    sp.add_argument("--role", default="viewer", choices=list(ROLES))

    sp = sub.add_parser("set-role", help="change a user's role")
    sp.add_argument("--username", required=True)
    sp.add_argument("--role", required=True, choices=list(ROLES))

    sub.add_parser("list-users", help="list every account")
    sub.add_parser("check", help="report whether anyone could log in if enforcing")

    args = ap.parse_args(argv)
    store, db = _cli_store(args)

    if args.cmd in ("create-admin", "create-user"):
        role = "admin" if args.cmd == "create-admin" else args.role
        pw = _prompt_password()
        try:
            u = store.create_local_user(args.username, pw, role)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"created {u['username']} (role={u['role']}, sub={u['sub']}) in {db}")
        return 0

    if args.cmd == "set-password":
        pw = _prompt_password()
        if not store.set_password(local_sub(args.username), pw):
            print(f"error: no local user {args.username!r}", file=sys.stderr)
            return 1
        store.revoke_all_for(local_sub(args.username))
        print(f"password updated for {args.username}; their sessions were revoked")
        return 0

    if args.cmd == "set-role":
        u = store.update_user(local_sub(args.username), role=args.role)
        if not u:
            print(f"error: no local user {args.username!r}", file=sys.stderr)
            return 1
        print(f"{args.username} is now {u['role']}")
        return 0

    if args.cmd == "unlock":
        u = store.update_user(local_sub(args.username), unlock=True)
        if not u:
            print(f"error: no local user {args.username!r}", file=sys.stderr)
            return 1
        print(f"{args.username} unlocked")
        return 0

    if args.cmd == "list-users":
        users = store.list_users()
        if not users:
            print(f"(no accounts in {db})")
            return 0
        print(f"{'USERNAME':<24}{'ROLE':<10}{'TYPE':<8}{'ACTIVE':<8}{'PW':<5}LAST LOGIN")
        for u in users:
            print(f"{(u['username'] or '')[:23]:<24}{u['role']:<10}"
                  f"{'local' if is_local_sub(u['sub']) else 'sso':<8}"
                  f"{'yes' if u['active'] else 'no':<8}"
                  f"{'yes' if u['has_password'] else '-':<5}{u['last_login'] or '-'}")
        return 0

    if args.cmd == "check":
        ok, why = can_authenticate()
        print(f"{'OK' if ok else 'NOT SAFE'}: {why}")
        print("auth.enforce can be turned on." if ok else
              "Do NOT enable auth.enforce yet — nobody could log in.")
        return 0 if ok else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
