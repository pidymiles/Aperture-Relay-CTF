#!/usr/bin/env python3
"""Aperture Relay CTF web portal — intentionally vulnerable."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


APP_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = APP_ROOT / "static"
DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/data"))
PORTAL_ROOT = DATA_ROOT / "portal"
DB_PATH = PORTAL_ROOT / "aperture.db"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))
SESSION_LIFETIME = 8 * 60 * 60


def db_connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, expected = stored.split(":", 1)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 220_000)
        return hmac.compare_digest(digest.hex(), expected)
    except (TypeError, ValueError):
        return False


def incident_token(incident_id: int) -> str:
    return base64.urlsafe_b64encode(str(incident_id).encode()).decode().rstrip("=")


def decode_incident_token(token: str) -> int:
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,24}", token):
        raise ValueError("invalid token")
    padded = token + "=" * (-len(token) % 4)
    decoded = base64.urlsafe_b64decode(padded).decode("ascii")
    if not decoded.isdigit():
        raise ValueError("invalid token")
    return int(decoded)


def document(title: str, body: str, user: sqlite3.Row | None = None) -> bytes:
    account = ""
    if user:
        account = f"""
        <div class="account"><span class="pulse"></span><span>{html.escape(user['display_name'])}</span>
        <form method="post" action="/logout"><button type="submit">Disconnect</button></form></div>"""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · Aperture Relay</title><link rel="stylesheet" href="/static/style.css"></head>
<body><header><a class="brand" href="/dashboard"><span class="mark">A</span><span><strong>APERTURE</strong><small>RELAY CONTROL</small></span></a>{account}</header>
<main>{body}</main><footer>APERTURE RELAY // AUTHORIZED OPERATIONS ONLY</footer></body></html>""".encode()


def login_page(error: str = "") -> bytes:
    alert = f'<div class="alert">{html.escape(error)}</div>' if error else ""
    body = f"""
    <section class="login-layout">
      <div class="hero"><span class="kicker">SIGNAL INTEGRITY PLATFORM</span><h1>Find the signal<br><em>inside the noise.</em></h1>
      <p>Review assigned relay incidents and preserve the evidence chain across operational teams.</p>
      <div class="signal"><i></i><i></i><i></i><i></i><i></i><span>RELAY NETWORK ONLINE</span></div></div>
      <div class="login-card"><span class="kicker">ANALYST CONSOLE</span><h2>Authenticate</h2><p>Use the issued training identity.</p>{alert}
      <form method="post" action="/login"><label>Username<input name="username" required autocomplete="username"></label>
      <label>Password<input name="password" type="password" required autocomplete="current-password"></label>
      <button class="primary" type="submit">Enter relay</button></form>
      <div class="credentials"><strong>Training identity</strong><code>analyst / Analyst!2026</code></div></div>
    </section>"""
    return document("Authenticate", body)


def dashboard_page(user: sqlite3.Row) -> bytes:
    body = f"""
    <section class="dashboard"><div class="page-heading"><div><span class="kicker">{html.escape(user['team']).upper()}</span><h1>Incident relay</h1><p>Records assigned to your current access scope.</p></div>
    <div class="clearance"><small>CLEARANCE</small><strong>ANALYST // TIER 1</strong></div></div>
    <div class="grid"><section class="panel queue"><div class="panel-head"><div><h2>Assigned incidents</h2><p>Open a record to inspect its relay data.</p></div><span id="incident-count">—</span></div><div id="incident-list"><div class="loading">Synchronizing…</div></div></section>
    <aside class="panel detail" id="incident-detail"><div class="empty"><div class="radar"></div><h2>No incident selected</h2><p>Select an assigned incident to inspect the evidence chain.</p></div></aside></div></section>
    <script src="/static/dashboard.js" defer></script>"""
    return document("Incident relay", body, user)


class Handler(BaseHTTPRequestHandler):
    server_version = "ApertureRelay/2.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}", flush=True)

    def send_bytes(self, body: bytes, status: HTTPStatus = HTTPStatus.OK, content_type: str = "text/html; charset=utf-8", headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(payload, separators=(",", ":")).encode(), status, "application/json; charset=utf-8")

    def redirect(self, location: str, cookie: str | None = None) -> None:
        headers = {"Location": location}
        if cookie:
            headers["Set-Cookie"] = cookie
        self.send_bytes(b"", HTTPStatus.SEE_OTHER, headers=headers)

    def user(self) -> sqlite3.Row | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            morsel = cookie.get("aperture_session")
        except Exception:
            return None
        if morsel is None:
            return None
        now = int(time.time())
        with db_connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            return db.execute(
                "SELECT users.id, users.username, users.display_name, users.team FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token=? AND sessions.expires_at>=?",
                (morsel.value, now),
            ).fetchone()

    def require_user(self, api: bool = False) -> sqlite3.Row | None:
        user = self.user()
        if user:
            return user
        if api:
            self.send_json({"error": "authentication_required"}, HTTPStatus.UNAUTHORIZED)
        else:
            self.redirect("/")
        return None

    def read_form(self) -> dict[str, str] | None:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if size <= 0 or size > 65536:
            self.send_json({"error": "invalid_request"}, HTTPStatus.BAD_REQUEST)
            return None
        values = parse_qs(self.rfile.read(size).decode(errors="replace"), keep_blank_values=True)
        return {key: entries[0] for key, entries in values.items()}

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/healthz":
            self.send_json({"status": "ok"})
            return
        if path == "/":
            self.redirect("/dashboard") if self.user() else self.send_bytes(login_page())
            return
        if path == "/dashboard":
            user = self.require_user()
            if user:
                self.send_bytes(dashboard_page(user))
            return
        if path == "/static/style.css":
            self.send_bytes((STATIC_ROOT / "style.css").read_bytes(), content_type="text/css; charset=utf-8")
            return
        if path == "/static/dashboard.js":
            self.send_bytes((STATIC_ROOT / "dashboard.js").read_bytes(), content_type="application/javascript; charset=utf-8")
            return
        if path == "/api/incidents":
            user = self.require_user(api=True)
            if not user:
                return
            with db_connect() as db:
                rows = db.execute("SELECT id,title,severity,status,opened_at FROM incidents WHERE owner_id=? ORDER BY opened_at DESC", (user["id"],)).fetchall()
            incidents = [{**dict(row), "reference": f"AR-{row['id']}", "object_token": incident_token(row["id"])} for row in rows]
            self.send_json({"incidents": incidents, "count": len(incidents)})
            return
        match = re.fullmatch(r"/api/incidents/([A-Za-z0-9_-]+)", path)
        if match:
            user = self.require_user(api=True)
            if not user:
                return
            try:
                incident_id = decode_incident_token(match.group(1))
            except (ValueError, UnicodeError):
                self.send_json({"error": "invalid_reference"}, HTTPStatus.BAD_REQUEST)
                return
            with db_connect() as db:
                # INTENTIONAL CTF FLAW: the opaque-looking token is decoded, but
                # the lookup never binds the object to the authenticated owner.
                row = db.execute(
                    "SELECT incidents.*,users.display_name AS owner FROM incidents JOIN users ON users.id=incidents.owner_id WHERE incidents.id=?",
                    (incident_id,),
                ).fetchone()
            if not row:
                self.send_json({"error": "incident_not_found"}, HTTPStatus.NOT_FOUND)
                return
            result = dict(row)
            result["reference"] = f"AR-{row['id']}"
            result["attachment_url"] = f"/api/attachments/{row['attachment']}" if row["attachment"] else None
            result.pop("owner_id", None)
            self.send_json({"incident": result})
            return
        attachment = re.fullmatch(r"/api/attachments/([A-Za-z0-9._-]+)", path)
        if attachment:
            if not self.require_user(api=True):
                return
            filename = attachment.group(1)
            if filename != "site-survey.png":
                self.send_json({"error": "attachment_not_found"}, HTTPStatus.NOT_FOUND)
                return
            payload = (PORTAL_ROOT / filename).read_bytes()
            self.send_bytes(payload, content_type="image/png", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
            return
        self.send_bytes(document("Not found", '<section class="missing"><h1>404</h1><p>Relay path not found.</p></section>'), HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/login":
            form = self.read_form()
            if form is None:
                return
            with db_connect() as db:
                user = db.execute("SELECT id,password_hash FROM users WHERE username=?", (form.get("username", "")[:100],)).fetchone()
                if not user or not verify_password(form.get("password", "")[:200], user["password_hash"]):
                    self.send_bytes(login_page("Authentication failed."), HTTPStatus.UNAUTHORIZED)
                    return
                token = secrets.token_urlsafe(32)
                db.execute("INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)", (token, user["id"], int(time.time()) + SESSION_LIFETIME))
            self.redirect("/dashboard", f"aperture_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_LIFETIME}")
            return
        if path == "/logout":
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
                morsel = cookie.get("aperture_session")
                if morsel:
                    with db_connect() as db:
                        db.execute("DELETE FROM sessions WHERE token=?", (morsel.value,))
            except Exception:
                pass
            self.redirect("/", "aperture_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            return
        self.send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)


def main() -> None:
    server = HTTPServer((HOST, PORT), Handler)
    print(f"Aperture Relay listening on http://{HOST}:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
