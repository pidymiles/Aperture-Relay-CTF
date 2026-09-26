#!/usr/bin/env python3
"""Initialize Aperture Relay's persistent challenge state."""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import sqlite3
import struct
import zlib
from pathlib import Path


DATA_ROOT = Path(os.environ.get("DATA_ROOT", "/data"))
PORTAL_ROOT = DATA_ROOT / "portal"
STATE_PATH = DATA_ROOT / "state.json"
SSH_LOGIN_PATH = DATA_ROOT / "ssh_login.txt"
DB_PATH = PORTAL_ROOT / "aperture.db"
EVIDENCE_PATH = PORTAL_ROOT / "site-survey.png"
ROOT_FLAG_PATH = Path(os.environ.get("ROOT_FLAG_PATH", "/root/root.txt"))
ACCESS_LOG_PATH = Path(os.environ.get("ACCESS_LOG_PATH", "/var/log/aperture/access.log"))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 220_000)
    return f"{salt.hex()}:{digest.hex()}"


def generated_flag(label: str) -> str:
    return f"flag{{{label}_{secrets.token_hex(8)}}}"


def load_or_create_state() -> dict[str, str]:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())

    state = {
        "flag1": os.environ.get("FLAG1") or generated_flag("encoded_refs_need_authz"),
        "flag2": os.environ.get("FLAG2") or generated_flag("pixels_whisper_in_low_bits"),
        "flag3": os.environ.get("FLAG3") or generated_flag("sudo_pagers_are_root_shells"),
        "ssh_user": "fieldtech",
        "ssh_password": secrets.token_urlsafe(12),
    }
    STATE_PATH.write_text(json.dumps(state, indent=2) + "\n")
    STATE_PATH.chmod(0o600)
    return state


def png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    body = chunk_type + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def make_evidence_png(message: str) -> None:
    width, height = 480, 300
    pixels = bytearray(width * height * 3)

    for y in range(height):
        for x in range(width):
            idx = (y * width + x) * 3
            distance = math.hypot(x - width * 0.62, y - height * 0.46)
            rings = int((math.sin(distance / 11.0) + 1) * 13)
            grid = 20 if x % 40 == 0 or y % 40 == 0 else 0
            sweep = 35 if abs(y - (0.34 * x + 42)) < 2 else 0
            pixels[idx] = min(255, 10 + rings + grid)
            pixels[idx + 1] = min(255, 30 + rings * 2 + grid + sweep)
            pixels[idx + 2] = min(255, 44 + rings * 3 + grid + sweep)

    hidden = ("APERTURE-LSB\n" + message + "\nEND-TRANSMISSION\n\x00").encode()
    # Store each byte least-significant-bit first so common PNG tooling reports
    # the payload as b1,r,lsb,xy.
    bits = "".join(f"{byte:08b}"[::-1] for byte in hidden)
    if len(bits) > width * height:
        raise ValueError("Hidden message is too large for the evidence image")

    # One payload bit is stored in the least significant bit of each red value.
    for offset, bit in enumerate(bits):
        red_index = offset * 3
        pixels[red_index] = (pixels[red_index] & 0xFE) | int(bit)

    scanlines = bytearray()
    stride = width * 3
    for y in range(height):
        scanlines.append(0)  # PNG filter type: None
        start = y * stride
        scanlines.extend(pixels[start : start + stride])

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    png.extend(png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)))
    png.extend(png_chunk(b"tEXt", b"Description\x00Sanitized relay site survey"))
    png.extend(png_chunk(b"IDAT", zlib.compress(bytes(scanlines), 9)))
    png.extend(png_chunk(b"IEND", b""))
    EVIDENCE_PATH.write_bytes(png)


def initialize_database(flag1: str) -> None:
    with sqlite3.connect(DB_PATH) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                team TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                opened_at TEXT NOT NULL,
                summary TEXT NOT NULL,
                restricted_notes TEXT NOT NULL,
                attachment TEXT,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_owner ON incidents(owner_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
            """
        )

        if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            return

        db.executemany(
            "INSERT INTO users (id, username, display_name, team, password_hash) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "analyst", "Alex Mercer", "Relay Operations", hash_password("Analyst!2026")),
                (2, "supervisor", "Samira Vale", "Incident Command", hash_password(secrets.token_urlsafe(24))),
                (3, "facilities", "Casey Lin", "Field Engineering", hash_password(secrets.token_urlsafe(24))),
            ],
        )

        incidents = [
            (7212, 2, "Quarterly relay attestation", "Low", "Closed", "2026-08-24", "Validate ownership metadata for relay assets.", "No discrepancies recorded.", None),
            (7214, 1, "Intermittent telemetry loss", "Medium", "Monitoring", "2026-09-02", "Relay C reports short telemetry gaps during scheduled power transfer.", "Continue packet capture during the next transfer window.", None),
            (7216, 3, "Cooling loop inspection", "Low", "Closed", "2026-09-05", "Inspect cabinet cooling after a transient temperature alarm.", "Airflow returned to baseline after filter replacement.", None),
            (7218, 1, "Archive reconciliation", "High", "Open", "2026-09-08", "Two evidence hashes differ from the archive index. Mirrored evidence remains attached to parent incident AR-7223.", "Recalculate hashes from the original evidence source.", None),
            (7220, 2, "Token rotation exception", "Medium", "Pending", "2026-09-10", "Review a temporary exception for an offline relay controller.", "Exception expires at the next maintenance window.", None),
            (7221, 3, "Survey camera alignment", "Low", "Closed", "2026-09-11", "Correct the north survey camera alignment.", "Alignment verified against fixed reference markers.", None),
            (7223, 2, "Aperture site-survey anomaly", "Critical", "Restricted", "2026-09-12", "A visual survey contains an unexplained low-amplitude signal. Evidence was sealed for incident command.", flag1, "site-survey.png"),
            (7225, 3, "Generator test follow-up", "Medium", "Open", "2026-09-15", "Review voltage drift captured during the monthly generator test.", "Field team assigned for the next service window.", None),
        ]
        db.executemany(
            """
            INSERT INTO incidents
                (id, owner_id, title, severity, status, opened_at, summary, restricted_notes, attachment)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            incidents,
        )


def main() -> None:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    PORTAL_ROOT.mkdir(parents=True, exist_ok=True)
    ROOT_FLAG_PATH.parent.mkdir(parents=True, exist_ok=True)
    ACCESS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    state = load_or_create_state()
    initialize_database(state["flag1"])

    stego_message = "\n".join(
        [
            f"FLAG-2: {state['flag2']}",
            "MAINTENANCE ACCESS",
            "host: use the same host as the web portal",
            "port: 2222",
            f"username: {state['ssh_user']}",
            f"password: {state['ssh_password']}",
        ]
    )
    make_evidence_png(stego_message)

    ROOT_FLAG_PATH.write_text(state["flag3"] + "\n")
    ROOT_FLAG_PATH.chmod(0o600)
    SSH_LOGIN_PATH.write_text(f"{state['ssh_user']}:{state['ssh_password']}\n")
    SSH_LOGIN_PATH.chmod(0o600)
    ACCESS_LOG_PATH.write_text(
        "2026-09-12T03:14:15Z relay-gateway INFO archive mirror started\n"
        "2026-09-12T03:14:19Z relay-gateway WARN evidence hash mismatch\n"
        "2026-09-12T03:14:23Z relay-gateway INFO restricted survey sealed\n"
    )
    ACCESS_LOG_PATH.chmod(0o640)


if __name__ == "__main__":
    main()
