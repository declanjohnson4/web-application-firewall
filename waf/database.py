import sqlite3
import os

DB_PATH = os.getenv("DB_PATH", "waf.db")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS request_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip          TEXT NOT NULL,
                method      TEXT NOT NULL,
                path        TEXT NOT NULL,
                user_agent  TEXT,
                body        TEXT,
                blocked     INTEGER DEFAULT 0,
                rules_hit   TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocklist (
                ip          TEXT PRIMARY KEY,
                reason      TEXT,
                hit_count   INTEGER DEFAULT 1,
                blocked_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def log_request(ip: str, method: str, path: str,
                user_agent: str, body: str,
                blocked: bool, rules_hit: list) -> None:
    import json
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO request_log (ip, method, path, user_agent, body, blocked, rules_hit)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip, method, path, user_agent, body,
              int(blocked), json.dumps(rules_hit)))
        conn.commit()


def get_recent_logs(limit: int = 100) -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM request_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]