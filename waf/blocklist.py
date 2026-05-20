from waf.database import get_conn


def is_blocked(ip: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT ip FROM blocklist WHERE ip = ?", (ip,)
        ).fetchone()
    return row is not None


def block_ip(ip: str, reason: str) -> None:
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO blocklist (ip, reason, hit_count)
            VALUES (?, ?, 1)
            ON CONFLICT(ip) DO UPDATE SET
                hit_count = hit_count + 1,
                reason = excluded.reason
        """, (ip, reason))
        conn.commit()


def unblock_ip(ip: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
        conn.commit()


def get_blocklist() -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM blocklist ORDER BY blocked_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_violation_count(ip: str) -> int:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) as count FROM request_log WHERE ip = ? AND blocked = 1",
            (ip,)
        ).fetchone()
    return row["count"] if row else 0