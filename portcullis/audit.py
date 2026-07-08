import sqlite3


class Audit:
    """Append-only history of detections and response actions, in SQLite.

    Every value reaches SQL through ? placeholders -- never string formatting.
    Usernames come from attacker-controlled log lines; parameterized queries
    are to SQL what list-argv was to subprocess.
    """

    def __init__(self, path):
        # path may be ":memory:" for a throwaway in-RAM database (tests).
        self._conn = sqlite3.connect(path)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                level TEXT NOT NULL,
                weighted_count REAL,
                usernames TEXT
            )"""
        )
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL,
                action TEXT NOT NULL,
                expires_at TEXT,
                operator TEXT NOT NULL
            )"""
        )
        self._conn.commit()

    def record_detection(self, detection):
        self._conn.execute(
            "INSERT INTO detections (ts, ip, level, weighted_count, usernames) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                detection.last_seen.isoformat(),
                detection.ip,
                detection.level.name,
                detection.weighted_count,
                ",".join(sorted(detection.usernames)),
            ),
        )
        self._conn.commit()

    def record_action(self, ip, action, ts, expires_at=None, operator="auto"):
        self._conn.execute(
            "INSERT INTO actions (ts, ip, action, expires_at, operator) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                ts.isoformat(),
                ip,
                action,
                expires_at.isoformat() if expires_at else None,
                operator,
            ),
        )
        self._conn.commit()

    def top_attackers(self, limit=10):
        """[(ip, detection_count, last_seen), ...] most-detected first."""
        cur = self._conn.execute(
            "SELECT ip, COUNT(*) AS n, MAX(ts) FROM detections "
            "GROUP BY ip ORDER BY n DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()

    def recent_actions(self, since=None):
        """[(ts, ip, action, expires_at, operator), ...] oldest first.

        ISO timestamps sort correctly as text, so WHERE ts > ? just works.
        """
        if since is None:
            cur = self._conn.execute(
                "SELECT ts, ip, action, expires_at, operator FROM actions ORDER BY ts"
            )
        else:
            cur = self._conn.execute(
                "SELECT ts, ip, action, expires_at, operator FROM actions "
                "WHERE ts > ? ORDER BY ts",
                (since.isoformat(),),
            )
        return cur.fetchall()

    def close(self):
        self._conn.close()
