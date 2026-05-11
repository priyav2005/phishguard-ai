"""
blacklist.py — PhishGuard AI
SQLite blacklist database — JSON-serializable output, no bytes errors
"""
import sqlite3, os
from datetime import datetime
from urllib.parse import urlparse

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard.db")

# ─── Connection ───────────────────────────────────────────────────────────────
def _conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

# ─── Safe row conversion ──────────────────────────────────────────────────────
def _safe(row):
    if row is None:
        return {}
    d = {}
    for k in row.keys():
        v = row[k]
        if isinstance(v, bytes):
            try:
                v = v.decode("utf-8")
            except:
                v = v.hex()
        if not isinstance(v, (str, int, float, bool, type(None))):
            v = str(v)
        d[k] = v
    return d

# ─── Init ─────────────────────────────────────────────────────────────────────
def _init():
    with _conn() as conn:
        conn.row_factory = sqlite3.Row

        conn.execute("""CREATE TABLE IF NOT EXISTS blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            domain TEXT NOT NULL,
            added_at TEXT NOT NULL,
            source TEXT DEFAULT 'auto-detected',
            confidence REAL DEFAULT 0.0
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT DEFAULT '',
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            confidence REAL DEFAULT 0.0,
            detection_layer TEXT DEFAULT 'ml',
            scanned_at TEXT NOT NULL
        )""")

        conn.execute("""CREATE TABLE IF NOT EXISTS threat_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL UNIQUE,
            phishing_count INTEGER DEFAULT 0,
            safe_count INTEGER DEFAULT 0
        )""")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON blacklist(domain)")

    print("✅ Database initialized")

_init()

# ─── Domain helper ────────────────────────────────────────────────────────────
def _domain(url):
    try:
        host = urlparse(url if url.startswith("http") else "http://" + url).hostname or url
        return host.lower().replace("www.", "")
    except:
        return url

# ─── Check ────────────────────────────────────────────────────────────────────
def is_blacklisted(url):
    with _conn() as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        domain = _domain(url)

        c.execute("SELECT * FROM blacklist WHERE url=? LIMIT 1", (url,))
        row = c.fetchone()
        if row:
            return True, _safe(row)

        c.execute("SELECT * FROM blacklist WHERE domain=? LIMIT 1", (domain,))
        row = c.fetchone()

        return (True, _safe(row)) if row else (False, None)

# ─── Add ──────────────────────────────────────────────────────────────────────
def add_to_blacklist(url, confidence=0.0, source="auto-detected"):
    domain = _domain(url)
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT INTO blacklist (url,domain,added_at,source,confidence) VALUES (?,?,?,?,?)",
                (url, domain, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source, float(confidence))
            )
        return True
    except sqlite3.IntegrityError:
        return False  # already exists

# ─── Remove ───────────────────────────────────────────────────────────────────
def remove_from_blacklist(url):
    with _conn() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM blacklist WHERE url=?", (url,))
        return c.rowcount > 0

# ─── Fetch ────────────────────────────────────────────────────────────────────
def get_blacklist(limit=200):
    with _conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM blacklist ORDER BY added_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_safe(r) for r in rows]

def get_blacklist_count():
    with _conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]

# ─── Log scan ─────────────────────────────────────────────────────────────────
def log_scan(url, result, confidence, detection_layer):
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    today = datetime.now().strftime("%Y-%m-%d")

    with _conn() as conn:
        conn.execute(
            "INSERT INTO scan_history (url,result,confidence,detection_layer,scanned_at) VALUES (?,?,?,?,?)",
            (url, result, float(confidence), detection_layer, now)
        )
        conn.execute(
            "INSERT INTO threat_stats (date,phishing_count,safe_count) VALUES (?,0,0) ON CONFLICT(date) DO NOTHING",
            (today,)
        )
        if result == "phishing":
            conn.execute("UPDATE threat_stats SET phishing_count=phishing_count+1 WHERE date=?", (today,))
        else:
            conn.execute("UPDATE threat_stats SET safe_count=safe_count+1 WHERE date=?", (today,))

# ─── History ──────────────────────────────────────────────────────────────────
def get_recent_scans(limit=100):
    with _conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_safe(r) for r in rows]

# ─── Stats ────────────────────────────────────────────────────────────────────
def get_today_stats():
    today = datetime.now().strftime("%Y-%m-%d")
    with _conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM threat_stats WHERE date=?", (today,)).fetchone()
        return _safe(row) if row else {"date": today, "phishing_count": 0, "safe_count": 0}
