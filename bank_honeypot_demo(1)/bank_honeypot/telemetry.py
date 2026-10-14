"""Stage 3 - Data Collection & Telemetry: a tiny SQLite store for every interaction."""
import os
import sqlite3
import threading
import time

DATA_DIR = os.environ.get("DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "honeypot.db")
MAX_EVENTS = 50000
_inserts = 0
_lock = threading.Lock()
_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row


def init():
    with _lock:
        _conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events(
              id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, session TEXT, ip TEXT,
              source TEXT, method TEXT, path TEXT, status INTEGER, ua TEXT,
              detail TEXT, level INTEGER, score REAL, decoy INTEGER);
            CREATE TABLE IF NOT EXISTS kb(
              key TEXT PRIMARY KEY, count INTEGER, last REAL);
            """
        )
        _conn.commit()


def reset(keep_kb=False):
    with _lock:
        _conn.execute("DELETE FROM events")
        if not keep_kb:
            _conn.execute("DELETE FROM kb")
        _conn.commit()


def log(session, ip, source, method, path, status, ua, detail, level, score, decoy):
    global _inserts
    with _lock:
        _inserts += 1
        if _inserts % 500 == 0:   # keep the table bounded on a public deployment
            _conn.execute("DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - ?", (MAX_EVENTS,))
        _conn.execute(
            "INSERT INTO events(ts,session,ip,source,method,path,status,ua,detail,level,score,decoy)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), session, ip, source, method, (path or "")[:300], status,
             (ua or "")[:200], (detail or "")[:400], level, round(score, 3), int(decoy)),
        )
        _conn.commit()


def recent(n=40):
    with _lock:
        rows = _conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (n,)).fetchall()
    return [dict(r) for r in rows]


def totals():
    with _lock:
        rows = _conn.execute("SELECT source, COUNT(*) c FROM events GROUP BY source").fetchall()
        decoys = _conn.execute("SELECT COUNT(*) FROM events WHERE decoy=1").fetchone()[0]
    out = {r["source"]: r["c"] for r in rows}
    out["total"] = sum(out.values())
    out["decoy_events"] = decoys
    return out


def kb_inc(key):
    with _lock:
        _conn.execute(
            "INSERT INTO kb(key,count,last) VALUES(?,1,?) "
            "ON CONFLICT(key) DO UPDATE SET count=count+1,last=excluded.last",
            (key[:200], time.time()),
        )
        _conn.commit()


def kb_get(key):
    with _lock:
        r = _conn.execute("SELECT count FROM kb WHERE key=?", (key[:200],)).fetchone()
    return r["count"] if r else 0


def kb_top(n=15):
    with _lock:
        rows = _conn.execute("SELECT key,count FROM kb ORDER BY count DESC, last DESC LIMIT ?", (n,)).fetchall()
        size = _conn.execute("SELECT COUNT(*) FROM kb").fetchone()[0]
    return [dict(r) for r in rows], size


def all_events():
    with _lock:
        rows = _conn.execute("SELECT * FROM events ORDER BY id").fetchall()
    return [dict(r) for r in rows]
