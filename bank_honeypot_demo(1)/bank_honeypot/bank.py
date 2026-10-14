"""The real (fictional) bank: users, accounts, password reset and atomic money transfers.

SQLite-backed, parameterised queries only (the *real* bank is not injectable - the fake
"auth bypass" the attacker sees comes from the honeypot layer, not from a weakness here).
Money is stored as integer paise to avoid float errors.
"""
import os
import random
import re
import secrets
import sqlite3
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

DATA_DIR = os.environ.get("DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "bank.db")
_lock = threading.RLock()
_db = sqlite3.connect(DB_PATH, check_same_thread=False)
_db.row_factory = sqlite3.Row

OTP_TTL = 600          # seconds
OTP_MAX_TRIES = 5
WELCOME_BONUS = 1000000  # Rs 10,000.00 demo opening balance (paise)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def init():
    with _lock:
        _db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
              id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE COLLATE NOCASE,
              email TEXT UNIQUE COLLATE NOCASE, full_name TEXT, pw_hash TEXT, created REAL);
            CREATE TABLE IF NOT EXISTS accounts(
              acct_no TEXT PRIMARY KEY, user_id INTEGER, balance INTEGER NOT NULL CHECK(balance >= 0));
            CREATE TABLE IF NOT EXISTS txns(
              id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, from_acct TEXT, to_acct TEXT,
              amount INTEGER, note TEXT);
            CREATE TABLE IF NOT EXISTS resets(
              id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, otp_hash TEXT, expires REAL,
              tries INTEGER DEFAULT 0, used INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS inbox(
              id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, to_addr TEXT, subject TEXT, body TEXT);
            """
        )
        _db.commit()
        if not _db.execute("SELECT 1 FROM users WHERE username='demo'").fetchone():
            _create("demo", "demo@aurorabank.example", "Demo Customer", "Demo@123", 24831055, seed=True)
            _create("priya", "priya@aurorabank.example", "Priya Nair", "Priya@2026", 5250000, seed=False)


def _new_acct_no():
    while True:
        n = "5" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if not _db.execute("SELECT 1 FROM accounts WHERE acct_no=?", (n,)).fetchone():
            return n


def _create(username, email, full_name, password, balance, seed=False):
    cur = _db.execute("INSERT INTO users(username,email,full_name,pw_hash,created) VALUES(?,?,?,?,?)",
                      (username, email, full_name, generate_password_hash(password), time.time()))
    acct = _new_acct_no()
    _db.execute("INSERT INTO accounts(acct_no,user_id,balance) VALUES(?,?,?)", (acct, cur.lastrowid, balance))
    if seed:
        now = time.time()
        for days, desc, amt in [(2, "Salary - Acme Pvt Ltd", 8500000), (3, "UPI - Grocery", -214050),
                                (5, "Electricity bill", -312000), (7, "Interest credit", 61245)]:
            if amt > 0:
                _db.execute("INSERT INTO txns(ts,from_acct,to_acct,amount,note) VALUES(?,?,?,?,?)",
                            (now - days * 86400, "EXTERNAL", acct, amt, desc))
            else:
                _db.execute("INSERT INTO txns(ts,from_acct,to_acct,amount,note) VALUES(?,?,?,?,?)",
                            (now - days * 86400, acct, "EXTERNAL", -amt, desc))
    _db.commit()
    return cur.lastrowid, acct


# ------------------------------------------------------------------ validation helpers
def password_problem(pw):
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    if not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        return "Password must contain letters and numbers."
    return None


def rupees(paise):
    return f"{paise / 100:,.2f}"


def parse_amount(text):
    """'1,250.50' -> 125050 paise; None if invalid / non-positive / more than 2 decimals."""
    t = (text or "").strip().replace(",", "")
    if not re.fullmatch(r"\d{1,9}(\.\d{1,2})?", t):
        return None
    paise = int(round(float(t) * 100))
    return paise if paise > 0 else None


# ------------------------------------------------------------------ accounts
def register(username, email, full_name, password, confirm):
    username, email, full_name = username.strip(), email.strip(), full_name.strip()
    if not USERNAME_RE.match(username):
        return None, "Customer ID must be 3-20 letters, numbers or underscores."
    if not EMAIL_RE.match(email):
        return None, "Please enter a valid e-mail address."
    if not (2 <= len(full_name) <= 60):
        return None, "Please enter your full name."
    if password != confirm:
        return None, "Passwords do not match."
    prob = password_problem(password)
    if prob:
        return None, prob
    with _lock:
        if _db.execute("SELECT 1 FROM users WHERE username=? OR email=?", (username, email)).fetchone():
            return None, "That Customer ID or e-mail is already registered."
        uid, acct = _create(username, email, full_name, password, WELCOME_BONUS)
        _db.execute("INSERT INTO txns(ts,from_acct,to_acct,amount,note) VALUES(?,?,?,?,?)",
                    (time.time(), "EXTERNAL", acct, WELCOME_BONUS, "Welcome bonus (demo)"))
        _db.commit()
    return uid, None


def authenticate(username, password):
    with _lock:
        r = _db.execute("SELECT id,pw_hash FROM users WHERE username=?", (username.strip(),)).fetchone()
    if r and check_password_hash(r["pw_hash"], password):
        return r["id"]
    return None


def user_view(uid):
    with _lock:
        u = _db.execute("SELECT u.id,u.username,u.full_name,u.email,a.acct_no,a.balance FROM users u "
                        "JOIN accounts a ON a.user_id=u.id WHERE u.id=?", (uid,)).fetchone()
    return dict(u) if u else None


def history(acct, limit=15):
    with _lock:
        rows = _db.execute("SELECT * FROM txns WHERE from_acct=? OR to_acct=? ORDER BY ts DESC, id DESC LIMIT ?",
                           (acct, acct, limit)).fetchall()
    out = []
    for r in rows:
        credit = r["to_acct"] == acct
        other = r["from_acct"] if credit else r["to_acct"]
        out.append({"ts": time.strftime("%d %b %H:%M", time.localtime(r["ts"])), "note": r["note"],
                    "other": other if other != "EXTERNAL" else "", "amount": r["amount"] if credit else -r["amount"]})
    return out


def transfer(uid, to_acct, amount_text, note):
    to_acct = (to_acct or "").strip()
    amount = parse_amount(amount_text)
    if amount is None:
        return False, "Enter a valid amount (e.g. 1500 or 1500.50)."
    if amount > 50000000:
        return False, "Single transfer limit is Rs 5,00,000."
    note = (note or "").strip()[:60] or "Fund transfer"
    with _lock:
        src = _db.execute("SELECT acct_no,balance FROM accounts WHERE user_id=?", (uid,)).fetchone()
        dst = _db.execute("SELECT a.acct_no,u.full_name FROM accounts a JOIN users u ON u.id=a.user_id "
                          "WHERE a.acct_no=?", (to_acct,)).fetchone()
        if not dst:
            return False, "Beneficiary account not found."
        if dst["acct_no"] == src["acct_no"]:
            return False, "You cannot transfer to your own account."
        if src["balance"] < amount:
            return False, "Insufficient balance."
        try:
            cur = _db.execute("UPDATE accounts SET balance=balance-? WHERE acct_no=? AND balance>=?",
                              (amount, src["acct_no"], amount))
            if cur.rowcount != 1:           # debit and credit commit together or not at all
                _db.rollback()
                return False, "Insufficient balance."
            _db.execute("UPDATE accounts SET balance=balance+? WHERE acct_no=?", (amount, dst["acct_no"]))
            _db.execute("INSERT INTO txns(ts,from_acct,to_acct,amount,note) VALUES(?,?,?,?,?)",
                        (time.time(), src["acct_no"], dst["acct_no"], amount, note))
            _db.commit()
        except sqlite3.Error:
            _db.rollback()
            return False, "Transfer failed. Please try again."
    return True, f"Rs {rupees(amount)} sent to {dst['full_name']} ({dst['acct_no']})."


# ------------------------------------------------------------------ forgot password
def start_reset(identifier):
    """Always behaves the same to the caller (no account enumeration). The OTP goes to the demo inbox."""
    ident = (identifier or "").strip()
    with _lock:
        u = _db.execute("SELECT id,email,full_name FROM users WHERE username=? OR email=?", (ident, ident)).fetchone()
        if not u:
            return
        otp = f"{secrets.randbelow(10**6):06d}"
        _db.execute("UPDATE resets SET used=1 WHERE user_id=?", (u["id"],))
        _db.execute("INSERT INTO resets(user_id,otp_hash,expires) VALUES(?,?,?)",
                    (u["id"], generate_password_hash(otp), time.time() + OTP_TTL))
        _db.execute("INSERT INTO inbox(ts,to_addr,subject,body) VALUES(?,?,?,?)",
                    (time.time(), u["email"], "Aurora Bank - password reset code",
                     f"Hello {u['full_name']},\n\nYour one-time code is {otp}. It is valid for 10 minutes.\n"
                     "If you did not ask for this, ignore this e-mail."))
        _db.commit()


def finish_reset(identifier, otp, new_pw, confirm):
    ident = (identifier or "").strip()
    if new_pw != confirm:
        return False, "Passwords do not match."
    prob = password_problem(new_pw)
    if prob:
        return False, prob
    generic = "Invalid or expired code."
    with _lock:
        u = _db.execute("SELECT id FROM users WHERE username=? OR email=?", (ident, ident)).fetchone()
        if not u:
            return False, generic
        r = _db.execute("SELECT * FROM resets WHERE user_id=? AND used=0 ORDER BY id DESC LIMIT 1", (u["id"],)).fetchone()
        if not r or r["expires"] < time.time() or r["tries"] >= OTP_MAX_TRIES:
            return False, generic
        _db.execute("UPDATE resets SET tries=tries+1 WHERE id=?", (r["id"],))
        if not check_password_hash(r["otp_hash"], (otp or "").strip()):
            _db.commit()
            return False, generic
        _db.execute("UPDATE resets SET used=1 WHERE id=?", (r["id"],))
        _db.execute("UPDATE users SET pw_hash=? WHERE id=?", (generate_password_hash(new_pw), u["id"]))
        _db.commit()
    return True, "Password updated. You can log in now."


def inbox(limit=10):
    with _lock:
        rows = _db.execute("SELECT * FROM inbox ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{"ts": time.strftime("%H:%M:%S", time.localtime(r["ts"])), "to": r["to_addr"],
             "subject": r["subject"], "body": r["body"]} for r in rows]
