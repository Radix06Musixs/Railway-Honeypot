"""Aurora Bank (demo) with a hidden AI-based adaptive honeypot.

Real customers see a normal bank.  Anything that looks like probing (decoy paths, SQLi, fake ports,
scanner behaviour...) is silently routed into the deception layer and scored by the ML engine.

    python app.py                      # http://127.0.0.1:5000      SOC dashboard: /soc?key=kaish-soc
    HOST=0.0.0.0 python app.py         # ONLY on an isolated lab network
"""
import json
import os
import time
from collections import defaultdict, deque

from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler
import secrets

from flask import (Flask, Response, flash, g, jsonify, redirect, render_template, request,
                   session, url_for)

import bank
import deception
import ports
import telemetry
from engine import Engine

PRODUCTION = bool(os.environ.get("RAILWAY_ENVIRONMENT") or os.environ.get("APP_ENV") == "production")
HOST = os.environ.get("HOST", "0.0.0.0" if PRODUCTION else "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))
SOC_KEY = os.environ.get("SOC_KEY", "kaish-soc")
SECRET_KEY = os.environ.get("SECRET_KEY", "demo-only-change-me")
# Lab labels / actor headers are only honoured outside production (a public attacker could forge them).
LAB_EVAL = os.environ.get("LAB_EVAL", "0" if PRODUCTION else "1") == "1"
if PRODUCTION and (SOC_KEY == "kaish-soc" or SECRET_KEY == "demo-only-change-me" or len(SOC_KEY) < 16):
    raise SystemExit("Refusing to start in production: set strong SECRET_KEY and SOC_KEY (16+ chars) environment variables.")

class QuietHandler(WSGIRequestHandler):
    """Stop the dev server from adding its own 'Server: Werkzeug/...' header next to the fake one."""
    def send_header(self, keyword, value):
        if keyword.lower() == "server" and str(value).startswith("Werkzeug"):
            return
        super().send_header(keyword, value)


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1" if PRODUCTION else "0") == "1")
# Behind Railway's proxy the real client IP is in X-Forwarded-For; without this every visitor shares one session.
_hops = int(os.environ.get("TRUST_PROXY_HOPS", "1" if PRODUCTION else "0"))
if _hops:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_hops, x_proto=_hops, x_host=_hops)

_rl = defaultdict(deque)


def rate_ok(key, limit, window=3600):
    """Tiny in-memory rate limiter so a public deployment can't be flooded with sign-ups / reset mails."""
    now, q = time.time(), _rl[key]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True

print("[engine] training ML models (a few seconds)...")
engine = Engine()
print(f"[engine] primary model: {engine.det.primary}  (trained in {engine.det.train_seconds}s)")

bank.init()


# ----------------------------------------------------------------------------- honeypot hooks
def _soc_ok():
    return (request.args.get("key") or request.cookies.get("soc_key")) == SOC_KEY


@app.before_request
def hp_before():
    p = request.path
    g.s = None
    if p.startswith("/static") or p.startswith("/soc") or p == "/healthz":
        return
    ua = request.headers.get("User-Agent", "")
    truth = request.headers.get("X-Lab-Truth") if LAB_EVAL else None
    actor = request.headers.get("X-Demo-Actor") if LAB_EVAL else None   # forgeable, so lab-only
    s = engine.session_for(request.remote_addr, actor, truth)
    g.s, g.decoy, g.detail = s, False, ""
    raw = request.get_data(parse_form_data=True, as_text=True)[:2000]
    body = f"{dict(request.form)} {raw}"
    hdr = " ".join(f"{k}:{v}" for k, v in request.headers if k.lower() not in ("x-lab-truth", "x-demo-actor"))
    engine.observe_request(s, request.method, p, request.query_string.decode(errors="ignore"), body, ua, hdr)
    engine.latency(s)


@app.after_request
def hp_after(resp):
    s = getattr(g, "s", None)
    if s is None:
        return resp
    # Believable fake stack fingerprint, consistent from the first byte; it only changes when the
    # engine deliberately rotates the profile (deception evolution), never because a session got flagged.
    resp.headers["Server"] = s.profile["server"]
    resp.headers["X-Powered-By"] = s.profile["php"]
    engine.observe_response(s, request.method, request.path, resp.status_code,
                            request.headers.get("User-Agent", ""), g.detail, g.decoy)
    return resp


def _decoy(body, status, mimetype, kind):
    g.decoy, g.detail = True, kind
    return Response(body, status=status, mimetype=mimetype)


@app.errorhandler(404)
def not_found(_):
    s = g.s
    if s is not None:
        res = deception.handle(request.path, request.method, request.form, s, engine)
        if res:
            return _decoy(*res)
    return render_template("404.html"), 404


@app.route("/console/vm/<vmid>/exec", methods=["POST"])
def vm_exec(vmid):
    s = g.s
    cmd = (request.get_json(silent=True) or {}).get("cmd", "")[:200]
    engine.note_command(s, cmd)
    g.decoy, g.detail = True, "emulated-shell"
    return jsonify({"out": deception.shell(cmd, s, engine)})


# ----------------------------------------------------------------------------- the real bank
def current_user():
    uid = session.get("uid")
    return bank.user_view(uid) if uid else None


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals.update(csrf_token=csrf_token, rupees=bank.rupees, current_user=current_user)


@app.route("/healthz")
def healthz():
    return "ok"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    error, form = None, {}
    if request.method == "POST" and not rate_ok(("reg", request.remote_addr), 10):
        error = "Too many sign-up attempts from your network. Please try again later."
    elif request.method == "POST":
        form = request.form
        uid, error = bank.register(form.get("username", ""), form.get("email", ""), form.get("full_name", ""),
                                   form.get("password", ""), form.get("confirm", ""))
        if uid:
            session.clear()
            session["uid"] = uid
            flash("Welcome to Aurora Bank! Your account is open and a demo bonus of Rs 10,000 was credited.")
            return redirect(url_for("dashboard"))
    return render_template("register.html", error=error, form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        s = g.s
        user, pw = request.form.get("username", ""), request.form.get("password", "")
        bait = user.lower() in ("admin", "root", "administrator", "dbadmin") or s.sqli or s.token_used
        if bait:   # hidden honeypot: a believable (fake) auth bypass
            engine.note_credential(s, user)
            return _decoy(deception.admin_panel(s, engine), 200, "text/html", "fake-auth-bypass")
        uid = bank.authenticate(user, pw)
        if uid:
            session.clear()
            session["uid"] = uid
            return redirect(url_for("dashboard"))
        engine.note_login_fail(s)
        engine.note_credential(s, user)
        error = "Invalid Customer ID or password."
    return render_template("login.html", error=error)


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        ident = request.form.get("identifier", "")
        engine.note_credential(g.s, ident)
        if rate_ok(("forgot", request.remote_addr), 10):
            bank.start_reset(ident)
        session["reset_ident"] = ident.strip()
        flash("If that account exists, a 6-digit code has been e-mailed. (Demo: open the Demo Inbox.)")
        return redirect(url_for("reset"))
    return render_template("forgot.html")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    error = None
    if request.method == "POST":
        ident = request.form.get("identifier", "") or session.get("reset_ident", "")
        ok, msg = bank.finish_reset(ident, request.form.get("otp", ""), request.form.get("password", ""),
                                    request.form.get("confirm", ""))
        if ok:
            session.pop("reset_ident", None)
            flash(msg)
            return redirect(url_for("login"))
        engine.note_login_fail(g.s)     # repeated bad OTPs look like brute-forcing to the detector
        error = msg
    return render_template("reset.html", error=error, ident=session.get("reset_ident", ""))


@app.route("/demo-inbox")
def demo_inbox():
    """Stands in for e-mail delivery so the reset flow can be demoed offline."""
    return render_template("inbox.html", mails=bank.inbox())


@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    return render_template("dashboard.html", u=u, txns=bank.history(u["acct_no"]))


@app.route("/transfer", methods=["POST"])
def transfer():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    if request.form.get("csrf") != session.get("csrf"):
        flash("Session expired, please try again.", "err")
        return redirect(url_for("dashboard"))
    ok, msg = bank.transfer(u["id"], request.form.get("to", ""), request.form.get("amount", ""),
                            request.form.get("note", ""))
    flash(msg, "ok" if ok else "err")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ----------------------------------------------------------------------------- SOC (hidden operator view)
@app.route("/soc")
def soc():
    if not _soc_ok():
        return render_template("404.html"), 404
    resp = Response(render_template("soc.html"))
    resp.set_cookie("soc_key", SOC_KEY, httponly=True, samesite="Strict", secure=app.config["SESSION_COOKIE_SECURE"])
    return resp


@app.route("/soc/api/state")
def soc_state():
    if not _soc_ok():
        return "", 404
    return jsonify(engine.state())


@app.route("/soc/api/reset", methods=["POST"])
def soc_reset():
    if not _soc_ok():
        return "", 404
    engine.reset()
    return jsonify({"ok": True})


@app.route("/soc/report.json")
def soc_report():
    if not _soc_ok():
        return "", 404
    data = {"state": engine.state(), "events": telemetry.all_events()}
    return Response(json.dumps(data, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=honeypot_report.json"})


if os.environ.get("START_PORTS") == "1" and __name__ != "__main__":
    # gunicorn path: the fake TCP listeners only help if your platform can expose raw TCP ports.
    ports.start(engine, HOST)

if __name__ == "__main__":
    started = ports.start(engine, HOST)
    print("[ports] fake services:", ", ".join(f"{p['port']}/{p['service']}" for p in started))
    print(f"[web]   http://{HOST}:{PORT}   |   SOC: http://{HOST}:{PORT}/soc?key={SOC_KEY}")
    app.run(host=HOST, port=PORT, threaded=True, debug=False, request_handler=QuietHandler)
