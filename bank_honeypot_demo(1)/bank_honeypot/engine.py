"""Adaptive Honeypot Engine: session tracking, ML scoring, deception levels, feedback loop,
honeytokens and the resilience score.  (Flowchart stages 2, 4, 5, 6.)"""
import collections
import hashlib
import random
import re
import statistics
import threading
import time
import uuid

import telemetry
from ml import FEATURES, Detector

SCANNER_UA = re.compile(r"sqlmap|nikto|nmap|gobuster|dirbuster|dirb|wfuzz|masscan|zgrab|nuclei|hydra|"
                        r"acunetix|burp|feroxbuster|ffuf", re.I)
SENSITIVE = re.compile(r"\.env|\.git|phpmyadmin|wp-(login|admin)|/admin|backup|\.sql|config|actuator|"
                       r"server-status|console|etc/passwd|\.aws|id_rsa|swagger|internal|debug|shell|"
                       r"cgi-bin|\.bak|\.zip|/vm", re.I)
SQLI = re.compile(r"union(\s|\+|%20)+select|or(\s|\+|%20)+1=1|'(\s|\+|%20)*or(\s|\+|%20)|sleep\(|benchmark\(|"
                  r"drop(\s|\+|%20)+table|--(\s|\+|%20|$)|;--|/\*", re.I)
TRAVERSAL = re.compile(r"\.\./|%2e%2e|/etc/passwd|\\windows\\", re.I)

PROFILES = [
    {"os": "Ubuntu 18.04.6 LTS", "kernel": "4.15.0-197-generic", "server": "Apache/2.4.29 (Ubuntu)",
     "php": "PHP/7.2.24", "db": "5.7.33-0ubuntu0.18.04.1", "ssh": "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7"},
    {"os": "CentOS Linux 7 (Core)", "kernel": "3.10.0-1160.el7.x86_64", "server": "Apache/2.4.6 (CentOS)",
     "php": "PHP/5.4.16", "db": "5.5.68-MariaDB", "ssh": "SSH-2.0-OpenSSH_7.4"},
    {"os": "Debian GNU/Linux 10 (buster)", "kernel": "4.19.0-21-amd64", "server": "nginx/1.14.2",
     "php": "PHP/7.3.31", "db": "10.3.31-MariaDB-0+deb10u1", "ssh": "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"},
    {"os": "Ubuntu 20.04.6 LTS", "kernel": "5.4.0-169-generic", "server": "Apache/2.4.41 (Ubuntu)",
     "php": "PHP/7.4.3", "db": "8.0.35-0ubuntu0.20.04.1", "ssh": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9"},
]


class Session:
    def __init__(self, key, ip, actor):
        self.id = hashlib.sha1(key.encode()).hexdigest()[:8]
        self.key, self.ip, self.actor = key, ip, actor
        self.seed = random.randrange(1 << 30)
        self.first = self.last = time.time()
        self.stamps = collections.deque(maxlen=400)
        self.gaps = collections.deque(maxlen=20)
        self.paths, self.methods, self.uas = set(), set(), []
        self.reqs = self.n404 = self.sensitive = self.scanner_ua = 0
        self.login_fails = self.sqli = self.traversal = self.ua_changes = 0
        self.decoy_hits = self.port_hits = self.commands = 0
        self.path_counts = collections.Counter()
        self.level, self.score, self.max_level = 0, 0.0, 0
        self.profile_idx = self.seed % len(PROFILES)
        self.rotations = 0
        self.truth = None          # lab-evaluation label only; never used for decisions
        self.flagged_at = None     # request index when first flagged
        self.token_used = False
        self.persona = "unknown"
        self.cwd = "/var/www"
        self.credentials = set()

    @property
    def profile(self):
        return PROFILES[self.profile_idx]


class Engine:
    def __init__(self):
        telemetry.init()
        self.det = Detector().train()
        self.sessions = {}
        self.lock = threading.RLock()
        self.tokens = {}           # honeytoken fragment -> (session id, kind)
        self.insights = collections.deque(maxlen=30)
        self.evolutions = 0
        self.port_info = []        # filled by ports.py

    # ------------------------------------------------------------ sessions
    def session_for(self, ip, actor=None, truth=None):
        key = f"{ip}|{actor}" if actor else ip
        with self.lock:
            s = self.sessions.get(key)
            if not s:
                if len(self.sessions) >= 5000:   # bound memory on a public deployment
                    oldest = min(self.sessions.values(), key=lambda x: x.last)
                    self.sessions.pop(oldest.key, None)
                s = self.sessions[key] = Session(key, ip, actor)
            if truth in ("attacker", "benign") and s.truth is None:
                s.truth = truth
            return s

    def session_by_ip(self, ip):
        with self.lock:
            cands = [s for s in self.sessions.values() if s.ip == ip]
            if cands:
                return max(cands, key=lambda s: s.last)
            return self.session_for(ip)

    # ------------------------------------------------------------ scoring
    def features(self, s):
        now = time.time()
        recent = sum(1 for t in s.stamps if now - t <= 60)
        n = max(s.reqs, 1)
        vec = {
            "req_count": s.reqs, "req_rate": recent,
            "unique_paths": len(s.paths), "ratio_404": s.n404 / n,
            "sensitive_ratio": s.sensitive / n, "scanner_ua": 1 if s.scanner_ua else 0,
            "login_fails": s.login_fails, "method_div": len(s.methods) or 1,
            "sqli_hits": s.sqli, "traversal_hits": s.traversal,
            "mean_gap": statistics.mean(s.gaps) if s.gaps else 30.0,
            "ua_changes": s.ua_changes, "decoy_hits": s.decoy_hits, "port_hits": s.port_hits,
        }
        return [vec[f] for f in FEATURES]

    def rescore(self, s):
        p = self.det.predict(self.features(s)) if s.reqs >= 3 or s.port_hits or s.decoy_hits else 0.0
        # Hybrid: hard evidence floors (a real customer never touches decoys / fake ports / honeytokens)
        if s.token_used:
            p = 1.0
        if s.port_hits:
            p = max(p, .75)
        if s.decoy_hits:
            p = max(p, .70 + min(.2, .03 * s.decoy_hits))
        if s.sqli >= 2 or s.traversal >= 1:
            p = max(p, .65)
        s.score = round(p, 3)
        lvl = 3 if p >= .85 else 2 if p >= .6 else 1 if p >= .35 else 0
        s.level = max(s.level, lvl)  # deception never relaxes within a session
        if s.level > s.max_level:
            s.max_level = s.level
            if s.flagged_at is None and s.score >= .5:
                s.flagged_at = s.reqs
        if s.flagged_at is None and s.score >= .5:
            s.flagged_at = s.reqs
        self._classify(s)

    def _classify(self, s):
        if s.score < .5:
            s.persona = "benign"
        elif s.login_fails >= 20:
            s.persona = "credential brute-forcer"
        elif s.ua_changes >= 1 and (s.decoy_hits or s.port_hits):
            s.persona = "adaptive / agentic attacker"
        elif s.sqli >= 5:
            s.persona = "injection tool"
        elif s.scanner_ua or (s.n404 / max(s.reqs, 1) > .4 and len(s.stamps) > 20) or \
                (len(s.paths) > 15 and len(s.stamps) > 20):
            s.persona = "automated scanner"
        else:
            s.persona = "recon / low-and-slow"

    # ------------------------------------------------------------ observe
    def observe_request(self, s, method, path, query, body, ua, headers_blob):
        now = time.time()
        with self.lock:
            if s.reqs:
                s.gaps.append(now - s.last)
            s.last = now
            s.stamps.append(now)
            s.reqs += 1
            s.methods.add(method)
            s.paths.add(path)
            s.path_counts[path] += 1
            if SENSITIVE.search(path):
                s.sensitive += 1
            if SCANNER_UA.search(ua or ""):
                if not s.scanner_ua:
                    telemetry.kb_inc("ua:" + (SCANNER_UA.search(ua).group(0).lower()))
                s.scanner_ua = 1
            if s.uas and ua != s.uas[-1]:
                s.ua_changes += 1
                if s.level >= 1:
                    self._rotate(s, "attacker switched tooling (User-Agent changed)")
            if not s.uas or ua != s.uas[-1]:
                s.uas.append(ua)
            blob = f"{path}?{query} {body}"
            if SQLI.search(blob):
                s.sqli += 1
                telemetry.kb_inc("payload:sqli")
            if TRAVERSAL.search(blob):
                s.traversal += 1
                telemetry.kb_inc("payload:traversal")
            full = (blob + " " + headers_blob).lower()
            for frag, (sid, kind) in list(self.tokens.items()):
                if frag in full:
                    s.token_used = True
                    s.credentials.add(kind)
                    self.insight(f"Honeytoken '{kind}' (issued to session {sid}) was REUSED by session {s.id} "
                                 f"- attacker is replaying harvested fake credentials")
                    telemetry.kb_inc("honeytoken:" + kind)
            if s.path_counts[path] == 3 and s.decoy_hits:
                self._rotate(s, f"decoy {path} fingerprinted by repeated probing")
            self.rescore(s)

    def observe_response(self, s, method, path, status, ua, detail, decoy):
        with self.lock:
            if status == 404:
                s.n404 += 1
            if decoy:
                s.decoy_hits += 1
                if path != "/login":  # real route used as a bait (fake auth bypass) - not a decoy path
                    telemetry.kb_inc("decoy_path:" + path[:80])
            self.rescore(s)
            telemetry.log(s.id, s.ip, "http", method, path, status, ua, detail, s.level, s.score, decoy)

    def note_login_fail(self, s):
        with self.lock:
            s.login_fails += 1

    def note_credential(self, s, user):
        with self.lock:
            if user:
                telemetry.kb_inc("cred_tried:" + user[:40])

    def note_command(self, s, cmd, source="shell"):
        with self.lock:
            s.commands += 1
            s.decoy_hits += 1
            self.rescore(s)
            telemetry.log(s.id, s.ip, source, "CMD", cmd, 200, "", "emulated shell", s.level, s.score, 1)
            telemetry.kb_inc("cmd:" + (cmd.split() or ["?"])[0][:30])

    def note_port(self, ip, port, service, data):
        s = self.session_by_ip(ip)
        with self.lock:
            s.port_hits += 1
            s.last = time.time()
            full = (data or "").lower()
            for frag, (sid, kind) in list(self.tokens.items()):
                if frag in full:
                    s.token_used = True
                    self.insight(f"Honeytoken '{kind}' replayed against fake {service} port {port}")
            self.rescore(s)
            telemetry.log(s.id, ip, "port", service.upper(), f":{port}", 0, "", (data or "")[:300],
                          s.level, s.score, 1)
            telemetry.kb_inc(f"port:{port}/{service}")

    # ------------------------------------------------------------ adaptation
    def _rotate(self, s, reason):
        s.profile_idx = (s.profile_idx + 1) % len(PROFILES)
        s.rotations += 1
        self.evolutions += 1
        self.insight(f"Deception evolved for session {s.id}: {reason} -> now emulating "
                     f"{s.profile['os']} / {s.profile['server']}")

    def insight(self, text):
        self.insights.appendleft({"ts": time.time(), "text": text})

    def mint_token(self, s, kind):
        frag = hashlib.md5(f"{s.seed}{kind}{len(self.tokens)}{time.time()}".encode()).hexdigest()[:8]
        self.tokens[frag] = (s.id, kind)
        while len(self.tokens) > 20000:           # drop oldest tokens (dicts keep insertion order)
            self.tokens.pop(next(iter(self.tokens)))
        return frag

    def vm_count(self):
        with self.lock:
            active = sum(1 for s in self.sessions.values() if s.level >= 2 and time.time() - s.last < 300)
        return min(12, 4 + 2 * active)   # dynamic service scaling

    def latency(self, s):
        """Behaviour emulation: believable response jitter on deeper deception levels."""
        if s.level >= 2:
            time.sleep(random.uniform(.05, .35))

    # ------------------------------------------------------------ analytics / output
    def live_eval(self):
        from sklearn.metrics import roc_auc_score
        with self.lock:
            lab = [s for s in self.sessions.values() if s.truth and s.reqs >= 3]
        if not lab:
            return None
        tp = sum(1 for s in lab if s.truth == "attacker" and s.score >= .5)
        fn = sum(1 for s in lab if s.truth == "attacker" and s.score < .5)
        fp = sum(1 for s in lab if s.truth == "benign" and s.score >= .5)
        tn = sum(1 for s in lab if s.truth == "benign" and s.score < .5)
        n = len(lab)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        auc = None
        y = [1 if s.truth == "attacker" else 0 for s in lab]
        if 0 < sum(y) < n:
            auc = round(roc_auc_score(y, [s.score for s in lab]), 3)
        return {"sessions": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "accuracy": round((tp + tn) / n, 3),
                "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3), "roc_auc": auc}

    def resilience(self):
        with self.lock:
            sess = list(self.sessions.values())
        attackers = [s for s in sess if (s.truth == "attacker") or (s.truth is None and s.score >= .5)]
        if not attackers:
            return {"score": None, "level": "Insufficient data", "components": {}}
        flagged = [s for s in attackers if s.score >= .5]
        det = len(flagged) / len(attackers)
        idx = [s.flagged_at for s in flagged if s.flagged_at]
        speed = 1 - min(1, (statistics.mean(idx) if idx else 30) / 30)
        engage = min(1, statistics.mean([s.decoy_hits + s.port_hits for s in flagged] or [0]) / 25)
        adapters = [s for s in attackers if s.ua_changes > 0]
        adapt = (sum(1 for s in adapters if s.score >= .5) / len(adapters)) if adapters else 1.0
        f1 = self.det.primary_f1
        score = 100 * (.30 * det + .20 * speed + .20 * engage + .15 * adapt + .15 * f1)
        level = "High" if score >= 75 else "Medium" if score >= 50 else "Low"
        return {"score": round(score, 1), "level": level, "components": {
            "Detection rate (30%)": round(det, 2), "Detection speed (20%)": round(speed, 2),
            "Attacker engagement depth (20%)": round(engage, 2),
            "Adaptation resistance (15%)": round(adapt, 2), "ML F1 (15%)": round(f1, 2)}}

    def state(self):
        with self.lock:
            sess = sorted(self.sessions.values(), key=lambda s: -s.last)[:25]
            rows = [{"id": s.id, "ip": s.ip, "actor": s.actor or "-", "level": s.level, "score": s.score,
                     "persona": s.persona, "reqs": s.reqs, "decoys": s.decoy_hits, "ports": s.port_hits,
                     "cmds": s.commands, "ua_changes": s.ua_changes, "rotations": s.rotations,
                     "token": s.token_used, "truth": s.truth or "-", "profile": s.profile["os"]} for s in sess]
            total = len(self.sessions)
            flagged = sum(1 for s in self.sessions.values() if s.score >= .5)
        kb, kb_size = telemetry.kb_top(12)
        return {
            "kpi": {"sessions": total, "flagged": flagged, "evolutions": self.evolutions,
                    "tokens_issued": len(self.tokens), "vms": self.vm_count(), **telemetry.totals()},
            "sessions": rows, "events": telemetry.recent(40), "offline_metrics": self.det.metrics,
            "primary_model": self.det.primary, "live_eval": self.live_eval(),
            "resilience": self.resilience(), "kb": kb, "kb_size": kb_size,
            "insights": list(self.insights)[:12], "ports": self.port_info,
            "train_seconds": self.det.train_seconds,
        }

    def reset(self):
        with self.lock:
            self.sessions.clear()
            self.tokens.clear()
            self.insights.clear()
            self.evolutions = 0
        telemetry.reset(keep_kb=False)
