"""Stage 2 - Deception layer: fake VMs, fake credentials, decoy files, honeytokens, emulated shell.

Everything returned here is synthetic.  The shell emulator NEVER executes anything - it only
looks up canned text, and network commands (curl/wget/ssh...) always "time out".
"""
import json
import random
import re

FIRST = ["Aarav", "Vivaan", "Ananya", "Diya", "Rohan", "Meera", "Kabir", "Isha", "Arjun", "Saanvi",
         "Imran", "Fatima", "Rahul", "Priya", "Nikhil", "Zoya", "Karthik", "Lakshmi", "Dev", "Nisha"]
LAST = ["Sharma", "Nair", "Khan", "Das", "Patel", "Menon", "Iyer", "Reddy", "Mishra", "Verma", "Pillai", "Roy"]
ROLES = ["core-banking-db", "payments-gateway", "reporting-etl", "backup-vault", "ldap-auth",
         "swift-bridge", "audit-log", "hr-portal", "card-switch", "kyc-store", "jump-host", "monitoring"]
PASSWORD_BASES = ["Aurora@", "Bank#", "Winter", "Admin!", "Welcome", "Secure$", "Vault_", "Core@"]


def rng(s, salt):
    return random.Random(f"{s.seed}:{s.profile_idx}:{salt}")


def fake_password(r, engine, s, kind):
    frag = engine.mint_token(s, kind)
    return f"{r.choice(PASSWORD_BASES)}{r.randint(10, 99)}{frag}"


def fake_aws(r, engine, s):
    frag = engine.mint_token(s, "aws_key")
    return "AKIA" + frag.upper() + "".join(r.choice("ABCDEFGHJKLMNPQRSTUVWXYZ234567") for _ in range(8))


def vm_inventory(s, engine):
    r = rng(s, "vms")
    out = []
    for i in range(engine.vm_count()):
        role = ROLES[i % len(ROLES)]
        pw = fake_password(rng(s, f"vm{i}"), engine, s, f"vm_{role}_pw")
        out.append({"id": f"vm-{100 + i}", "name": f"{role}-{r.randint(1, 4):02d}",
                    "ip": f"10.20.{r.randint(1, 9)}.{r.randint(10, 240)}", "os": s.profile["os"],
                    "state": r.choice(["running", "running", "running", "stopped"]),
                    "user": r.choice(["root", "svc_bank", "ubuntu", "deploy"]), "password": pw,
                    "open_ports": r.sample([22, 80, 443, 3306, 5432, 6379, 8080, 9200], 3)})
    return out


# ------------------------------------------------------------------ file-like decoys
def env_file(s, engine):
    r = rng(s, "env")
    return "\n".join([
        "APP_ENV=production", "APP_DEBUG=false", f"APP_KEY=base64:{''.join(r.choice('abcdef0123456789') for _ in range(44))}",
        "DB_CONNECTION=mysql", f"DB_HOST=10.20.{r.randint(1, 9)}.{r.randint(10, 99)}", "DB_PORT=3306",
        "DB_DATABASE=aurora_core", "DB_USERNAME=bank_app", f"DB_PASSWORD={fake_password(r, engine, s, 'env_db_pw')}",
        f"AWS_ACCESS_KEY_ID={fake_aws(r, engine, s)}",
        f"AWS_SECRET_ACCESS_KEY={''.join(r.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(40))}",
        "REDIS_HOST=127.0.0.1", "REDIS_PORT=6380", f"REDIS_PASSWORD={fake_password(r, engine, s, 'env_redis_pw')}", ""])


def sql_dump(s, engine):
    r = rng(s, "sql")
    lines = [f"-- MySQL dump 10.13  Distrib {s.profile['db']}", "-- Host: localhost    Database: aurora_core",
             "-- Server version\t" + s.profile["db"], "", "DROP TABLE IF EXISTS `customers`;",
             "CREATE TABLE `customers` (`id` int, `name` varchar(80), `account_no` varchar(16), `balance` decimal(14,2), `pwd_hash` varchar(60));",
             "LOCK TABLES `customers` WRITE;"]
    for i in range(1, 16):
        name = f"{r.choice(FIRST)} {r.choice(LAST)}"
        acct = "".join(str(r.randint(0, 9)) for _ in range(12))
        h = "$2y$10$" + "".join(r.choice("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(53))
        lines.append(f"INSERT INTO `customers` VALUES ({i},'{name}','{acct}',{r.randint(5000, 9000000)}.{r.randint(10, 99)},'{h}');")
    lines += ["UNLOCK TABLES;", f"INSERT INTO `admins` VALUES (1,'dbadmin','{fake_password(r, engine, s, 'sqldump_admin_pw')}');", ""]
    return "\n".join(lines)


def git_config(s, engine):
    r = rng(s, "git")
    return ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
            f"[remote \"origin\"]\n\turl = https://deploy:{fake_password(r, engine, s, 'git_deploy_pw')}@git.aurora-internal.example/core/netbank.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"master\"]\n\tremote = origin\n\tmerge = refs/heads/master\n")


def aws_creds(s, engine):
    r = rng(s, "aws")
    return (f"[default]\naws_access_key_id = {fake_aws(r, engine, s)}\naws_secret_access_key = "
            f"{''.join(r.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(40))}\n")


def ssh_key(s, engine):
    r = rng(s, "key")
    body = "\n".join("".join(r.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(64)) for _ in range(12))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"


def actuator_env(s, engine):
    r = rng(s, "act")
    return {"activeProfiles": ["prod"], "propertySources": [{"name": "applicationConfig", "properties": {
        "spring.datasource.url": {"value": f"jdbc:mysql://10.20.{r.randint(1, 9)}.{r.randint(10, 99)}:3306/aurora_core"},
        "spring.datasource.username": {"value": "bank_app"},
        "spring.datasource.password": {"value": fake_password(r, engine, s, "actuator_db_pw")},
        "server.port": {"value": 8080}}}]}


def server_status(s, engine):
    ports = "\n".join(f"  {p['port']}/tcp  open  {p['service']}" for p in engine.port_info) or "  (none)"
    return (f"Server Version: {s.profile['server']} {s.profile['php']}\nServer MPM: prefork\n"
            f"Current Time: now\nTotal accesses: {random.randint(10**5, 10**6)}\nBusySlaves: 7\nIdleWorkers: 18\n\n"
            f"Listening services on this host:\n{ports}\n")


def robots(s, engine):
    return "User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\nDisallow: /.env\nDisallow: /api/internal/vms\nDisallow: /phpmyadmin\n"


# ------------------------------------------------------------------ HTML decoys
def _page(title, body):
    return (f"<!doctype html><html><head><meta charset=utf-8><title>{title}</title><style>"
            "body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#f4f6f8}header{background:#1f2d3d;color:#fff;padding:12px 24px}"
            "main{max-width:980px;margin:24px auto;padding:0 16px}table{border-collapse:collapse;width:100%;background:#fff}"
            "td,th{border:1px solid #dde3ea;padding:6px 10px;text-align:left}th{background:#eef2f6}"
            "input,button{padding:8px;margin:4px 0}.box{background:#fff;border:1px solid #dde3ea;padding:20px;max-width:340px}"
            "a{color:#0b63c5}code{background:#eef2f6;padding:1px 4px}</style></head><body>"
            f"<header><b>Aurora Bank</b> &mdash; {title}</header><main>{body}</main></body></html>")


def admin_login(path):
    return _page("Internal Admin Console", f"<div class=box><h3>Administrator sign in</h3><form method=post action='{path}'>"
                 "<input name=username placeholder=Username><br><input name=password type=password placeholder=Password><br>"
                 "<button>Sign in</button></form></div>")


def admin_panel(s, engine):
    vms = vm_inventory(s, engine)
    rows = "".join(f"<tr><td>{v['id']}</td><td>{v['name']}</td><td>{v['ip']}</td><td>{v['state']}</td><td>{v['user']}</td>"
                   f"<td><code>{v['password']}</code></td><td><a href='/console/vm/{v['id']}'>open console</a></td></tr>" for v in vms)
    r = rng(s, "users")
    users = "".join(f"<tr><td>{r.choice(FIRST)} {r.choice(LAST)}</td><td>{''.join(str(r.randint(0, 9)) for _ in range(12))}</td>"
                    f"<td>&#8377;{r.randint(5000, 9000000):,}</td></tr>" for _ in range(8))
    return _page("Internal Admin Console",
                 f"<h3>Virtual machines ({len(vms)})</h3><table><tr><th>ID</th><th>Name</th><th>IP</th><th>State</th><th>User</th><th>Password</th><th></th></tr>{rows}</table>"
                 f"<h3>Customer accounts (sample)</h3><table><tr><th>Name</th><th>Account</th><th>Balance</th></tr>{users}</table>"
                 "<p><a href='/backup.sql'>Download latest DB backup</a> | <a href='/api/internal/vms'>VM API</a></p>")


def console_page(vmid, s):
    return _page(f"Console {vmid}", f"<div style='background:#0b0f14;color:#9fe870;font-family:monospace;padding:14px;min-height:320px' id=t>"
                 f"Connected to {vmid} ({s.profile['os']})<br></div><form onsubmit='return go()'>"
                 f"<input id=c style='width:80%;font-family:monospace' autofocus placeholder='type a command'><button>Run</button></form>"
                 "<script>async function go(){const c=document.getElementById('c');const t=document.getElementById('t');"
                 f"t.innerHTML+='<br>$ '+c.value+'<br>';const r=await fetch('/console/vm/{vmid}/exec',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{cmd:c.value}})}});"
                 "const j=await r.json();t.innerText+=j.out+'\\n';c.value='';return false}</script>")


# ------------------------------------------------------------------ emulated shell
def shell(cmd, s, engine):
    p = s.profile
    c = cmd.strip()
    if not c:
        return ""
    head = c.split()[0]
    r = rng(s, "shell")
    files = ["backup_2024.tar.gz", ".env", "deploy.sh", "notes.txt", "release"]
    if head == "whoami":
        return "svc_bank"
    if head == "id":
        return "uid=1001(svc_bank) gid=1001(svc_bank) groups=1001(svc_bank),27(sudo)"
    if head == "pwd":
        return s.cwd
    if head == "hostname":
        return "core-bank-db-01"
    if head == "uname":
        return f"Linux core-bank-db-01 {p['kernel']} #1 SMP x86_64 GNU/Linux"
    if head == "ls":
        return "  ".join(files) if "-l" not in c else "\n".join(
            f"-rw-r--r-- 1 svc_bank svc_bank {r.randint(300, 90000):>6} Mar  3 11:2{i} {f}" for i, f in enumerate(files))
    if c.startswith("cat"):
        if ".env" in c:
            return env_file(s, engine)
        if "passwd" in c:
            return ("root:x:0:0:root:/root:/bin/bash\nsvc_bank:x:1001:1001::/home/svc_bank:/bin/bash\n"
                    "deploy:x:1002:1002::/home/deploy:/bin/bash\nmysql:x:112:117:MySQL Server:/nonexistent:/bin/false")
        if "shadow" in c:
            return "cat: /etc/shadow: Permission denied"
        if "notes" in c:
            return f"TODO: rotate db creds (current: bank_app / {fake_password(r, engine, s, 'notes_db_pw')})"
        return f"cat: {c[4:].strip() or '?'}: No such file or directory"
    if head in ("ifconfig", "ip"):
        return f"eth0: inet 10.20.{r.randint(1, 9)}.{r.randint(10, 240)}  netmask 255.255.255.0  broadcast 10.20.9.255"
    if head == "ps":
        return "USER  PID %CPU COMMAND\nroot    1  0.0 /sbin/init\nmysql 812  1.2 /usr/sbin/mysqld\nroot  955  0.0 /usr/sbin/sshd -D\nsvc_bank 2041 0.0 -bash"
    if head == "netstat" or head == "ss":
        lst = "\n".join(f"tcp  0  0 0.0.0.0:{q['port']}  0.0.0.0:*  LISTEN" for q in engine.port_info)
        return "Proto Recv-Q Send-Q Local Address  Foreign Address  State\n" + lst
    if head == "sudo":
        return "User svc_bank may run the following commands: (ALL) NOPASSWD: /usr/bin/vim, /usr/bin/find"
    if head == "history":
        return "  1  ssh deploy@10.20.4.22\n  2  mysql -u bank_app -p\n  3  cat /var/www/.env\n  4  ./deploy.sh"
    if head in ("curl", "wget", "ssh", "scp", "nc", "ncat", "ping", "telnet", "ftp"):
        return f"{head}: connection timed out"
    if head == "cd":
        s.cwd = c[3:].strip() or "/home/svc_bank"
        return ""
    if head == "exit":
        return "logout"
    return f"bash: {head}: command not found"


# ------------------------------------------------------------------ routing
ROUTES = [
    (r"^/\.env(\.bak|\.old|\.prod)?$", lambda s, e, m: (env_file(s, e), 200, "text/plain")),
    (r"^/(backup|db_backup|dump|database)\.(sql|bak)$", lambda s, e, m: (sql_dump(s, e), 200, "application/sql")),
    (r"^/\.git/config$", lambda s, e, m: (git_config(s, e), 200, "text/plain")),
    (r"^/\.git/HEAD$", lambda s, e, m: ("ref: refs/heads/master\n", 200, "text/plain")),
    (r"^/\.aws/credentials$", lambda s, e, m: (aws_creds(s, e), 200, "text/plain")),
    (r"^/(id_rsa|\.ssh/id_rsa)$", lambda s, e, m: (ssh_key(s, e), 200, "text/plain")),
    (r"^/actuator/env$", lambda s, e, m: (json.dumps(actuator_env(s, e)), 200, "application/json")),
    (r"^/actuator(/health)?$", lambda s, e, m: ('{"status":"UP"}', 200, "application/json")),
    (r"^/server-status$", lambda s, e, m: (server_status(s, e), 200, "text/plain")),
    (r"^/robots\.txt$", lambda s, e, m: (robots(s, e), 200, "text/plain")),
    (r"^/(api/internal/vms|api/v1/internal/hosts)$", lambda s, e, m: (json.dumps(vm_inventory(s, e)), 200, "application/json")),
    (r"^/config\.json$", lambda s, e, m: (json.dumps({"db": {"host": "10.20.4.17", "user": "bank_app",
                                          "password": fake_password(rng(s, 'cfg'), e, s, 'config_json_pw')}}), 200, "application/json")),
]
ADMIN_LOGINS = re.compile(r"^/(admin|admin/login|phpmyadmin|wp-login\.php|wp-admin|administrator|manager/html)/?$")
GENERIC_DECOY = re.compile(r"^/(cgi-bin|debug|shell|swagger|internal|private|old|test|staging)(/.*)?$", re.I)


def handle(path, method, form, s, engine):
    """Return (body, status, mimetype, kind) for a decoy path, else None."""
    for pat, fn in ROUTES:
        if re.match(pat, path):
            body, st, mt = fn(s, engine, method)
            return body, st, mt, "decoy-file"
    if ADMIN_LOGINS.match(path):
        if method == "POST":
            user = form.get("username", "")
            engine.note_credential(s, user)
            return admin_panel(s, engine), 200, "text/html", "decoy-admin-login-accepted"
        return admin_login(path), 200, "text/html", "decoy-admin-login"
    if path.rstrip("/") == "/admin/panel":
        return admin_panel(s, engine), 200, "text/html", "decoy-admin-panel"
    m = re.match(r"^/console/vm/(vm-\d+)$", path)
    if m:
        return console_page(m.group(1), s), 200, "text/html", "decoy-console"
    m = re.match(r"^/console/vm/(vm-\d+)/exec$", path)
    if m and method == "POST":
        return None
    if GENERIC_DECOY.match(path) and s.level >= 1:
        return "<h1>403 Forbidden</h1>" if s.level < 3 else "<h1>Index of " + path + "</h1><ul><li>backup.zip</li><li>notes.txt</li></ul>", \
               (403 if s.level < 3 else 200), "text/html", "decoy-generic"
    return None
