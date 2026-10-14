"""Low-interaction fake network services (SSH / FTP / Telnet / MySQL / Redis banners).

These are *listeners that only talk*: they send a believable banner, record what the client sends,
and reply with canned answers.  They never execute anything and never touch the filesystem.
High, unprivileged ports are used so no root is needed; map them to 22/21/23/3306/6379 with
iptables/port-forwarding on an isolated lab network if you want nmap's default scans to see them.
"""
import socket
import struct
import threading

PORTS = [(2222, "ssh"), (2121, "ftp"), (2323, "telnet"), (3307, "mysql"), (6380, "redis")]


def _mysql_greeting(version):
    payload = (b"\x0a" + version.encode() + b"\x00" + struct.pack("<I", 4242) + b"abcdefgh\x00" +
               b"\xff\xf7\x21\x02\x00\xff\x81\x15" + b"\x00" * 10 + b"ijklmnopqrst\x00" + b"mysql_native_password\x00")
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


def _mysql_denied():
    msg = b"#28000Access denied for user 'root'@'localhost' (using password: YES)"
    payload = b"\xff\x15\x04" + msg
    return struct.pack("<I", len(payload))[:3] + b"\x02" + payload


def _readline(conn, limit=512):
    buf = b""
    while len(buf) < limit:
        ch = conn.recv(1)
        if not ch:
            break
        buf += ch
        if ch == b"\n":
            break
    return buf.decode(errors="replace").strip()


def _serve(conn, addr, port, service, engine):
    ip = addr[0]
    conn.settimeout(8)
    try:
        s = engine.session_by_ip(ip)
        prof = s.profile
        engine.note_port(ip, port, service, "connect")
        if service == "ssh":
            conn.sendall((prof["ssh"] + "\r\n").encode())
            data = _readline(conn)
            engine.note_port(ip, port, service, f"client banner: {data}")
        elif service == "ftp":
            conn.sendall(b"220 Aurora Bank FTP server ready.\r\n")
            while True:
                line = _readline(conn)
                if not line:
                    break
                engine.note_port(ip, port, service, line)
                cmd = line.split(" ")[0].upper()
                if cmd == "USER":
                    conn.sendall(b"331 Password required.\r\n")
                elif cmd == "PASS":
                    conn.sendall(b"230 Login successful.\r\n")
                elif cmd == "SYST":
                    conn.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd in ("LIST", "NLST"):
                    conn.sendall(b"150 Here comes the listing.\r\n226 Directory send OK.\r\n")
                elif cmd == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    conn.sendall(b"502 Command not implemented.\r\n")
        elif service == "telnet":
            conn.sendall(f"\r\n{prof['os']}\r\ncore-bank-db-01 login: ".encode())
            user = _readline(conn)
            conn.sendall(b"Password: ")
            pw = _readline(conn)
            engine.note_port(ip, port, service, f"login attempt user={user} pass={pw}")
            engine.note_credential(s, user)
            conn.sendall(b"\r\nLogin incorrect\r\n")
        elif service == "mysql":
            conn.sendall(_mysql_greeting(prof["db"]))
            data = conn.recv(512)
            engine.note_port(ip, port, service, f"auth packet {len(data)} bytes {data[36:60]!r}")
            conn.sendall(_mysql_denied())
        elif service == "redis":
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                text = data.decode(errors="replace")
                engine.note_port(ip, port, service, text.replace("\r\n", " ")[:200])
                words = [w for w in text.replace("\r", "").split("\n") if w and w[0] not in "*$"]
                cmd = (words[0] if words else "").upper()
                if cmd == "PING":
                    conn.sendall(b"+PONG\r\n")
                elif cmd == "INFO":
                    body = f"# Server\r\nredis_version:5.0.7\r\nos:{prof['os']}\r\ntcp_port:6379\r\n"
                    conn.sendall(f"${len(body)}\r\n{body}\r\n".encode())
                elif cmd == "KEYS":
                    conn.sendall(b"*3\r\n$12\r\nsession:9f31\r\n$9\r\nacct:cache\r\n$8\r\napi_keys\r\n")
                elif cmd in ("CONFIG", "FLUSHALL", "SLAVEOF", "MODULE"):
                    conn.sendall(b"-ERR unknown command\r\n")
                elif cmd == "AUTH":
                    conn.sendall(b"+OK\r\n")
                else:
                    conn.sendall(b"+OK\r\n")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _listen(port, service, engine, host):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(20)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_serve, args=(conn, addr, port, service, engine), daemon=True).start()


def start(engine, host="127.0.0.1"):
    started = []
    for port, service in PORTS:
        try:
            probe = socket.socket()
            probe.bind((host, port))
            probe.close()
        except OSError:
            print(f"[ports] {port}/{service} busy - skipped")
            continue
        threading.Thread(target=_listen, args=(port, service, engine, host), daemon=True).start()
        started.append({"port": port, "service": service})
    engine.port_info = started
    return started
