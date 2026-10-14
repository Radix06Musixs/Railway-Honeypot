# Aurora Bank + Hidden AI-Based Adaptive Honeypot (working demo)

A fictional bank website (home / login / account dashboard) with an adaptive honeypot hidden inside it.
Real customers never see it. Anything that looks like probing is silently routed into a deception layer,
scored by an ML model, and fed back into the engine - the 7 stages of the flowchart, running end to end.

> **Hosting:** see `DEPLOY.md` for GitHub + Railway (+ Hostinger domain) steps.

## Run it

```bash
pip install -r requirements.txt
python app.py                         # bank: http://127.0.0.1:5000
                                      # SOC : http://127.0.0.1:5000/soc?key=kaish-soc   (set SOC_KEY to change)
python simulate_attacker.py all       # in a 2nd terminal: benign users + 5 attacker personas
```

Models train at start-up (~4 s). Seeded customers: `demo` / `Demo@123`, `priya` / `Priya@2026`.

## Real bank features (v2)

- **Create account** (`/register`): Customer ID, e-mail, strong-password rule, unique 12-digit account number, Rs 10,000 demo bonus.
- **Forgot password** (`/forgot` -> `/reset`): 6-digit OTP (hashed, 10-min expiry, 5 tries, single use). No e-mail server is needed: codes land in the **Demo Inbox** (`/demo-inbox`). The response is identical for unknown accounts (no account enumeration); bad OTP guesses count as suspicious behaviour in the detector.
- **Money transfer** between accounts (`/transfer` from the dashboard): integer-paise ledger, atomic debit+credit, overdraft / self-transfer / bad-amount checks, Rs 5,00,000 per-transfer limit, CSRF token, per-account history.
- `python test_bank.py` runs 19 functional checks of all of the above against a running server.
- The real bank uses parameterised SQL and hashed passwords. The "login bypass" an attacker sees is the honeypot's fake, not a weakness.

## 5-minute live demo script

0. Create an account at `/register`, send money to `priya` (copy her account number from her dashboard), try *Forgot password*. Then:
1. Open the bank in one tab and `/soc?key=kaish-soc` in another. Log in as the demo customer: nothing odd appears in the bank, SOC shows a benign session at Level 0.
2. Visit `/.env`, `/backup.sql`, `/admin`, `/api/internal/vms`, `/server-status` in the browser: fake passwords, fake DB dump, fake VM inventory, fake open ports. Watch the session jump to L2/L3.
3. In `/admin`, sign in with anything -> fake admin panel -> **open console** on a fake VM and type `whoami`, `cat /etc/passwd`, `cat .env`. Nothing is executed; every command is captured.
4. Port-scan the fake services: `nmap -p 2222,2121,2323,3307,6380 127.0.0.1` (or `nc 127.0.0.1 2121`). Each shows believable banners (SSH, FTP, Telnet, MySQL, Redis).
5. Run `python simulate_attacker.py agentic` and watch the SOC: honeytoken reuse, tool-switching, **deception evolution** (the fake OS/server banner rotates), resilience score, KB growth.

## Flowchart -> code map

| Stage | Where |
|---|---|
| 1 Adaptive / agentic attacker | `simulate_attacker.py` (scan, brute-force, SQLi, low-and-slow, 7-stage agentic that adapts when the banner changes) |
| 2 Adaptive honeypot infrastructure | `deception.py` (fake VMs, decoy data, fake credentials, honeytokens, emulated shell, misleading info), `ports.py` (SSH/FTP/Telnet/MySQL/Redis), `engine.py` (response engine: dynamic scaling of fake VMs, response jitter, deception evolution) |
| 3 Data collection & telemetry | `telemetry.py` (SQLite: http / port / shell events, KB) |
| 4 Analytics & feature engineering | `engine.py` (session reconstruction, 14 behavioural features, behaviour profiling) |
| 5 ML-based resilience evaluation | `ml.py` (Random Forest, SVM, Neural Net, Gradient Boosting/XGBoost; Accuracy/Precision/Recall/F1/ROC-AUC) + resilience score |
| 6 Feedback & adaptation loop | `engine.py` insights, honeytoken replay detection, profile rotation, KB of attacker signatures |
| 7 Outputs & reporting | `/soc` dashboard, `/soc/report.json` download |

## Resilience score (0-100; High >=75, Medium >=50, else Low)

`0.30*detection rate + 0.20*detection speed + 0.20*attacker engagement depth + 0.15*adaptation resistance + 0.15*ML F1`

## Be honest about these limits (important for your write-up)

- **Training data is synthetic** (`ml.generate_dataset`). Offline metrics (~98% F1) measure how separable *my simulated personas* are, not real-world accuracy. For research results, replace it with labelled real honeypot logs.
- **Scoring is hybrid**: ML + hard-evidence floors (touching a decoy, fake port, honeytoken or SQLi payload sets a minimum score - a real customer never does these). The live-evaluation table therefore reads ~100% on the tiny simulated set; don't quote it as a generalisable result. The ML contribution is clearest on behavioural cases without decoy hits (rate, 404 ratio, tool switching).
- The simulator's `X-Lab-Truth` header exists only to compute live metrics and is never used for decisions (disable with `LAB_EVAL=0`).
- Sessions are keyed by IP (+ optional `X-Demo-Actor` header so several actors can share localhost). Behind a proxy/NAT you would key on IP + fingerprint instead.

## Safety

- Everything fake is synthetic. The shell emulator never executes anything; `curl/wget/ssh` always "time out". The fake ports only send banners and canned replies.
- Binds to 127.0.0.1 by default. Use `HOST=0.0.0.0` only on an isolated lab network, never on a real bank/production network, and put the SOC behind real auth.
- The simulator refuses non-loopback/private targets.
- This is a research prototype (Flask dev server), not production hardening.
