# Deploying to Railway (GitHub -> Railway)

The whole app (bank + hidden honeypot + SOC dashboard) runs as **one** Railway service. Do not split the
frontend onto another host: scanners must hit the honeypot on the same public address as the bank.

## 1. Push to GitHub
```bash
cd bank_honeypot
git init && git add . && git commit -m "Aurora Bank adaptive honeypot"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main
```
`.gitignore` already keeps databases, logs and `.env` out of the repo.

## 2. Create the Railway service
1. railway.com -> **New Project -> Deploy from GitHub repo** -> pick the repo.
2. **Variables** tab (see `.env.example`):
   - `SECRET_KEY` = long random string  (`python -c "import secrets;print(secrets.token_urlsafe(48))"`)
   - `SOC_KEY` = another long random string (this is your dashboard password)
   - `DATA_DIR` = `/data`
3. **Volumes** -> add a volume mounted at `/data` (keeps `bank.db` and `honeypot.db` across deploys; without it everything resets on each deploy).
4. **Settings -> Networking -> Generate Domain**. Railway provides HTTPS.
5. Deploy. `railway.json` already sets the start command (1 gunicorn worker, 8 threads: the engine keeps live sessions in memory, so do not raise workers) and the `/healthz` health check.

The app refuses to start in production with the default or a short `SECRET_KEY`/`SOC_KEY`.

## 3. Use your Hostinger domain (optional)
In Railway: **Settings -> Networking -> Custom Domain** -> enter e.g. `bank.yourdomain.com`; Railway shows a CNAME target.
In Hostinger hPanel: **Domains -> DNS / Nameservers -> DNS records** -> add that CNAME. Wait for DNS, Railway issues the certificate.
Hostinger Premium is shared PHP hosting and cannot run this Python app; use it only for the domain, or for a static info page on another subdomain.

## 4. Open the dashboard
`https://<your-domain>/soc?key=<SOC_KEY>`

## What works / what does not on Railway
| Feature | On Railway |
|---|---|
| Bank (register, login, forgot password, transfers) | Works. Forgot-password codes appear at `/demo-inbox` (no real e-mail is sent) |
| HTTP honeypot (fake `.env`, `/admin`, VMs, shell, honeytokens, adaptive rotation) | Works |
| SOC dashboard, ML scoring, resilience score, report download | Works |
| Fake SSH/FTP/Telnet/MySQL/Redis ports | Not reachable: Railway exposes HTTP, plus at most a single raw-TCP port per service. Set `START_PORTS=1` only if you wire up a TCP proxy; for all five ports use a small VPS |
| `simulate_attacker.py` | Refuses non-private targets by design. Run it against a local copy, or probe the public site by hand |

Production behaviour differences: lab-label headers (`X-Lab-Truth`, `X-Demo-Actor`) are ignored (they are forgeable), so the "live lab-labelled" metrics stay empty and all traffic from one IP is one session. Session cookies are `Secure`. Client IPs come from `X-Forwarded-For` (`TRUST_PROXY_HOPS`, default 1). Sessions, tokens and event rows are capped, and sign-up / reset requests are rate-limited per IP.

## Before you make it public
- The site looks like a bank login. Keep the "fictional demo bank" footer and use a clearly demo-style domain, or browsers/Safe Browsing may flag it as phishing.
- Real attackers' IPs and requests are stored in `honeypot.db`: treat it as personal data, do not share it raw.
- The decoy credentials are synthetic. Never put real secrets anywhere in the app.
