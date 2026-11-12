# Install on a Linux server

For a team: RiskPrism runs as a systemd service on 127.0.0.1, Caddy in front of it provides HTTPS, and every analyst signs in with their own account and an authenticator app. Any Linux VM or physical server works (Ubuntu 24.04 is used below); for Azure-specific options see [AZURE_DEPLOY.md](AZURE_DEPLOY.md).

## What you need

- A Linux server with Python 3.10 or newer, 1 vCPU and 1 GB RAM. Run **one** instance per organisation.
- A DNS name pointing at the server, for example `riskprism.yourco.example`.
- Inbound 443 (and 80, which Caddy uses for its certificate) from your users, and 22 for SSH from your own address only. Never expose port 8765.
- Outbound HTTPS if you use the AI questionnaire, single sign-on, ServiceNow or Jira; outbound 587 or 465 for email.

## 1. Install

Log in as your normal (non-root) user. The commands below use `$USER`, so they work whatever it is called.

```bash
sudo apt-get update && sudo apt-get install -y python3 git caddy
cd ~ && git clone https://github.com/generalwax2018/riskprism.git
python3 --version   # 3.10 or newer
```

## 2. Settings file

Readable by root only, because it can hold passwords and API keys.

```bash
sudo mkdir -p /etc/riskprism /var/lib/riskprism && sudo chown "$USER" /var/lib/riskprism && sudo chmod 700 /var/lib/riskprism
sudo tee /etc/riskprism/riskprism.env >/dev/null << 'EOF'
ENTROPY_HOST=127.0.0.1
ENTROPY_PORT=8765
ENTROPY_DATA_DIR=/var/lib/riskprism
ENTROPY_AUTH=accounts
ENTROPY_BASE_URL=https://riskprism.yourco.example
ENTROPY_ALLOWED_HOSTS=riskprism.yourco.example
EOF
sudo chmod 600 /etc/riskprism/riskprism.env
```

Every other setting (email, single sign-on, tickets, AI, backups) goes in the same file. The full list is in `.env.example` and the README.

## 3. Service

```bash
sudo tee /etc/systemd/system/riskprism.service >/dev/null << EOF
[Unit]
Description=RiskPrism
After=network.target

[Service]
User=$USER
WorkingDirectory=$HOME/riskprism
EnvironmentFile=/etc/riskprism/riskprism.env
ExecStart=/usr/bin/python3 serve.py
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/riskprism

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now riskprism
journalctl -u riskprism -n 20 --no-pager
```

The log should start with `RiskPrism  http://127.0.0.1:8765   auth=accounts` and say there are no accounts yet. If it lists a problem instead, fix that setting and run `sudo systemctl restart riskprism`. If you keep backups on another disk (`ENTROPY_BACKUP_DIR`), add that folder to `ReadWritePaths`.

## 4. HTTPS with Caddy

Replace the contents of `/etc/caddy/Caddyfile` with:

```
riskprism.yourco.example {
    reverse_proxy 127.0.0.1:8765
}
```

Then `sudo systemctl reload caddy`. Caddy gets and renews the certificate itself once the DNS name points at the server. It also passes `X-Forwarded-For`, which RiskPrism uses for the audit log and sign-in throttling.

## 5. The first admin

Run this as the same user, with the service's settings, so the account lands in the data folder the server reads. Do not use `sudo`.

```bash
cd ~/riskprism
set -a; source <(sudo cat /etc/riskprism/riskprism.env); set +a
python3 accounts.py invite you@yourco.example --admin --name "Your Name"
```

Check that the `Data folder:` line matches `/var/lib/riskprism`, then open the printed link (it works once, for 72 hours). Choose a password, scan the QR code with an authenticator app and enter the code. Invite everyone else from **People**.

## 6. Before real use

1. **Your environment:** set your organisation name, the security contact vendors see, and your deadlines for fixing findings.
2. **Data and audit → Remove sample data**, if you loaded any.
3. Copy `/var/lib/riskprism/secret.key` somewhere safe and separate (a password manager or a key vault). Backups leave it out on purpose; without it, a restored server cannot verify authenticator apps or the audit log.
4. Point `ENTROPY_BACKUP_DIR` at another disk or a network share so a lost server does not take its backups with it. See **Backups, export and delete** in the README.

## Updating

```bash
cd ~/riskprism && git pull && python3 -m unittest discover -s tests && sudo systemctl restart riskprism
```

The tests use a temporary folder, not your data. If one fails, do not restart: report it, or go back with `git checkout <previous commit>`. Read [CHANGELOG.md](../CHANGELOG.md) before updating.

## Troubleshooting

- **400 "Unexpected Host header":** the address in the browser does not match `ENTROPY_ALLOWED_HOSTS`. Add it, or open the site by its DNS name.
- **The setup link opens the wrong address:** `ENTROPY_BASE_URL` is wrong; fix it and create a new invite.
- **"Refusing to bind ... with no authentication":** `ENTROPY_AUTH` is missing from the settings file, or the service is not reading it (`systemctl cat riskprism` shows the `EnvironmentFile=` line).
- **Locked out (lost phone, only admin):** on the server, with the settings loaded as in step 5, run `python3 accounts.py reset you@yourco.example` and open the new link.
