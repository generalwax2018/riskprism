# Deploying to Azure

RiskPrism is a single Python process that keeps JSON files and one SQLite file (`riskprism.db`) on disk. That decides what is safe to deploy:

- **Run exactly one instance.** Two instances would each write their own copy of the files. Do not scale out.
- **The data folder must survive restarts.** On App Service for Linux that means `/home`. In a container it means a mounted volume. On a VM it means the disk.
- **Turn on analyst sign-in before anything is reachable from the internet.** The server enforces this: it will not start on a non-loopback address with `ENTROPY_AUTH=none`.

Pick one of the two paths below. Path A is the simplest managed option. Path B is the cheap VM the earlier version of this file described.

## Configuration reference

All settings are environment variables. `.env.example` lists them with comments.

| Variable | Default | Meaning |
|---|---|---|
| `ENTROPY_DATA_DIR` | `./data` | Vendor JSON, tokens, `riskprism.db` (including the audit log), uploaded evidence, secret key |
| `ENTROPY_HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` in a container or App Service |
| `ENTROPY_PORT` (falls back to `PORT`) | `8765` | Listen port |
| `ENTROPY_BASE_URL` | request Host | Public URL used in vendor magic links. Set it to your HTTPS URL |
| `ENTROPY_AUTH` | `none` | `none`, `accounts` (per-person login with authenticator code), `password` or `easyauth` |
| `ENTROPY_ANALYST_PASSWORD` | | Required for `password` mode, 12+ characters |
| `ENTROPY_ALLOWED_USERS` | any | `easyauth` only: comma separated sign-in names allowed in |
| `ENTROPY_ALLOWED_HOSTS` | | Extra Host values to accept on a loopback bind behind a proxy |
| `ENTROPY_SECRET` | generated | Signs sessions, CSRF tokens and audit seals; encrypts authenticator secrets. Otherwise kept in `DATA_DIR/secret.key`. Not in backups: keep a copy in Key Vault or a password manager |
| `ENTROPY_TOKEN_DAYS` | `30` | How long a vendor link lasts |
| `ENTROPY_ADMINS` | | Sign-in names that may edit org units, approvers, people and data. In `password` mode the name is `analyst` |
| `ENTROPY_VIEWERS` | | Sign-in names that can read and export everything and change nothing. Wins over `ENTROPY_ADMINS`. In `accounts` mode use the People page instead |
| `ENTROPY_ACCEPT_MAX_DAYS` | `365` | Longest a risk acceptance may run |
| `ENTROPY_AI` | `on` | Optional. `off` hides every AI control and makes the code refuse model calls and vendor website fetches, even when `XAI_*` or `LLM_*` is set |
| `ENTROPY_OIDC_ISSUER` / `ENTROPY_OIDC_CLIENT_ID` / `ENTROPY_OIDC_CLIENT_SECRET` | | Optional. Analyst single sign-on with OpenID Connect, `accounts` mode only. Redirect URI: `<ENTROPY_BASE_URL>/login/sso/callback`. Issuer must be `https` |
| `ENTROPY_OIDC_LABEL` / `ENTROPY_OIDC_ONLY` / `ENTROPY_OIDC_EMAIL_CLAIM` | | Optional. Button text; `1` switches off password sign-in; the claim that holds the email (default `email`, then `preferred_username`, then `upn`) |
| `ENTROPY_SNOW_INSTANCE` / `ENTROPY_SNOW_USER` / `ENTROPY_SNOW_PASSWORD` | | Optional. Raise findings as ServiceNow records. Instance is an `https` URL |
| `ENTROPY_SNOW_TABLE` / `ENTROPY_SNOW_GROUP` | `incident` / empty | Optional. Target table, and an assignment group if you want one |
| `ENTROPY_JIRA_URL` / `ENTROPY_JIRA_EMAIL` / `ENTROPY_JIRA_TOKEN` / `ENTROPY_JIRA_PROJECT` | | Optional. Raise findings as Jira issues in one project |
| `ENTROPY_JIRA_ISSUETYPE` | `Task` | Optional. Jira issue type |
| `ENTROPY_JIRA_DUEDATE` | off | Optional. `1` sends each finding's due date as Jira `duedate` |
| `ENTROPY_SMTP_HOST` / `ENTROPY_SMTP_PORT` / `ENTROPY_SMTP_TLS` | off / `587` / `starttls` | Optional email. `ssl` for port 465; `none` only for a mail server on the same machine |
| `ENTROPY_SMTP_USER` / `ENTROPY_SMTP_PASSWORD` / `ENTROPY_SMTP_FROM` | | Mail server sign-in, and the From address (required when the host is set) |
| `ENTROPY_DIGEST` / `ENTROPY_DIGEST_TO` | `weekly` / | Weekly digest on Monday after 08:00 server time, or `off`; extra recipients besides active admins |
| `ENTROPY_BACKUP` / `ENTROPY_BACKUP_DIR` / `ENTROPY_BACKUP_KEEP` | `daily` / `DATA_DIR/backups` / `14` | Nightly backup after 02:00 server time, where it goes, how many to keep |
| `XAI_API_KEY` / `XAI_MODEL` | | Grok for the AI questionnaire. The key alone is enough |
| `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` | | Any other OpenAI-compatible provider; these override `XAI_*` |
| `LLM_TIMEOUT` | `180` | Seconds allowed for one model call |
| `ENTROPY_AZURE_ACCOUNT_URL` / `ENTROPY_AZURE_CONNECTION` / `ENTROPY_AZURE_CONTAINER` | | Optional Blob storage for evidence, see below |

## Path A: App Service for Linux (managed TLS, Entra sign-in)

This path has not been run against a live App Service in this repository. The app-side behaviour (header handling, excluded paths, port) is covered by tests and local runs; the portal steps follow Microsoft's documented settings, so expect to adjust names if the portal has changed.

1. Create a **Linux** App Service plan. Any tier that supports Easy Auth and custom domains works. The Free tier sleeps and is not suitable for real use. Set the plan to **one instance** and do not enable autoscale.
2. Create a Web App: Python 3.12, Linux. Deploy from GitHub (branch `main`), ZIP deploy, or a container built from the `Dockerfile`.
3. Startup command (code deploy): `python serve.py`
4. Application settings:

```
ENTROPY_HOST=0.0.0.0
ENTROPY_PORT=8000
WEBSITES_PORT=8000              # tells App Service which port the app listens on
ENTROPY_DATA_DIR=/home/entropy-data
ENTROPY_AUTH=easyauth
ENTROPY_BASE_URL=https://<your-app>.azurewebsites.net
ENTROPY_ALLOWED_USERS=ana@example.com,ben@example.com   # recommended
```

5. **Authentication** blade: add the Microsoft identity provider, set *Require authentication*, and choose *HTTP 302 redirect* for unauthenticated requests.
6. **Exclude the public paths from platform sign-in.** Vendors have no account in your tenant, so the vendor form must stay reachable. In *Authentication → Edit → Excluded paths* (or `authsettingsV2` `excludedPaths`) add:

```
/q/*
/static/*
/healthz
```

The app does its own checks on those paths: `/q/<token>` requires a valid, unexpired vendor token, and `/static` and `/healthz` return nothing sensitive. Everything else is refused unless the platform supplies a signed-in identity.

7. Turn on **HTTPS Only**, set **Minimum TLS 1.2**, and disable FTP basic auth.
8. Set the health check path to `/healthz`.

How `easyauth` mode works: App Service authenticates the user and forwards the identity in `X-MS-CLIENT-PRINCIPAL-NAME`. The app trusts that header, which is safe **only because the platform strips it from inbound requests and the app is not reachable except through App Service**. Do not run `easyauth` mode on a VM or anywhere a client can reach the app directly, since anyone could then send the header themselves. If you turn on IP access restrictions or a private endpoint, keep it that way.

## Path B: one small VM (cheap, more to look after)

The same steps work on any Linux server; [INSTALL.md](INSTALL.md) is the provider-neutral version, with per-person accounts from the start.

Expected bill for a Standard_B1s Linux VM in East US or West US 2 left running all month is about $8, plus disk and IP. Stop the VM when nobody is testing.

1. Create an Ubuntu 24.04 VM (Standard_B1s), SSH key only. Open only 22 (from your IP) and 443.
2. Install:

```bash
sudo apt-get update && sudo apt-get install -y python3 git caddy
git clone https://github.com/generalwax2018/riskprism.git
cd riskprism
```

3. Environment file, readable by root only:

```bash
sudo mkdir -p /etc/entropy /var/lib/entropy && sudo chown azureuser /var/lib/entropy
sudo tee /etc/entropy/entropy.env >/dev/null << 'EOF'
ENTROPY_HOST=127.0.0.1
ENTROPY_PORT=8765
ENTROPY_DATA_DIR=/var/lib/entropy
ENTROPY_AUTH=password
ENTROPY_ANALYST_PASSWORD=change-me-to-a-long-random-phrase
ENTROPY_BASE_URL=https://demo.example.com
ENTROPY_ALLOWED_HOSTS=demo.example.com
EOF
sudo chmod 600 /etc/entropy/entropy.env
```

On an existing VM, `systemctl cat entropy` shows which settings file the service actually reads (its `EnvironmentFile=` line). The examples here use `/etc/entropy/entropy.env`.

4. Service:

```bash
sudo tee /etc/systemd/system/entropy.service >/dev/null << 'EOF'
[Unit]
Description=RiskPrism TPRM
After=network.target

[Service]
User=azureuser
WorkingDirectory=/home/azureuser/riskprism
EnvironmentFile=/etc/entropy/entropy.env
ExecStart=/usr/bin/python3 serve.py
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/entropy

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now entropy
```

5. TLS with Caddy. The app stays on loopback and Caddy terminates HTTPS. `/etc/caddy/Caddyfile`:

```
demo.example.com {
    reverse_proxy 127.0.0.1:8765
}
```

Point a DNS A record for that name at the VM, then `sudo systemctl reload caddy`. Caddy adds `X-Forwarded-For`, which the app uses for the audit log and login throttling.

Do not bind the app to `0.0.0.0` on the VM and expose 8765. Keep it on loopback behind Caddy.

The AI questionnaire needs **outbound** HTTPS from the VM: to the model provider (for example `api.x.ai`) and to vendor websites for research. Single sign-on needs outbound HTTPS to your identity provider, ticketing to your ServiceNow or Jira instance, and email outbound port 587 (or 465) to your mail server. Azure blocks outbound port 25 on most subscriptions, so do not plan on it. Backups to Azure Files need outbound port 445 to the storage account. With `ENTROPY_AI=off` the first two AI destinations are not used. Inbound rules do not change.

If SSH times out, the network security group probably only allows port 22 from an old IP address. In the portal, open the VM's **Networking**, set the SSH rule's source to **My IP address**, and try again. **Serial console** works without SSH.

### Updating the VM

The git repository uses one branch, `main`. To deploy:

1. On your laptop, commit and push to `main` in GitHub Desktop.
2. On the server (the service is named `entropy`):

```bash
cd /home/azureuser/riskprism && git pull && python3 -m unittest discover -s tests && sudo systemctl restart entropy
```

Run the tests before the restart. They use a temporary data folder, not the live one. The suite is 283 tests; `tests/test_pilot.py` starts the real server on an empty data folder. If a test fails, do not restart; fix it first or `git checkout` the previous commit. Templates are read on each request, but Python modules load once, so the restart is needed after any `.py` change.

### Switching a VM to per-person accounts

1. Pull and restart as in **Updating the VM** so `accounts.py` is on the box.
2. Create the first admin **as the service user, with the service's settings**, so the account lands in the same data folder the server reads:

```bash
cd ~/riskprism
set -a; source <(sudo cat /etc/entropy/entropy.env); set +a
python3 accounts.py invite you@example.com --admin --name "Your Name"
```

Check that the `Data folder:` line it prints matches the server's. Do not run it with `sudo`, which would leave the database owned by root.
3. In the settings file change `ENTROPY_AUTH=password` to `ENTROPY_AUTH=accounts` (you can delete `ENTROPY_ANALYST_PASSWORD` and set `ENTROPY_ADMINS=` empty), then `sudo systemctl restart entropy`.
4. Open the printed link, finish setup, and invite everyone else from **People**.

## Evidence in Blob Storage (optional)

Without this, uploads live in `DATA_DIR/evidence/` on the same disk. That is fine for one tenant. If you want them in Blob:

1. Storage account (Standard LRS), private container named `evidence`. Disable anonymous access and shared-key access if you can.
2. Install the SDK: `pip install azure-storage-blob azure-identity` (or uncomment the line in the `Dockerfile`).
3. Give the web app a **managed identity** and assign it *Storage Blob Data Contributor* on the container.
4. Set `ENTROPY_AZURE_ACCOUNT_URL=https://<account>.blob.core.windows.net`.

A connection string in `ENTROPY_AZURE_CONNECTION` also works, but it is a secret with full account access. Prefer the managed identity.

Uploads are still validated (extension allow-list, magic bytes, 25 MB cap) and their SHA-256 is recorded in the vendor record. **The Blob path has not been tested against a live storage account** in this repository; try it with a test file and check the audit log and the container before relying on it. Vendor JSON, tokens and the audit log stay on the local disk either way.

## Backups

Everything worth keeping is under `ENTROPY_DATA_DIR`: `vendors/`, `evidence/`, `tokens.json`, `policy.json`, `secret.key`, `riskprism.db` (including the `users` and `audit` tables), `integrations.json`, `environment.json`, `objectives.json`, `catalog.json` (if present), `shadow.json`, `tickets.json` and `findings_state.json`.

The app backs this up itself every night after 02:00 server time (`ENTROPY_BACKUP=daily`, the default): one `.tar.gz` in `ENTROPY_BACKUP_DIR`, newest `ENTROPY_BACKUP_KEEP` (14) kept. The default folder is `DATA_DIR/backups`, on the same disk as the data, and the **Data and audit** page warns about that. Point it at an Azure Files share instead, so losing the VM does not lose its backups. Disk snapshots or App Service **Backups** (which include `/home`) are a good second copy.

### `secret.key` lives somewhere else

`secret.key` is **not** in the backups, on purpose: the database and the key together could rebuild the audit log. Store one copy in Azure Key Vault (as a secret) or a password manager, and do not put it on the backup share. Without it, restored authenticator apps stop working and the audit log fails verification. If you set `ENTROPY_SECRET` instead, the same applies to that value.

### Back up to Azure Files (VM)

This has not been run against a live storage account in this repository.

1. Create a storage account and a file share (for example `riskprism-backups`). Restrict network access to the VM's virtual network if you can.
2. In the portal, open the share and choose **Connect** → **Linux**. It prints a mount script for that share. Install `cifs-utils`, run the script with mount point `/mnt/riskprism-backups`, and add `uid=azureuser,gid=azureuser,dir_mode=0700,file_mode=0600` to the mount options so the service user can write and nobody else can read.
3. Let the service write there. The unit in Path B uses `ProtectSystem=strict`, so add the folder:

```
ReadWritePaths=/var/lib/entropy /mnt/riskprism-backups
```

4. Add `ENTROPY_BACKUP_DIR=/mnt/riskprism-backups` to the settings file, then `sudo systemctl daemon-reload && sudo systemctl restart entropy`. The startup line `Backups: nightly to /mnt/riskprism-backups, keeping 14` confirms it.
5. On **Data and audit**, choose **Back up now** and check the file appears on the share.

On App Service, mount an Azure Files share under **Configuration → Path mappings** and set `ENTROPY_BACKUP_DIR` to its mount path. Not tested here either.

### Restore (VM)

Run as the service user with the service's settings, as in **Switching a VM to per-person accounts** (use the settings file `systemctl cat entropy` names):

```bash
sudo systemctl stop entropy
cd ~/riskprism
set -a; source <(sudo cat /etc/entropy/entropy.env); set +a
# new VM? copy your saved secret.key into the data folder first (a new server makes its own key, which will not match)
python3 ops.py restore /mnt/riskprism-backups/riskprism-YYYYMMDD-HHMMSS.tar.gz --force
sudo systemctl start entropy
```

The current contents of the data folder (except `secret.key` and `backups/`) are moved into a `before-restore-<stamp>` folder inside the data folder, not deleted; delete it yourself once the restore checks out. Backups never include that folder. If the backup was made with a different server key than the one in place, the restore prints a warning: put the original `secret.key` in place before starting. The restore refuses an archive with unsafe paths. Afterwards sign in, open **Data and audit** and choose **Check the seals now**: an intact result means the key matches.

`ops.py restore` needs the service stopped, which App Service does not offer from its SSH console. On App Service, restore with the platform's own **Backups** feature.

## Email (optional)

Set these in the settings file (VM) or application settings (App Service), then restart. The startup line `Email: via <host>, weekly digest weekly` confirms it, and **Data and audit** → **Send a test** checks it end to end.

SendGrid (the user name is the literal word `apikey`):

```
ENTROPY_SMTP_HOST=smtp.sendgrid.net
ENTROPY_SMTP_PORT=587
ENTROPY_SMTP_USER=apikey
ENTROPY_SMTP_PASSWORD=<SendGrid API key with Mail Send permission>
ENTROPY_SMTP_FROM=Acme Security <security@acme.example>   # a verified sender in SendGrid
```

Microsoft 365 (SMTP AUTH client submission):

```
ENTROPY_SMTP_HOST=smtp.office365.com
ENTROPY_SMTP_PORT=587
ENTROPY_SMTP_USER=riskprism@acme.example
ENTROPY_SMTP_PASSWORD=<that mailbox's password>
ENTROPY_SMTP_FROM=Acme Security <riskprism@acme.example>  # must be the mailbox, or one it may send as
```

SMTP AUTH has to be allowed for that mailbox. RiskPrism signs in with a user name and password only (no OAuth), and Microsoft has been retiring password sign-in for SMTP AUTH in Exchange Online, so check that it still works for your tenant. If it does not, use SendGrid or another service that accepts a password or API key over SMTP.

Keep `ENTROPY_SMTP_PASSWORD` in the root-only settings file or App Service settings (or a Key Vault reference), never in git. Set `ENTROPY_DIGEST=off` if you do not want the Monday digest, and `ENTROPY_DIGEST_TO` for recipients who are not admins.

## Smoke test after deploy

1. `https://<host>/healthz` returns `ok` without signing in.
2. `https://<host>/` sends you to Microsoft sign-in (easyauth) or the app's login page (password) when signed out.
3. Sign in (in `accounts` mode with the authenticator code), open a vendor, choose *New vendor form link*, open that link in a private window: the vendor form loads with no sign-in.
4. Change a value as the vendor, then find the change in the vendor's Activity tab.
5. `https://<host>/vendor/anything` in the private window does not show a vendor record.

## What this does not do

- No database server. Two people saving the same vendor within milliseconds are serialised by a lock, but only inside one process.
- One shared password (`password` mode) is not per-person identity, so risk acceptances cannot be signed in that mode. Use `accounts` (per-person login) or `easyauth` (Path A) to sign them.
- Email needs your own SMTP service (see above). Without it, copy the vendor link or the ready-to-send message into your own mail.
- Backups are files in a folder. Getting them off the server is the share you mount there.
- Postgres is the next step if you need more than one instance, high availability or queries across vendors. `records.py` is the only module that reads and writes vendor files, so that is where it would go.
