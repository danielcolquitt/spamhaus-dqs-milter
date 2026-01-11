# Spamhaus DQS Milter (Python)

A small Python **milter** daemon that queries Spamhaus DQS DNS zones. It can be used with **any Mail Transfer Agent (MTA) that supports the milter protocol** (Sendmail-compatible milters), such as Postfix and others. A Postfix configuration example is included below.

## What it does

SMTP-stage checks:

- **CONNECT**: checks the connecting IP against **ZEN** (optional)
- **HELO/EHLO**: checks the HELO domain against **DBL** + **ZRD**
- **MAIL FROM**: checks the sender domain against **DBL** + **ZRD**

Policy (as implemented):

- **DBL**: reject only `127.0.1.2`–`127.0.1.99` (“safe to block”)
- **ZRD**: reject `127.0.2.2`–`127.0.2.24` (“domain too young”)
- **ZEN**: reject if `127.0.0.X` where `X ∈ {2,3,4,9,10,11}` by default
- `127.255.255.*` indicates DQS-side error conditions and is treated as **fail-open**

> You need your own [Spamhaus DQS credentials/API key](https://www.spamhaus.com/data-access/free-data-query-service/) (free for low volume non-commercial use) and must comply with Spamhaus terms. This is an independent, unofficial hobby project and is not affiliated with, endorsed by, or sponsored by The Spamhaus Project. “Spamhaus” and “Spamhaus DQS” are trademarks of their respective owners. All other trademarks are the property of their respective owners.


## Repository contents

- `spamhaus-dqs-milter.py` — the milter daemon
- `requirements.txt` — Python dependencies
- `spamhaus-dqs-milter.service` — example systemd unit file (runs the daemon + loads env)

Dependencies:
- `pymilter`
- `dnspython`

## Installation (base dir: `/opt/spamhaus-dqs-milter`)

These steps install into:
- Code: `/opt/spamhaus-dqs-milter`
- Virtualenv: `/opt/spamhaus-dqs-milter/venv`
- Env file: `/etc/spamhaus-dqs-milter.env`
- Default listener: `inet:11332@localhost`

### 1) Create a dedicated service user

```
sudo adduser --system --group --no-create-home --shell /usr/sbin/nologin spamhausmilter
```

### 2) Install the code

```
sudo install -d -o root -g root -m 0755 /opt/spamhaus-dqs-milter
sudo git clone <your-repo-url> /opt/spamhaus-dqs-milter
sudo chown -R root:root /opt/spamhaus-dqs-milter
sudo chmod -R a-w /opt/spamhaus-dqs-milter
```

### 3) Create a virtual environment in `/opt/spamhaus-dqs-milter`

```
sudo python3 -m venv /opt/spamhaus-dqs-milter/venv
sudo /opt/spamhaus-dqs-milter/venv/bin/pip install --upgrade pip
sudo /opt/spamhaus-dqs-milter/venv/bin/pip install -r /opt/spamhaus-dqs-milter/requirements.txt
```


### 4) Create the environment file

The systemd unit loads:
- `/etc/spamhaus-dqs-milter.env`

Create it (see `.env.example` for an example):

```
sudo install -m 0640 -o root -g spamhausmilter /dev/null /etc/spamhaus-dqs-milter.env
sudo nano /etc/spamhaus-dqs-milter.env
```

### 5) Install and start the systemd service

```
sudo cp /opt/spamhaus-dqs-milter/spamhaus-dqs-milter.service /etc/systemd/system/spamhaus-dqs-milter.service
sudo systemctl daemon-reload
sudo systemctl enable --now spamhaus-dqs-milter
```

Logs:
```
sudo systemctl status spamhaus-dqs-milter --no-pager
sudo journalctl -u spamhaus-dqs-milter -f
```

## Integrating with an MTA

This daemon implements the milter protocol and listens on `SPAMHAUS_DQS_LISTEN`
(default `inet:11332@localhost`). Configure your milter-capable MTA to connect to that socket.

### Postfix example

In `/etc/postfix/main.cf`:

```
# Milter integration
smtpd_milters = inet:localhost:11332
non_smtpd_milters = $smtpd_milters

# Recommended: keep mail flowing if the milter is unavailable
milter_default_action = accept

# Often used with milters; adjust if you have specific requirements
milter_protocol = 6
milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}
```

Reload postfix:
```
sudo postfix check
sudo systemctl reload postfix
```

## Configuration (environment variables)

The daemon reads an env file at startup (defaults to `/etc/spamhaus-dqs-milter.env`).
Override the env file path with:

- `SPAMHAUS_DQS_ENV_FILE=/path/to/file`

### Required

- `SPAMHAUS_DQS_API_KEY`  
  Your Spamhaus DQS key (inserted into the DQS query name).

### Core settings

- `SPAMHAUS_DQS_LISTEN` (default: `inet:11332@localhost`)
- `SPAMHAUS_DQS_LOG_LEVEL` (default: `INFO`)
- `SPAMHAUS_DQS_NAMESERVERS` (default: `127.0.0.1,::1`)

### Timeouts (seconds)

- `SPAMHAUS_DQS_MILTER_TIMEOUT` (default: `2`)
- `SPAMHAUS_DQS_DNS_LIFETIME` (default: `1.8`)
- `SPAMHAUS_DQS_DNS_PER_TRY` (default: `0.7`)

The script enforces `DNS_LIFETIME < MILTER_TIMEOUT` with headroom.

### Cache

- `SPAMHAUS_DQS_CACHE_MAX` (default: `20000`)
- `SPAMHAUS_DQS_CACHE_TTL_LISTED` (default: `600`)
- `SPAMHAUS_DQS_CACHE_TTL_UNLISTED` (default: `300`)

### ZEN at CONNECT

- `SPAMHAUS_DQS_ZEN_ENABLE` (default: `1`)
- `SPAMHAUS_DQS_ZEN_REJECT_CODES` (default: `2,3,4,9,10,11`)

### Whitelisting

- `SPAMHAUS_DQS_IP_WHITELIST`  
  Comma-separated IPs (exact match), e.g. `192.0.2.10,2001:db8::1`

- `SPAMHAUS_DQS_DOMAIN_WHITELIST`  
  Comma-separated exact domains (applies to both HELO and MAIL FROM).

- `SPAMHAUS_DQS_DOMAIN_SUFFIX_WHITELIST`  
  Comma-separated suffixes; matches `example.com` and `*.example.com`.

- `SPAMHAUS_DQS_WHITELIST_SKIP_ALL` (default: `0`)  
  If `1` and the connecting IP is whitelisted, skip all checks for that connection.

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0).

## Contributing / Support

Comments, issues, and pull requests are welcome. By submitting a pull request, you agree that your contribution will be licensed under the MPL-2.0.

**Please note:** this is a side project maintained in spare time. I’ll do my best to respond, but I can’t guarantee timelines or provide production support. For bug reports, please include logs (sanitised), your MTA + OS details, and steps to reproduce.

I created this milter because my MTA (not Postfix or Exim) does not have native support for rejected connections at the `CONNECT` or `MAILFROM` stages of the SMTP transaction and I could not find a compatible milter that had the necessary functionality. If such functionality exists elsewhere, please do let me know so that I can reference it here.

## Note on AI assistance

This is a hobby project and some parts of the code and documentation were created with the help of generative AI, with manual review and testing by the author.
