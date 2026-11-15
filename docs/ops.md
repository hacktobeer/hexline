# Operations runbook

## Install

```sh
CGO_ENABLED=0 go build -trimpath -o bbs ./cmd/bbs
install -m 0755 bbs /usr/local/bin/bbs
```

Nothing else is required: one binary, one SQLite file, one SSH port.

## First run

```sh
mkdir -p /var/lib/hexline && chown hexline:hexline /var/lib/hexline
cp hexline.example.toml /etc/hexline.toml   # edit to taste

sudo -u hexline bbs --config /etc/hexline.toml migrate
sudo -u hexline bbs --config /etc/hexline.toml admin user create --handle sysop --role sysop
# prints a generated password once; change it after first login (Settings → p)

sudo -u hexline bbs --config /etc/hexline.toml serve
```

The host key is generated on first serve at `server.data_dir/host_ed25519` (0600). Back it up with
the database: callers see a host-key-changed warning if it is lost.

## systemd

```ini
[Unit]
Description=hexline BBS
After=network-online.target

[Service]
User=hexline
Group=hexline
ExecStart=/usr/local/bin/bbs --config /etc/hexline.toml serve
Restart=on-failure
RestartSec=2
StateDirectory=hexline
Environment=HEXLINE_LOG_FORMAT=json
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hexline
CapabilityBoundingSet=
AmbientCapabilities=
# Port 2222 is unprivileged; no capabilities needed.

[Install]
WantedBy=multi-user.target
```

`Port 22` is possible with `AmbientCapabilities=CAP_NET_BIND_SERVICE` or an nginx/HAProxy stream
front-end. Prefer the stream front-end if you need per-IP rate limiting before SSH.

## Configuration

Every `hexline.toml` key has a `HEXLINE_*` environment override (see `internal/config/config.go`
for the exact list): `HEXLINE_DATA_DIR`, `HEXLINE_SSH_ADDRESS`, `HEXLINE_SSH_HOST_KEY`,
`HEXLINE_DB_PATH`, `HEXLINE_FILES_DIR`, `HEXLINE_MAX_UPLOAD_BYTES`, `HEXLINE_SSH_MAX_SESSIONS`,
`HEXLINE_SSH_MAX_PER_IP`, `HEXLINE_SSH_IDLE_TIMEOUT`, `HEXLINE_SSH_PUBKEY`, `HEXLINE_METRICS`,
`HEXLINE_METRICS_ADDR`, `HEXLINE_REGISTRATION_OPEN`, `HEXLINE_PROBATION_DAYS`,
`HEXLINE_PROBATION_POSTS`, `HEXLINE_LOG_LEVEL`, `HEXLINE_LOG_FORMAT`.

Invalid keys are rejected at startup with the key name and the fix. There is no hot reload:
config is read at boot.

## Backup and restore

```sh
bbs backup --out /var/backups/hexline --keep 14   # VACUUM INTO, safe while serving
```

Restore:

```sh
systemctl stop hexline
cp /var/backups/hexline/hexline-YYYYMMDD-HHMMSS.db /var/lib/hexline/hexline.db
rm -f /var/lib/hexline/hexline.db-wal /var/lib/hexline/hexline.db-shm
systemctl start hexline
bbs doctor --config /etc/hexline.toml    # integrity_check + schema + filesystem
```

Back up `files/` (uploads) separately with your usual file-level backup; it is content-addressed by
ULID, never rewritten in place.

## Upgrade

1. `bbs backup`
2. Stop the service.
3. Replace the binary.
4. `bbs migrate`
5. Start the service.

Migrations are forward-only and transactional. Starting a newer database with an older binary is
refused (`schema is newer than this binary`).

## Monitoring

- `journalctl -u hexline -o json` — structured slog lines, `session_id` per connection.
- `metrics.enabled = true` exposes `/metrics` and `/healthz` on a loopback address (default
  `127.0.0.1:9101`): sessions active/total, online callers, database size.
- `bbs doctor` — config, `PRAGMA integrity_check`, host key, filesystem writability, account count.

Signals worth alerting on: `ssh auth rejected` spikes, `audit write failed`, `download interrupted`
spikes, disk usage of `data_dir`.

## Moderation and abuse

- Suspended accounts cannot log in (`bbs admin user status HANDLE suspended`).
- Bans: `bbs admin ban add --handle X --reason ...`, `--ip <hash>` using the `ip_hash` shown in the
  audit log. Expired bans are ignored.
- Escape-sequence injection is blocked at write and render time; if you find a bypass, capture the
  bytes and file a security issue. Keep the sanitizer fuzz corpus updated.
- Uploads land as `scan_status = clean`; wire an external scanner before opening uploads to
  untrusted users (M6 hook).
- Rate limits: posts/hour, one-liners, chat/minute, login attempts/window, per-IP session caps.
  Defaults live in `[limits]`.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `all nodes for your address are busy` | `transport.ssh.max_per_ip` reached (NAT, load test) |
| `invalid handle or password` for a new caller | handle taken; ask them to connect with a different handle |
| `database is locked` | another process holds the DB (editor, backup script); only one `bbs serve` per DB |
| TUI garbage after upgrade | terminal width detection; resize the window or set `ui.default_width` |
| `schema is newer than this binary` | binary rolled back without restoring its backup |
