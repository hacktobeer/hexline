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

## Docker

The image is distroless (no shell, no package manager, ~17 MB) and runs as UID 65532. All state
lives in `/data`: SQLite database, SSH host key, uploads, backups.

Published images live at `ghcr.io/hacktobeer/hexline` (see Releasing); build locally with
`docker build -t hexline .`.

```sh
# first run (one-shot container, same volume)
docker volume create hexline-data
docker run --rm -v hexline-data:/data hexline admin user create --handle sysop --role sysop

# serve
docker run -d --name hexline -p 2222:2222 -v hexline-data:/data hexline
ssh -p 2222 sysop@127.0.0.1
```

`HEXLINE_DATA_DIR`, `HEXLINE_SSH_ADDRESS` and JSON logging are already set in the image. Override
anything with `-e`, or mount a config file and run `serve --config /data/hexline.toml`.

Compose: copy `docker-compose.example.yml` to `docker-compose.yml`, then
`docker compose run --rm hexline admin user create --handle sysop --role sysop` and
`docker compose up -d`.

Notes:

- **Bind mounts** must be writable by UID 65532: `mkdir data && sudo chown 65532:65532 data`.
  Named volumes inherit the image's ownership and just work.
- **No shell**: run admin commands as the entrypoint
  (`docker run --rm -v hexline-data:/data hexline admin user list`) or
  `docker exec hexline /usr/local/bin/bbs admin stats`.
- **Backups**: `docker exec hexline /usr/local/bin/bbs backup --out /data/backups`, then
  `docker cp hexline:/data/backups ./backups`. Also copy `/data/host_ed25519`; losing it makes
  callers see a host-key warning.
- **Upgrades**: rebuild/pull the image, `docker rm -f hexline`, start the new one. `serve` applies
  migrations on boot (`--migrate=false` disables that); take a backup first.
- **Metrics** are off by default. Inside a container the loopback default is unreachable from the
  host: set `HEXLINE_METRICS=true` and `HEXLINE_METRICS_ADDR=0.0.0.0:9101`, publish 9101, and
  restrict it at the firewall. `/healthz` and `/metrics` then answer.
- **Timezone data** is embedded in the binary, so caller profiles can pick any zone without
  tzdata in the image.
- **Architectures**: `docker buildx build --platform linux/amd64,linux/arm64 -t hexline .`.

## Configuration

Every `hexline.toml` key has a `HEXLINE_*` environment override (see `internal/config/config.go`
for the exact list): `HEXLINE_DATA_DIR`, `HEXLINE_SSH_ADDRESS`, `HEXLINE_SSH_HOST_KEY`,
`HEXLINE_DB_PATH`, `HEXLINE_FILES_DIR`, `HEXLINE_MAX_UPLOAD_BYTES`, `HEXLINE_SSH_MAX_SESSIONS`,
`HEXLINE_SSH_MAX_PER_IP`, `HEXLINE_SSH_IDLE_TIMEOUT`, `HEXLINE_SSH_PUBKEY`, `HEXLINE_METRICS`,
`HEXLINE_METRICS_ADDR`, `HEXLINE_REGISTRATION_OPEN`, `HEXLINE_PROBATION_DAYS`,
`HEXLINE_PROBATION_POSTS`, `HEXLINE_ARGON_MEMORY_KIB`, `HEXLINE_ARGON_CONCURRENCY`,
`HEXLINE_LOG_LEVEL`, `HEXLINE_LOG_FORMAT`.

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

## Retention

```sh
bbs admin prune        # report what would be deleted (default is a dry run)
bbs admin prune --yes  # delete sessions, audit rows, oneliners and soft-deleted posts
```

Categories come from `[retention]`; a zero disables that category. Pruning is permanent: the audit
trail is what you need after an incident, so run the dry run first and keep `audit_days` generous.

## Releasing

Releases are tag-driven and automated by `.github/workflows/release.yml` (GoReleaser v2):

```sh
git tag -a v1.0.0 -m "hexline 1.0.0"
git push origin v1.0.0
```

The workflow runs the test suite, then publishes a GitHub release with static `linux`, `darwin`
and `windows` binaries for `amd64` and `arm64`. Unix targets ship as `.tar.gz`, Windows as `.zip`
(with `bbs.exe`); every archive includes `README.md`, `docs/*.md` and `hexline.example.toml`, and a
`checksums.txt` covers all of them. The changelog groups `feat:` and `fix:` commits and
drops docs/test/chore/ci/build noise. `bbs version` reports the tag, commit and build date baked in
with `-X` ldflags.

Dry-run locally before tagging:

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=publish   # writes dist/
```

CI validates the config on every push.

The same tag builds and pushes a multi-arch container image (`linux/amd64`, `linux/arm64`) to the
GitHub Container Registry, after the release job succeeds:

```sh
docker pull ghcr.io/hacktobeer/hexline:1.0.0
# also tagged :1.0, :1 and :latest (prereleases are not tagged latest)
```

Version, commit and build date are baked into both the binaries and the image. The first push
creates a private GHCR package: set its visibility to public in the package settings if you want
anonymous pulls.

## Upgrade

1. `bbs backup`
2. Stop the service.
3. Replace the binary.
4. `bbs migrate`
5. Start the service.

Migrations are forward-only and transactional. Starting a newer database with an older binary is
refused (`schema is newer than this binary`).

## Capacity and tuning

Measured with `cmd/loadgen` on loopback (8 vCPU). Numbers are for the default configuration unless
noted.

| Run | Result |
| --- | --- |
| Single login (`ssh … whoami`, incl. handshake + argon2id) | ~0.27 s |
| 10 concurrent TUI sessions | session p50 0.16 s, keystroke p95 0.2 ms |
| 100 concurrent TUI sessions | 0 errors, keystroke p95 ~18 ms, p99 ~19 ms, session p50 ~3.1 s |
| 100 concurrent logins | argon2 queue: `argon_concurrency / argon_memory_kib` dominate |

Memory: a fresh server is ~20 MB RSS. A 100-session burst leaves ~300 MB RSS even after the board
empties: Go retains heap, and argon2 allocates large arenas. Levers, in order of effect:

1. `[security] argon_memory_kib` (default 32768) with `argon_concurrency` (default 2). Peak hashing
   memory is roughly `concurrency * memory_kib`. 19 MiB / 1 concurrency is the OWASP floor and cuts
   both memory and login latency.
2. `GOMEMLIMIT=512MiB` (or lower) to make the GC work harder instead of growing the heap.
3. `GOGC=50` for a smaller heap at the cost of more CPU.
4. `transport.ssh.max_sessions` if you would rather refuse callers than serve them slowly.

Login storms are hash-bound by design: 100 simultaneous logins queue behind `argon_concurrency`.
Normal call patterns never approach this.

```sh
# measure it yourself; raise max_per_ip or run from several source addresses
HEXLINE_SSH_MAX_PER_IP=200 ./bbs serve &
command -v sshpass >/dev/null && go run ./cmd/loadgen -addr 127.0.0.1:2222 \
  -handle sysop -password '…' -sessions 100 -duration 15s -mode tui
```

`loadgen` reports session-lifecycle percentiles and a keystroke→render proxy (time from a keypress
to the next output chunk).

## Monitoring

- `journalctl -u hexline -o json` — structured slog lines, `session_id` per connection.
- `metrics.enabled = true` exposes `/metrics` and `/healthz` on a loopback address (default
  `127.0.0.1:9101`): sessions active/total, online callers, database size.
- `bbs doctor` — config, `PRAGMA integrity_check`, host key, filesystem writability, account count.

`govulncheck ./...` is clean with the pinned toolchain; run it after dependency updates.

Signals worth alerting on: `ssh auth rejected` spikes, `audit write failed`, `download interrupted`
spikes, disk usage of `data_dir`.

## Moderation and abuse

- Suspended accounts cannot log in (`bbs admin user status HANDLE suspended`).
- Bans: `bbs admin ban add --scope handle --value X --reason ...`, or `--scope ip --value <hash>`
  with the 22-character `ip_hash` shown in the audit log (a raw IP is rejected). Expired bans are
  ignored, and both password and key logins check them.
- SSH keys: `bbs admin user key add HANDLE ~/.ssh/id_ed25519.pub`, `key list HANDLE`,
  `key remove HANDLE FINGERPRINT`. Key login is disabled entirely with `transport.ssh.allow_pubkey = false`.
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
