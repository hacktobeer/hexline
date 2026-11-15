# `hexline` — a BBS in Go

**Status:** Approved · **Version:** 0.4 (implemented) · **Date:** 2025-11-15
**Decisions applied:** D1 SSH-only · D2 no ZMODEM/doors · D3 open registration with probation ·
D4 web mirror after v1.0 · D5 QWK deferred · D6 SQLite only · D7 English-only · D8 separate
message/file areas · D9 probation 3 d/10 posts · D10 sysop-only chat channels. See §11.
**Companion document:** [`TASKS.md`](./TASKS.md) (milestones, backlog, acceptance criteria)

---

## 1. Summary

`hexline` is a single-binary, terminal-first Bulletin Board System written in Go. It revives the
classic BBS experience — dial-up-era aesthetics, message conferences, file areas, one-liners,
who's-online — over SSH, with modern operational
hygiene (SQLite, migrations, structured logs, argon2id, ACLs, audit trail, backups).

One process serves many concurrent callers ("nodes"), each with a full-screen ANSI terminal UI.
The sysop's job is a CLI plus an in-BBS admin menu — no web UI in v1.

### Design principles

1. **One binary, one database file.** `bbs serve` needs nothing but a config file and a SQLite file.
2. **Terminal is the product.** Every feature must work at 80×24 with ANSI, degrade gracefully to
   VT100/`--no-ansi`, and never emit raw user bytes to a terminal.
3. **Classic semantics, modern internals.** Keep BBS vocabulary and flow (boards, nodes, new-message
   scan, time left, bulletins). Implement them with typed services, tests, and migrations.
4. **Boring, verifiable dependencies.** Small, audited dependency set; nothing that phones home.
5. **Safe by default.** Registration throttled and probation-gated, content sanitized, uploads
   quarantined, encrypted transport only.

---

## 2. Personas & primary flows

| Persona | Needs |
| --- | --- |
| **Caller** (new user) | Register fast, see what's new, post a message, grab a file, feel the vibe |
| **Regular** | Unread scan across boards, thread subscriptions, private mail, chat, oneliners |
| **Moderator** | Delete/lock/move posts, ban, see reports, act without shell access |
| **Sysop** | Provision areas, manage users, back up, watch health, read audit log |

**First-session flow:** connect → ANSI/CP437 detect → login or new-user registration (handle,
password, optional email, terminal prefs) → MOTD + bulletins + "what's new since your last call"
→ main menu. **Return flow:** login → unread summary with counts → jump to board / mail / files.

**Session flow rules that matter:** idle timeout (default 15 min), clean disconnect on `Ctrl-C` or
`q` from the main menu, live chat channels (global and sysop), and every screen reachable with
single-key hotkeys as well as arrows.

---

## 3. Feature set

### 3.1 v1.0 scope (must ship)

**Access & identity**
- SSH is the only transport (D1): password + optional public-key auth (keys enrolled with
  `bbs admin user key add`), persistent host key, one listener, one auth path, no cleartext option;
  per-IP and per-account login throttling with exponential backoff. Bans apply to both auth methods.
- Guest/demo account (read-only, configurable), open registration with handle rules +
  reserved-name list, password reset by sysop CLI, self-service password change.
- New-user probation (D3): capped posts/day, no uploads, no links; auto-promoted by time + post
  count (defaults 3 days / 10 posts) or manually by a moderator.
- Profiles: handle, real name (private by default), location, signature (ASCII, sanitized, max 4
  lines), timezone, terminal prefs (width, ANSI on/off, CP437 art on/off, pager vs scroll).
- Presence: node IDs, who's online, idle state, and live chat channels (global + sysop).
- Session accounting: login count, last call, time-online stats, per-user message/file counters.

**Message bases**
- Areas (conferences) with description, ordering, ACLs (`read`, `post`, `reply`, `attach`,
  `moderate`), per-area retention and post-rate limits.
- Threads + replies, quoting with attribution (`> ` prefix, `%s wrote:` header), post preview,
  editing, moderator soft delete, lock, sticky, move thread between areas. Readers load the newest
  50 posts and page backwards with `o`, so a huge thread never lands in memory at once.
- Read tracking per user (`last_read_post_id`), unread counts per area and per thread, full
  "new messages" scan across all readable areas, mark-all-read.
- Full-text search (SQLite FTS5) over subject+body with area/author/date filters, snippet
  highlighting.
- Moderation: hide/delete post, lock thread, ban author from area, report queue, mod log;
  report → moderator notification (in-BBS inbox).
- Minimal Markdown subset: paragraphs, `*bold*`, `_italic_`, `` `code` ``, `> quote`, links shown
  as text (no auto-fetch), lists. Rendered width-aware to ANSI; unknown constructs pass through
  as literal text.
- ANSI/CP437 art support for area headers and bulletins: CP437→UTF-8 decoding, `SAUCE00`
  128-byte trailer + `COMNT` comment block stripped, cached rendering with width/iCE handling.

**Private mail**
- Local mail between handles, inbox/sent, read/unread, threading by subject, delete/archive,
  per-user mailbox quota, "you have new mail" badge; optional simple blocklist.

**File areas**
- File areas with ACLs, uploads (quota per user/area, size cap, checksum SHA-256, description,
  extension allow/deny list), download counters and ratings, keyword search.
- Transfer: non-interactive `ssh bbs put AREA/FILE < local` and
  `ssh bbs get AREA/FILE > local` pipe mode (binary-safe, PTY-free). Tokenized HTTP download
  URLs are deferred to v1.x; no in-session binary transfer protocols (D2).
- File detail screen: size, uploader, date, description, checksum, "similar files".

**Community**
- One-liners ("wall") with length cap, moderation, and rolling retention.
- Polls: question, options, single-choice, close date, results after vote, sysop-created.
- Bulletins/MOTD managed from the admin menu; per-user "don't show again" for bulletins.
- Inter-node chat: global channel + sysop channel, scrollback per session, join/leave notices.

**Sysop & operations**
- Admin CLI: `bbs admin user|area|filearea|bulletin|poll|ban ...`, `bbs backup`, `bbs passwd`,
  `bbs migrate`, `bbs doctor` (config + DB + permission sanity check).
- In-BBS sysop menu for the day-to-day (users, areas, bulletins, audit tail, stats, broadcast).
- Config via TOML + `HEXLINE_*` env overrides; strict validation with actionable errors.
- Structured logging (`slog`, JSON or text), per-session correlation ID, audit log table for every
  privileged action (actor, action, target, diff, IP).
- Backups: `bbs backup --out DIR` uses `VACUUM INTO` for a consistent snapshot; documented
  restore path; retention helper.
- Metrics on an opt-in loopback HTTP listener (`/healthz`, `/metrics`); no metrics by default.
- Retention jobs: prune old sessions/audit rows/one-liners per config, nightly at a fixed hour.

### 3.2 Nice-to-have (v1.x, after v1.0)

- Thread subscriptions + "new reply to your post" notices.
- Self-service account deletion (GDPR-ish) and data export.
- Read-only web mirror of public areas (server-rendered, no JS).
- Per-area "files attached to posts", inline image → ASCII preview.
- Two-factor via TOTP for sysop accounts.
- Themes/color schemes, user-selectable; "amiga"/"c64" palettes.
- Mail forwarding to SMTP (opt-in, per user).
- Sysop RSS/Atom of bulletins.

### 3.3 Out of scope

Declined entries need a new explicit decision to re-enter; deferred entries are candidates for v1.x/v2.

| Item | Why / where it goes |
| --- | --- |
| ZMODEM/XMODEM/YMODEM in-session transfer | **Declined, not deferred** (D2): needs raw byte bridging under the TUI and clutters the session. Pipe/HTTP upload+download covers the need. |
| FidoNet echomail/netmail gateway (FTN, BSO, tosser/scanner) | Declined for this project: large protocol surface; belongs in a separate gateway. |
| External "doors" (DOOR32.SYS games) | **Declined** (D2): arbitrarily untrusted executables with PTY bridging is a sysop footgun. If games matter later, build them in-process as first-class features. |
| Telnet / any unencrypted listener | **Declined** (D1): cleartext credentials and a second protocol parser to fuzz. Retro clients that can't do SSH are an accepted loss. |
| RIPscrip / graphical modes | Declined: dead protocol with an incomplete spec. |
| Web app / mobile app | Deferred (D4): read-only mirror after v1.0; no interactive web UI. |
| Real-time federation/ActivityPub | Declined: not a BBS concern. |

### 3.4 Interop (v2 candidate): QWK packets

Classic offline mail: `<BBSID>.QWK` is a ZIP containing `CONTROL.DAT` (system/caller/conference
info), `MESSAGES.DAT` (a packet header block followed by messages as 128-byte header + N×128-byte
text blocks; lines terminate with `0xE3`, not CRLF), one `NNN.NDX` per conference (5-byte entries:
4-byte offset + 1-byte conference), and optional `DOOR.ID`. Replies travel back as `.REP` packets
with the same layout.

It is a simple, static format and a natural fit for a Go exporter/importer — but it is **not** in
v1: there is no single normative spec (the field layouts come from PCBoard/QWKE documentation and
de-facto implementations), so it needs its own conformance fixtures and a mailer story. Design
leaves room: `internal/qwk` boundary and stable message IDs. No licensing or patent restrictions
were found; that is absence of evidence, not a legal opinion.

---

## 4. Architecture

### 4.1 Process & layering

```
  ssh :2222  ──────────▶  transport/ssh  (wish + charmbracelet/ssh)
                            │  one tea.Program per session
                            ▼
                        ┌────────────────────────────────────────────────┐
                        │ tui     shell, screens, keymaps, layout, ANSI  │
                        └────────────────────────────────────────────────┘
                            │  service interfaces (fakes in tests)
                            ▼
                        ┌────────────────────────────────────────────────┐
                        │ service auth, boards, mail, files, presence,   │
                        │         moderation, admin, retention           │
                        └────────────────────────────────────────────────┘
                            │  domain types + repository interfaces
                            ▼
                        ┌────────────────────────────────────────────────┐
                        │ store   sqlite: migrations, queries, FTS5      │
                        └────────────────────────────────────────────────┘

  side paths: admin CLI ──▶ service (same code path, no TUI)
              hub (in-proc pub/sub) ──▶ presence, chat, notifications
              render (sanitize → markup → layout → ANSI) used by tui + art loader
```

Rules: TUI never touches SQL; services never touch `*tea.Model`; store never formats for humans.
`service` interfaces exist so screens can be tested with fakes.

### 4.2 Repository layout

```
cmd/bbs/                 main, subcommand dispatch (serve, migrate, admin, backup, doctor)
internal/config/         TOML schema, env overlay, validation, defaults
internal/domain/         entities, value objects, typed errors, permission constants
internal/store/          sqlite open/pragmas, migrations/*, one file per aggregate
internal/service/        auth, board, mail, filearea, presence, moderation, admin, retention
internal/render/         sanitize.go, markup.go, layout.go, ansi.go, art.go (SAUCE)
internal/tui/            app.go (shell/router), screens/, components/, keys.go, theme.go
internal/transport/ssh/  server, host key mgmt, auth callbacks, session→tea program
internal/hub/            in-process broker: presence, chat, notifications
internal/admin/          CLI command implementations (cobra)
internal/version/        build info (ldflags)
internal/store/migrations/  embedded via embed.FS (must live with the store package)
docs/                    DESIGN.md, TASKS.md, ops.md, deps.md
testdata/                golden renders, sample .ans, fixtures
```

### 4.3 Key technical decisions

| Area | Decision | Rationale |
| --- | --- | --- |
| Language | Go ≥1.25, toolchain pinned to a patched 1.26.x (`govulncheck` clean) | `slog`, modern stdlib; single static binary |
| TUI | Bubble Tea **v1.x** + Lip Gloss v1.x (+ Bubbles v0.21) | v1 is the stable line; v2 was still RC with a breaking `charm.land/*` module rename — not worth the churn for v1.0. `teatest`-testable |
| SSH | `charmbracelet/wish` v1.x + `charmbracelet/ssh` (maintained fork of `gliderlabs/ssh`) | Wish's `bubbletea.Middleware` wires an SSH PTY straight to a `tea.Program` incl. resize; `gliderlabs/ssh` has been frozen since Jan 2025 |
| Transport policy | SSH only — no telnet, no plain TCP (D1) | One auth path, one fuzz surface, credentials never cleartext. Wish's `bubbletea.Middleware` provides PTY+resize for free |
| DB | SQLite (WAL) default; `modernc.org/sqlite` (pure Go) | cgo-free static builds; **FTS5 compiled in by default** (no build tag, unlike `mattn/go-sqlite3`); Postgres out of scope but repository interfaces keep the door open |
| Migrations | Plain SQL files + tiny embedded runner with `schema_migrations` | No ORM; explicit, reviewable SQL |
| Search | FTS5 virtual table, triggers to sync posts | No external search service |
| Config | TOML (`BurntSushi/toml`) + env overrides | Human-editable, no magic |
| CLI | `spf13/cobra` | Subcommand ergonomics; same services as TUI |
| Logging | `log/slog` | Structured, stdlib, zero deps |
| Passwords | argon2id (`x/crypto/argon2`), per-user 128-bit salt, 256-bit tag, versioned params | Memory-hard; params stored per hash to allow future increases |
| Markup | Custom minimal parser (~400 LOC) | Predictable rendering; avoids a Markdown dependency and its HTML assumptions |
| IDs | ULID strings for user-visible entities; int64 for posts (ordering + read pointers) | Sortable, opaque; cheap monotonic ordering |
| Time | UTC in DB, render in user timezone | No DST surprises |
| Deploy | Static binary + systemd unit + Dockerfile (distroless) | Boring ops |

#### 4.3.1 Dependency pins & upgrade posture

Verified 2025-11 (release lines, not exact patch levels; pin exact versions in `go.mod` at M0.1):

| Module | Line to pin | Note |
| --- | --- | --- |
| `github.com/charmbracelet/bubbletea` | v1.3.x | v2 was `rc.1` and renames the import path to `charm.land/bubbletea/v2` |
| `github.com/charmbracelet/lipgloss` | v1.1.x | v2 was `beta.2` (`charm.land/lipgloss/v2`) |
| `github.com/charmbracelet/bubbles` | v0.21.x | v2 line also RC in 2025-11 |
| `github.com/charmbracelet/wish` | v1.4.x | v2 GA'd later with a `charm.land/wish/v2` path; includes an SCP path-traversal advisory fixed in 2.0.x — **we do not use Wish's SCP middleware** |
| `github.com/charmbracelet/ssh` | pseudo-version (no semver tag in 2025-11) | Comment the pseudo-version in `go.mod` with the commit date |
| `modernc.org/sqlite` | latest | FTS5 included; verify with `PRAGMA module_list` in a store test |
| `github.com/spf13/cobra`, `github.com/BurntSushi/toml`, `github.com/oklog/ulid/v2` | latest | Stable, small surface |
| `golang.org/x/crypto`, `golang.org/x/text` | latest | argon2id, CP437 decoding |

**Policy:** no v2 `charm.land/*` migration before v1.0. Revisit as one deliberate task after release,
behind a branch, since it touches imports only (not behaviour). Dependabot/renovate proposes, CI
decides; every new dependency needs a line in `docs/deps.md`.

### 4.4 Rendering pipeline (security-critical)

```
user input ──▶ sanitize (deny-by-default control chars; allow \n, \t)
           ──▶ validate (length, UTF-8, max lines, no bidi/zero-width)
           ──▶ store as plain text (source of truth)
           ──▶ markup parse (AST: paragraph, quote, emph, code, list, link-text)
           ──▶ layout to terminal width (word-wrap, quote gutters, indent)
           ──▶ ANSI render (lipgloss styles; strip if --no-ansi)
           ──▶ terminal
```

- **Never trust stored bytes at render time** either: sanitize again (defense in depth).
- Escape sequences are emitted **only** by the renderer; user text is never passed through.
- `render/sanitize` is fuzz-tested against CSI/OSC/DCS/8-bit C1/overlong-UTF-8 payloads.
- Art files are loaded once at boot, `SAUCE00` trailer and `COMNT` block stripped,
  CP437→UTF-8 decoded (`x/text/encoding/charmap`, SGR preserved), pre-rendered and cached with
  (width, encoding, iCE) keys. Defaults remain 80×24/80×25 for non-resizing clients.

### 4.5 Concurrency model

- One goroutine per connection running a `tea.Program`; teardown on disconnect cancels context.
- `hub` is an in-process broker: `Publish(event)`, `Subscribe(pattern) → chan Event`; backpressure
  via bounded buffers and drop-oldest for chat (never block a session).
- Presence is in-memory truth with periodic DB checkpoint (`sessions` table rows for forensics,
  not for "who's online").
- SQLite: WAL, `busy_timeout=5000`, `synchronous=NORMAL`, single writer discipline; long reports
  and backups use separate connections. All writes go through services ⇒ short transactions.
- Graceful shutdown: stop accepting, notify sessions ("system going down in 30s"), drain ≤10 s,
  checkpoint WAL.

### 4.6 Errors & user experience

Typed domain errors (`domain.ErrNotFound`, `ErrPermission`, `ErrConflict`, `ErrRateLimited`,
`ErrQuota`) mapped once to friendly one-line messages plus a recovery hint. Unexpected errors get
a correlation ID shown to the user and logged at `error` with the same ID. Panics in a session are
recovered, logged with stack, and disconnect only that session.

---

## 5. Data model

SQLite, `STRICT` tables, `WITHOUT ROWID` where appropriate, FK enforcement on.

```
users(id PK ulid, handle UNIQUE COLLATE NOCASE, email NULL, pass_hash, pass_params,
      role, created_at, last_call_at, calls, time_online_s, status[active|suspended|deleted],
      timezone, prefs_json, promoted_at, is_guest)
                                          -- single role in v1; add user_roles when multi-role lands
areas(id PK ulid, tag UNIQUE, name, description, sort_order, acl_read, acl_post, acl_moderate,
      retention_days NULL, rate_limit_per_hour, is_public, created_at)
threads(id PK ulid, area_id FK, subject, author_id, created_at, last_post_at,
        post_count, is_sticky, is_locked, is_deleted, moved_from_area_id NULL)
posts(id PK int64 AUTOINCREMENT, thread_id FK, author_id, body, created_at, edited_at,
      is_deleted, deleted_by, delete_reason, ip_hash NULL)
ssh_keys(fingerprint PK, user_id FK, key, created_at)
thread_reads(user_id, thread_id, last_read_post_id, read_at, PRIMARY KEY(user_id, thread_id))
posts_fts(subject, body)                  -- contentless/external-content FTS5 + sync triggers

mail(id PK ulid, from_id, to_id, subject, body, created_at, read_at NULL,
     is_deleted_by_from, is_deleted_by_to, thread_key)
mail_blocks(owner_id, blocked_id)

file_areas(id PK ulid, tag UNIQUE, name, description, acl_read, acl_upload, quota_bytes)
files(id PK ulid, area_id FK, filename, stored_path, size_bytes, sha256, description,
      uploader_id, uploaded_at, download_count, is_deleted, scan_status)
file_downloads(file_id, user_id, at, bytes_sent)
file_ratings(file_id, user_id, stars, at)

oneliners(id PK int64, author_id, body, created_at, is_hidden, hidden_by)
polls(id PK ulid, question, created_by, created_at, closes_at, is_multi, is_hidden)
poll_options(id PK int64, poll_id, label, sort_order)
poll_votes(poll_id, option_id, user_id, at, PRIMARY KEY(poll_id, user_id))

bulletins(id PK ulid, title, body, sort_order, is_active, created_at, updated_at)
bulletin_dismissals(user_id, bulletin_id, PRIMARY KEY(user_id, bulletin_id))
bans(id PK ulid, scope[ip|handle], value, reason, created_by, created_at, expires_at NULL)
sessions(id PK ulid, user_id, node, started_at, ended_at NULL, ip_hash, client)
login_attempts(id PK int, at, ip_hash, handle, ok)
audit_log(id PK int64, at, actor_id NULL, action, target_kind, target_id, detail_json, ip_hash)
settings(key PK, value)                   -- runtime-overridable knobs (MOTD toggles, etc.)
schema_migrations(version PK, applied_at)
```

**Notes**
- `last_read_post_id` gives O(1) unread counts: `COUNT(*) WHERE thread_id=? AND id > ?`.
- Post bodies are capped (default 32 KiB, 1000 lines); file bodies live on disk under
  `<data_dir>/files/<area>/<ulid>` with the original name only in the DB (no traversal surface).
- `ip_hash` = HMAC-SHA256(server_secret, ip) so abuse correlation survives without storing PII.
- Soft deletes everywhere; a privileged purge job is the only hard delete, and it logs counts.
- Indexes: `posts(thread_id, id)`, `threads(area_id, last_post_at DESC)`, `mail(to_id, read_at)`,
  `audit_log(at DESC)`, `files(area_id, uploaded_at DESC)`, `posts(author_id, created_at)`.

---

## 6. Security model

| Threat | Control |
| --- | --- |
| Credential theft | argon2id defaults `m=32 MiB, t=3, p=2` (between RFC 9106's second recommendation and the OWASP minimum), configurable via `[security]`, versioned per row and rehashed on login; a semaphore caps concurrent hashes (default 2) so login bursts cannot exhaust RAM; SSH key auth encouraged; no cleartext transport exists (D1) |
| Online guessing | Per-IP + per-account exponential backoff, generic "invalid handle or password", audit + optional auto-ban after N failures |
| Terminal escape injection | Deny-by-default sanitizer at write **and** render, fuzz-tested; renderer-owned escapes only |
| Stored XSS-equivalents in web mirror (future) | HTML-escape at render; mirror is text-only |
| Spam/flood | Per-user post/upload/login rate limits, new-user probation (post cap + mod review flag), CAPTCHA-free but registration delay |
| Privilege escalation | Central `authz.Allowed(actor, action, resource)`; no screen checks permissions ad hoc; table-driven tests for every role×action |
| Path traversal in file areas | Server-generated storage names, `filepath.Base` on input, storage root resolution check |
| Malicious uploads | Extension allow/deny, size caps, `scan_status` quarantine + optional ClamAV hook, never served with a sniffable inline type |
| Session hijack (in-BBS) | Sessions are per-connection, no bearer tokens; short-lived signed download URLs bound to user+file |
| DoS | Connection cap, per-IP cap, input line cap, message size cap, idle timeout, per-frame read caps |
| Data loss | WAL + nightly `VACUUM INTO` backup, restore doc, `bbs doctor` verifying integrity |
| Secret leakage | Config secrets from env/file with 0600 check; logs redact auth fields; no request bodies in logs |

**Moderation powers** are capability-scoped (moderator in area X only). **Sysop** actions are always
audited. Bans are scoped (IP/handle) and time-bounded by default.

---

## 7. Non-functional targets

Measured 2026-11-15 on the development host (8 vCPU, loopback) with `cmd/loadgen`; see
`docs/ops.md` §Capacity for the procedure.

| Property | Target |
| --- | --- |
| Keystroke→render latency | p95 < 50 ms (LAN/SSH), p99 < 150 ms. Measured on loopback: p95 0.2 ms, p99 19 ms |
| Login latency (argon2id bound) | ~0.25 s single caller, ~0.65 s p95 with 20 concurrent logins (hash semaphore 4) |
| Concurrent sessions | Verified 100 concurrent TUI sessions on 8 vCPU with 0 errors; cap is `transport.ssh.max_sessions` (default 200) |
| Search | FTS5 + bm25; not benchmarked at 1M posts (correctness covered by tests) |
| Cold start | < 1 s to accepting connections (measured ~0.4 s incl. migrations check) |
| Binary size | < 25 MB static |
| Footprint | 20 MB RSS fresh; ~300 MB after a 100-session burst (Go retains heap; `security.argon_*` and `GOMEMLIMIT` are the levers — see ops.md) |
| Availability | Restart-safe: no in-flight write lost, sessions get a clean "going down" notice |
| Data durability | WAL + `synchronous=NORMAL`; documented RPO ≤ 1 checkpoint, RTO < 5 min |

---

## 8. Testing & verification strategy

- **Unit:** `render` (golden files per width 40/80/132 × ANSI on/off), sanitizer (fuzz + corpus),
  markup parser (table tests), permissions (matrix), config validation.
- **Store:** every migration applied to a fresh temp SQLite; repository round-trips; unread
  counting and retention job edge cases; concurrent write smoke test.
- **Service:** fakes for hub/clock; auth throttling with a fake clock.
- **TUI:** `teatest` golden frames for the main screens; keymap coverage test (every screen
  reachable, `esc` always safe).
- **End-to-end:** in-process server + real SSH client (`x/crypto/ssh`) driving register → post →
  read → mail → upload → download, plus disconnect/resize/reconnect cases.
- **Load:** `cmd/loadgen` establishing N sessions and replaying a scripted tour; report p95/p99.
- **Security:** `gosec`, `govulncheck`, dependency review, manual abuse checklist in `docs/ops.md`.
- **CI:** `go vet`, `golangci-lint`, race-enabled tests, `go test -run Fuzz -fuzztime 30s` smoke,
  cross-build linux/amd64+arm64, Docker image build.

---

## 9. Operations

- **Config:** single `hexline.toml` (see example in plan task M0.3) with sections `server`,
  `transport.ssh`, `database`, `storage`, `limits`, `retention`, `metrics`,
  `ui`. Validation errors name the exact key and the fix.
- **First run:** `bbs migrate && bbs admin user create --handle sysop --role sysop` then
  `bbs serve`. Host key auto-generated into data dir (0600). Seed data: "General" area, "Sysop"
  area, welcome bulletin, sample oneliner.
- **Backup:** cron `bbs backup --out /backups --keep 14`; restore = stop, replace `hexline.db`,
  start, `bbs doctor`.
- **Upgrade:** binary swap + `bbs migrate` (forward-only, each migration transactional); version
  compatibility check refuses to start against a newer schema.
- **Monitoring:** `journalctl -u hexline -o json`, `/metrics` (sessions, posts, logins, latency
  histogram), `/healthz`.

---

## 10. Risks & mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Bubble Tea over SSH adds per-keystroke render cost | Latency at 200 sessions | Profile early (M1), render diffing, avoid full redraws, cap repaint rate |
| SQLite write contention under chat/audit load | Stalls | Short transactions, WAL, batch audit inserts, hub keeps chat in memory only |
| Scope creep into FidoNet/doors | v1 never ships | Explicit non-goals (§3.3), declined items need a new decision to re-enter |
| Content sanitizer bypass | Terminal compromise | Fuzz + allowlist design + double sanitize at render |
| Single-maintainer bus factor | Stagnation | Docs-first, migrations, tests as spec, `docs/ops.md` runbook |
| No legacy-transport fallback | Old clients/hardware can't connect | Accepted (D1); SSH clients exist for every platform incl. retro hardware; document terminal requirements |
| Charm v2 module rename (`charm.land/*`) | Ecosystem drift, forks | Pinned v1 lines in §4.3.1; v2 migration is a single post-1.0 task, not a surprise |

## 11. Decisions & open questions

### 11.1 Resolved (review, 2025-11-15)

| ID | Decision | Consequence |
| --- | --- | --- |
| D1 | **SSH only — no telnet, no plain TCP.** | `transport/telnet` dropped from the layout; one auth path; cleartext credential risk eliminated; legacy non-SSH clients knowingly unsupported. Simplified M1.6 (no NAWS) and removed a test bed from M6.1. |
| D2 | **No ZMODEM/XMODEM/YMODEM, no external doors — not deferred, declined.** | Removes the PTY byte-bridging problem entirely and keeps sessions TUI-only. File transfer is `ssh bbs get` pipe + tokenized HTTP. Games, if wanted later, are in-process features, not subprocesses. |
| D3 | **Registration: open, with new-user probation.** | Default config: registrations open, new accounts capped (posts/day, no uploads, no links) until promoted by time+activity or a moderator. Configurable to invite-only/sysop-approval later — the schema and admin CLI support it from day one. |
| D4 | **Read-only web mirror comes after v1.0.** | v1.0 stays terminal-only; the mirror is the first v1.x item and reuses `service` + `render` with HTML escaping instead of ANSI. |
| D5 | **QWK/REP interop deferred to v2** (export first, then import). | No QWK code in v1.0; `internal/qwk` stays an empty package boundary until then. |
| D6 | **SQLite only.** | `modernc.org/sqlite`, one file, WAL. Repository interfaces stay narrow so a Postgres store remains possible. |
| D7 | **English-only UI.** | All user-facing strings live in `internal/tui/strings.go` as plain constants, so i18n is a mechanical change later. |
| D8 | **Separate message areas and file areas** (classic split, not a unified "forum"). | Two independent area tables, two menus, two ACL families. |
| D9 | **Probation: auto-promote at 3 days *and* 10 posts; moderators can promote early.** | Both thresholds configurable in `hexline.toml`; promotion is an audited action. |
| D10 | **Chat channels: global + sysop only.** | No user-created channels; joining is a toggle, not a subscription system. |

### 11.2 Still open

None. D1–D10 cover every prior open question; new questions should be raised as a dated entry
in this section and resolved into 11.1.

---

## 12. References (checked 2025-11)

- Wish — Bubble Tea over SSH: https://github.com/charmbracelet/wish · v1.0.0 notes: https://github.com/charmbracelet/wish/releases/tag/v1.0.0
- `gliderlabs/ssh` (frozen): https://github.com/gliderlabs/ssh/releases
- Bubble Tea v2 RC changelog: https://go.libhunt.com/bubbletea-changelog/2.0.0-rc.1 · Lip Gloss v2 beta: https://github.com/charmbracelet/lipgloss/releases/tag/v2.0.0-beta.2
- QWK structure: https://annex.retroarchive.org/cdrom/nightowl-022/007A/QWKEINFO/FILENAME.TXT · field layout: https://swag.outpostbbs.net/MAIL/0011.PAS.html · https://en.wikipedia.org/wiki/QWK_(file_format)
- SAUCE metadata: https://www.acid.org/info/sauce/sauce.htm
- RIPscrip (legacy, incomplete spec): https://en.wikipedia.org/wiki/RIPscrip
- `modernc.org/sqlite`: https://pkg.go.dev/modernc.org/sqlite · `golang.org/x/crypto/argon2`: https://pkg.go.dev/golang.org/x/crypto/argon2
- Argon2id params: RFC 9106 §4 https://datatracker.ietf.org/doc/html/rfc9106#name-recommendations · OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- CP437 decoding: https://pkg.go.dev/golang.org/x/text/encoding/charmap
