# `hexline` — implementation plan

Companion to [`DESIGN.md`](./DESIGN.md) (v0.2). Forward-only, milestone-gated. Estimates are
**dev-days for one experienced Go developer** including tests and docs, not calendar days.

**Locked decisions (DESIGN §11.1):** D1 SSH only — no telnet task exists anywhere below.
D2 no ZMODEM, no external doors — file transfer is `ssh bbs get` pipe + tokenized HTTP.
D3 open registration with new-user probation (M1.3 + M5.8). D4 web mirror is v1.x, after release.

## Implementation status (2026-11-15)

| Milestone | State | Notes |
| --- | --- | --- |
| M0 Foundation | **done** | toolchain pinned to a patched 1.26.x, repo layout, config, slog, store+migrations, cobra CLI, CI, distroless image |
| M1 Sessions/accounts/shell | **done** | SSH+host key, argon2id with configurable cost, throttling, registration, TUI shell, prefs, help, presence nodes |
| M2 Message bases | **done** | areas/threads/posts, quoting, edit, soft delete, lock/sticky/move, unread math, FTS5 search, moderation with audit |
| M3 Mail + files | **done** (minus HTTP URLs) | inbox/sent, read flags, thread keys, quota, blocklist; file upload/download via `ssh put`/`get`, SHA-256, ratings; tokenized HTTP download deferred to v1.x |
| M4 Community | **done** | one-liners, polls, bulletins + dismissals, live chat (global/sysop, in-memory), who's-online |
| M5 Sysop & ops | **done** | sysop CLI (area/filearea/bulletin/poll/ban/audit/stats/prune/broadcast), in-BBS menu, audit, backup, doctor, metrics, retention, probation promotion |
| M6 Hardening | **partly** | e2e over real SSH + 100-session load run + `govulncheck` clean + fuzz/race/traversal tests are done; `gosec`/`golangci-lint` are wired in CI/Makefile but not installed in this environment; releases are automated (`.goreleaser.yaml` + tag workflow) but no tag has been cut yet |

Deviations worth reviewing:

- File transfer is pipe-only (`ssh bbs put|get`); the tokenized HTTP download URL is v1.x.
- Search filters by area only; author/date filters and snippet highlighting are not exposed in the UI.
- Post editing is not limited to a grace window; moderators can edit any post in their area.
- Last callers, sysop page/interrupt, per-user time budget and post restore were promised by the
  first draft of the docs and are not implemented; they are tracked as X6-X9 instead.
- Mail has no archive/search; per-side soft delete covers the "delete" half of "delete/archive".
- Chat history is in-memory per process; a restart clears scrollback (by design, no table).
- `bbs admin broadcast` publishes to the calling process's broker, so it only reaches live sessions
  when run inside `serve`; the in-BBS broadcast screen is the live path. A CLI→server bridge is a
  v1.x candidate.
- Metrics are opt-in and loopback-first; non-loopback binds log a warning.

Not started (correctly): v1.x/web mirror, QWK, Postgres, TOTP/themes, ZMODEM, doors.

**Ground rules**

- Every task lands with tests, passes `go vet` + `golangci-lint` + race tests, and updates docs.
- No milestone starts before the previous milestone's *exit criteria* are met, but tasks marked
  **∥** can proceed in parallel within a milestone.
- "Done" means: merged, exercised end-to-end manually over a real SSH client, and no known
  security regression.

---

## M0 — Foundation (≈4 d) · blocks everything

| ID | Task | Acceptance | Est | Deps |
| --- | --- | --- | --- | --- |
| M0.1 | Bootstrap toolchain: install Go 1.26.x (patched), `golangci-lint`, `govulncheck`; pin versions in `.tool-versions` + `Makefile`, pin Go module versions per DESIGN §4.3.1, start `docs/deps.md` | `go version`, `make lint` work from clean checkout; every module pinned with justification; pseudo-versions carry commit dates | 0.5 | — |
| M0.2 | Repo skeleton per DESIGN §4.2, `go.mod`, license, README, CONTRIBUTING, `.gitignore` | `go build ./...` green; package boundaries match layout | 0.5 | M0.1 |
| M0.3 | Config package: TOML schema, env overlay, defaults, strict validation, `hexline.example.toml` | Table tests for valid/invalid configs; invalid key errors name key + fix; example file loads | 1 | M0.2 |
| M0.4 | Logging: `slog` setup (text/json), levels, per-session correlation ID helper | Logs include `session_id`; secrets redacted (test) | 0.5 | M0.2 |
| M0.5 | Store bootstrap: open SQLite with pragmas (WAL, FK, busy_timeout), embedded migration runner, `schema_migrations` | Migrations apply/re-apply idempotently on temp DB; refuses to start on newer schema | 1 | M0.2 |
| M0.6 | CLI skeleton (`cobra`): `serve`, `migrate`, `admin`, `backup`, `doctor`, `version` | `bbs --help` lists commands; `version` prints build info via ldflags | 0.5 | M0.2 |
| M0.7 | CI: vet, lint, race tests, fuzz smoke, cross-build amd64/arm64, Dockerfile (distroless) | CI green on empty feature set; image runs `bbs version` | 1 | M0.2, M0.6 |
| M0.8 | Baseline `internal/domain` types, typed errors, permission constants, ULID helper | Compiles; errors map to user messages in one place | 0.5 | M0.2 |

**Exit:** `make build && ./bbs migrate --db /tmp/t.db && ./bbs doctor` succeeds; CI green.

---

## M1 — Sessions, accounts, terminal shell (≈5 d) · critical path

| ID | Task | Acceptance | Est | Deps |
| --- | --- | --- | --- | --- |
| M1.1 | SSH transport: `wish` server, persistent host key (0600, auto-gen), connection limits | `ssh -p 2222 localhost` connects; host key stable across restarts; cap enforced with friendly message | 1 | M0 |
| M1.2 | Auth: password (argon2id + versioned params), optional pubkey → user mapping, generic failure message, per-IP/per-account exponential backoff | Unit tests with fake clock; N failures ⇒ lockout window; timing-safe compare | 1.5 | M1.1, M0.8 |
| M1.3 | Registration flow: open registration, handle rules, reserved names, password policy, optional email, timezone/prefs; guest account; new accounts created in `probation` (D3) | Register over real SSH in e2e test; duplicate handle rejected case-insensitively; new user row carries probation flags + caps | 1.25 | M1.2 |
| M1.4 | TUI app shell: router/stack, header/footer, help bar, keymap registry, quit-confirm, `--no-ansi` fallback | `teatest` golden frames at 80×24; every screen reachable; `esc` always safe | 1.5 | M1.1 |
| M1.5 | Main menu + MOTD + who's-online + last callers; session limits (idle warn, time-left) | Manual: two terminals show each other online; idle warning then disconnect | 1 | M1.3, M1.4 |
| M1.6 | Preserve terminal prefs (width from SSH PTY resize, ANSI/CP437 toggles) and apply at render | 40/80/132-column golden renders; resize event updates layout; non-resizing clients default 80×24 | 0.5 | M1.4 |
| M1.7 | ∥ `internal/render`: sanitizer (deny-by-default control chars) + fuzz corpus; plain-text wrap | Fuzz 30 s clean; CSI/OSC/DCS/C1 payload corpus rejected; golden wraps | 1 | M0.2 |

**Exit:** a new caller can register (into probation), log in over SSH, see MOTD/who's-online, change
prefs, log out. No session can print unsanitized input.

---

## M2 — Message bases (≈8 d) · product core

| ID | Task | Acceptance | Est | Deps |
| --- | --- | --- | --- | --- |
| M2.1 | Migrations + store for `areas`, `threads`, `posts`, `thread_reads`; seed "General" + "Sysop" areas | Round-trip tests; FK + index coverage asserted | 1 | M0.5 |
| M2.2 | Area list + area index screens (unread counts, last post meta, ACL-filtered) | Golden frames; unauthorized areas invisible, direct access denied | 1 | M2.1, M1.4 |
| M2.3 | Thread list: paging/sorting, sticky/locked markers, unread bold, jump-to-first-unread | Store test for unread math; golden list at 80 cols | 1 | M2.2 |
| M2.4 | Post reader: pager, quote, next/prev, author info, reply tree flattening | Manual read of 100-post thread; no render artifacts | 1 | M2.3 |
| M2.5 | Composer: line editor, preview, edit window, cancel, size caps, post-rate limit | e2e: create/edit/delete within grace; oversize rejected with message | 1.5 | M2.4 |
| M2.6 | Markup subset parser + ANSI renderer (`*bold*`, `_italic_`, code, quote, lists, link-as-text) | Table tests + golden renders; malformed input passes through literally | 1.5 | M1.7 |
| M2.7 | Read tracking UI: per-area catch-up, "new since last call" digest, mark-all-read | Counts match store queries after mixed activity | 1 | M2.3 |
| M2.8 | FTS5 search: index + triggers, query screen, filters (area/author/date), snippet highlight | 1M-post synthetic benchmark < 100 ms; injection-safe query builder | 1 | M2.1 |
| M2.9 | Moderation v1: soft delete/hide, lock, sticky, move thread, reason capture, mod log | Moderator can act only in permitted areas; actions audited | 1 | M2.5 |

**Exit:** two users hold a real threaded conversation with quoting, unread tracking, search, and a
moderator cleaning up — all from the terminal.

---

## M3 — Private mail & file areas (≈6 d)

| ID | Task | Acceptance | Est | Deps |
| --- | --- | --- | --- | --- |
| M3.1 | Mail schema + service (inbox/sent, read flags, threading by subject, quotas, blocklist) | Round-trip + quota tests; per-side delete semantics verified | 1 | M2.1 |
| M3.2 | Mail screens: list, read, compose (handle autocomplete), reply, delete, new-mail badge | Golden frames; badge appears/disappears correctly | 1 | M3.1, M1.4 |
| M3.3 | File area schema + storage layout (`<data>/files/<area>/<ulid>`), quotas, checksums | Traversal attempts rejected (test); quota enforced | 1 | M2.1 |
| M3.4 | Upload flow in-TUI: pick area, path/description, size streaming with cap, extension policy, scan hook | Oversize mid-upload aborts cleanly; quarantine state visible to sysop | 1.5 | M3.3 |
| M3.5 | Download: listing/search, detail screen, tokenized HTTP URL, `ssh bbs get AREA/FILE` pipe mode | `ssh … get` output byte-identical (sha256); expired token rejected | 1 | M3.3, M1.1 |
| M3.6 | File ratings + download counters; "new files since last call" | Counters accurate under concurrency test | 0.5 | M3.4 |

**Exit:** send/receive mail with quota behavior; upload and retrieve a file both ways with matching
checksums.

---

## M4 — Community (≈5 d)

| ID | Task | Acceptance | Est | Deps |
| --- | --- | --- | --- | --- |
| M4.1 | `hub` broker: publish/subscribe, bounded buffers, drop-oldest, presence events | Unit tests for slow-subscriber isolation; no blocking under load | 1 | M0.8 |
| M4.2 | Presence integration: who's online live updates, idle status, node numbers, sysop page | Two sessions see join/leave within 1 s | 1 | M4.1, M1.5 |
| M4.3 | Inter-node chat: global + sysop channels, scrollback, join/leave notices, rate limit | 5 concurrent sessions chat without interleaving corruption | 1 | M4.1 |
| M4.4 | One-liners: post/list, length cap, moderation hide, retention prune | Golden list; hidden entries invisible to users, visible to mods | 0.5 | M2.1 |
| M4.5 | Polls: create (sysop), vote, results, close date, one-vote enforcement | Double-vote rejected by constraint, not just UI | 1 | M2.1 |
| M4.6 | Bulletins + signatures: sysop CRUD, per-user dismiss, signature sanitize/render limits | Signature cannot inject escapes or exceed 4 lines | 0.5 | M2.6 |

**Exit:** a lively evening's usage is possible: chat, oneliners, poll, bulletins, signatures.

---

## M5 — Sysop & operations (≈5.75 d)

| ID | Task | Acceptance | Est | Deps |
| --- | --- | --- | --- | --- |
| M5.1 | Central `authz` package: role × action × resource matrix, table-driven tests | Every screen/service check goes through it; matrix documented | 1 | M2.9 |
| M5.2 | Admin CLI: user (create/suspend/reset/role), area, filearea, bulletin, poll, ban | Scriptable: create area+user+bulletin via CLI, verify in TUI | 1.5 | M5.1 |
| M5.3 | In-BBS sysop menu: users, areas, audit tail, stats, broadcast message, ban | Broadcast reaches all sessions; audit tail paginates | 1 | M5.2, M4.1 |
| M5.4 | Audit log: writes on every privileged action, before/after diff JSON, tamper-evident ordering | Test asserts an audit row per admin action; secrets redacted | 0.5 | M5.1 |
| M5.5 | `bbs backup` (`VACUUM INTO`, retention), restore doc, `bbs doctor` (config/DB/schema/permissions) | Backup of live DB restores and passes `doctor` + integrity check | 0.5 | M0.5 |
| M5.6 | Retention/prune job (sessions, audit, oneliners, soft-deleted posts) + scheduled run | Dry-run mode reports counts; prune is idempotent | 0.5 | M5.4 |
| M5.7 | Metrics (`/metrics`, `/healthz`) on opt-in loopback listener | Metrics off by default; endpoint refuses non-loopback bind unless explicit | 0.5 | M1.1 |
| M5.8 | Probation lifecycle (D3): auto-promote on time + post count (defaults 3 d / 10 posts), moderator-promote, capability gates for uploads/links | Table tests for promotion boundaries with fake clock; probation user is blocked at the service layer, not just the UI | 0.75 | M2.5, M5.2 |

**Exit:** sysop can run the board entirely from CLI + in-BBS menu, with a tested backup/restore and
an audit trail.

---

## M6 — Hardening & v1.0 (≈5 d)

| ID | Task | Acceptance | Est | Deps |
| --- | --- | --- | --- | --- |
| M6.1 | E2E suite over real SSH: register→probation→post→reply→search→mail→upload→download→moderate→promote→logout, plus disconnect/resize/reconnect | Runs in CI against in-process server; deterministic | 1.5 | M2–M5 |
| M6.2 | Load test `cmd/loadgen`: 200 scripted sessions, p95/p99, memory report; fix hotspots | p95 < 50 ms, RSS < 150 MB at 200 sessions (or documented tuning) | 1 | M6.1 |
| M6.3 | Security pass: `gosec`, `govulncheck`, abuse checklist (flood, escape injection, traversal, quota), dependency review | No high findings; checklist signed off in `docs/ops.md` | 1 | M6.2 |
| M6.4 | Docs: README quickstart, `docs/ops.md` runbook, `docs/moderation.md`, config reference, CONTRIBUTING | A fresh reader can deploy in < 15 min from README alone | 1 | M5 |
| M6.5 | Release: goreleaser, versioned migrations, changelog, tag `v1.0.0`, Docker image | Tagged artifacts build; upgrade from previous tag runs `migrate` cleanly | 0.5 | M6.3 |

**Exit:** v1.0.0 tag, reproducible release, documented ops, load + security evidence.

---

## v1.x / v2 stretch (not committed)

| ID | Task | Notes |
| --- | --- | --- |
| X1 | QWK/REP export + import (`internal/qwk`) — open question Q1, v2 only | Export first: `CONTROL.DAT`, `MESSAGES.DAT` (128-byte records, `0xE3` line ends), per-conference `NNN.NDX` (5-byte entries), `DOOR.ID`; conformance fixtures captured from a real Synchronet/Mystic packet, then import of `.REP` |
| X2 | Thread subscriptions & reply notifications | Reuses hub + mail |
| X3 | Read-only web mirror (D4 — first v1.x item) | Server-rendered, no JS, text-only, same sanitizer with HTML escaping |
| X4 | Postgres store implementation | Repository interfaces already abstracted |
| X5 | TOTP for sysop, themes/palettes, SMTP forwarding | Independent, small |
| X6 | "Last callers" list | Needs only a sessions query; was advertised in early docs |
| X7 | Sysop page / chat interrupt | Ring a live node from the sysop menu; reuses presence + hub |
| X8 | Per-user time budget ("time left") | Classic BBS limit; needs a per-class budget in config |
| X9 | Restore a soft-deleted post | Store already keeps body + who/why; needs an undelete path + audit |

---

## Sequencing & parallelism

```
M0 ─▶ M1 ─▶ M2 ─▶ M3 ─┬─▶ M4 ─▶ M5 ─▶ M6 ─▶ v1.0 ─▶ X3 (web mirror)
        │              │
        └─ M1.7 render │ (can start during M2)
                       └─ M3 mail (∥ with file areas M3.3–M3.5)
```

- **Critical path:** M0 → M1 → M2 → M4 → M5 → M6 (M3 slots in after M2.1).
- Two developers: split **A** = transport/TUI/community (M1, M4), **B** = store/boards/mail/files/
  admin (M2, M3, M5); render (M1.7, M2.6) is a shared early deliverable owned by A.
- Total ≈ **38.75 dev-days** for v1.0 (D1 removed work; D3 added M5.8). M6.2 (load) is the most
  likely to overrun; budget +2 d. Declined items (ZMODEM, doors, telnet) add zero days by design.

## Definition of done (every task)

1. Tests: unit + at least one integration/e2e path for new user-visible behavior.
2. `make check` green: fmt, vet, lint, race tests, fuzz smoke.
3. Docs touched: config keys, CLI flags, or screens described as needed.
4. Manual verification over a real SSH session, recorded in the PR description.
5. No new dependency without a one-line justification in `docs/deps.md`.
