# hexline

A terminal-first Bulletin Board System in Go — SSH, message areas, file areas, mail,
one-liners, chat. Single binary, SQLite, no interactive web UI.

**Status:** v1.0 implementation in progress. Licensed Apache-2.0.

## Read this first

- [`docs/DESIGN.md`](docs/DESIGN.md) — vision, feature set, architecture, data model, security,
  NFRs, risks, decisions (§11)
- [`docs/TASKS.md`](docs/TASKS.md) — milestones M0–M6, task backlog with acceptance criteria,
  sequencing, v1.x stretch list

## Quickstart

```sh
make build
export HEXLINE_DATA_DIR=$PWD/data

./bbs migrate
./bbs admin user create --handle sysop --role sysop   # prints a generated password
./bbs serve

# in another terminal
ssh -p 2222 sysop@127.0.0.1
```

Requires Go 1.24+. No Node, no database server, no cgo.

Drive it without a terminal:

```sh
ssh -p 2222 sysop@127.0.0.1 whoami
ssh -p 2222 sysop@127.0.0.1 get UPLOADS/notes.txt > notes.txt
```

## Documentation

- [`docs/ops.md`](docs/ops.md) — install, systemd, backup/restore, upgrades, monitoring, troubleshooting
- [`docs/moderation.md`](docs/moderation.md) — moderator and sysop workflows, audit log
- [`docs/deps.md`](docs/deps.md) — every dependency and why it exists

## Decisions so far

| | |
| --- | --- |
| D1 | SSH only — no telnet |
| D2 | No ZMODEM/XMODEM, no external doors (declined, not deferred) |
| D3 | Open registration with new-user probation |
| D4 | Read-only web mirror after v1.0 |
| D5 | QWK offline mail deferred to v2 |
| D6 | SQLite only (repository interfaces keep Postgres possible) |
| D7 | English-only UI, strings centralized |
| D8 | Separate message and file areas |
| D9 | Probation: auto-promote at 3 days + 10 posts |
| D10 | Chat: global + sysop channels only |

No open questions remain (DESIGN §11).

## Review checklist

1. Scope: does §3.1 (v1.0) match what you want? §3.3 lists what is declined and why.
2. Estimate: ≈38.75 dev-days to v1.0 (`TASKS.md`, end of file).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
