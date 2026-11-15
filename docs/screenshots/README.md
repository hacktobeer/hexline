# Screenshots

These SVGs are captures of a real hexline session over SSH, not mockups. `capture.py` logs in with
a key, drives the TUI through a PTY, records the ANSI stream, replays it onto an 80×24 grid and
writes that grid as an SVG inside a terminal window frame — text, colours, reverse-video selection
and box drawing included.

| File | Screen |
| --- | --- |
| `main-menu.svg` | new mail + unread counts, hotkeys, MOTD |
| `thread.svg` | thread reader with markup, quote, signature and paging hint |
| `whos-online.svg` | live nodes with activity and idle time |

## Regenerate

Requirements: Go (see `go.mod`), `ssh`, `python3` (standard library only).

```sh
# 1. a board to photograph
export HEXLINE_DATA_DIR=$PWD/demo-data
go build -o /tmp/hexline ./cmd/bbs
/tmp/hexline migrate
/tmp/hexline admin user create --handle sysop --role sysop

# 2. key auth (the script never types a password)
ssh-keygen -q -t ed25519 -N '' -f demo-key
/tmp/hexline admin user key add sysop demo-key.pub

# 3. optional second caller for the who's-online shot
/tmp/hexline admin user create --handle alice --role user
ssh-keygen -q -t ed25519 -N '' -f alice-key
/tmp/hexline admin user key add alice alice-key.pub

# 4. post something in General so the thread shot has content, then:
/tmp/hexline serve
python3 docs/screenshots/capture.py --key demo-key --alt-key alice-key
```

Running from a clean board is fine — the captures simply show an empty board. The committed images
came from a demo board with three accounts, three threads (one sticky), two unread mails to the
sysop and a poll.

## Options

| Flag | Default | Purpose |
| --- | --- | --- |
| `--host`, `--port` | `127.0.0.1`, `2222` | running board |
| `--user`, `--key` | `sysop`, `~/.ssh/id_ed25519` | capture account (needs key auth enrolled) |
| `--alt-user`, `--alt-key` | `alice`, none | second live node; omit `--alt-key` for a single node |
| `--out` | this directory | where the SVGs go |
| `--cols`, `--rows` | `80`, `24` | terminal size (the UI is written for 80×24) |
| `--only` | all | comma-separated names: `main-menu,thread,whos-online` |
| `--no-preview` | off | skip printing the captured screens |

## Notes and limits

- The script captures the screens in the order who's online → main menu → thread, so the node
  numbers read 1–4 naturally. Any board state is captured as-is.
- The terminal emulator supports what Bubble Tea emits for this UI: cursor movement, erase,
  16/256/truecolour SGR, reverse video and the alternate screen. Scroll regions, mouse and
  bracketed-paste modes are ignored on purpose.
- SVGs keep the terminal's dark theme and use `xml:space="preserve"` plus presentation attributes so
  alignment survives GitHub's SVG sanitising. No binary assets, no image dependencies.
