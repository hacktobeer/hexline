#!/usr/bin/env python3
"""Capture hexline TUI screens over SSH and write them as terminal SVGs.

The script logs in with an SSH key, drives the real TUI through a PTY with
keystrokes, records the ANSI byte stream, replays it onto an 80x24 character
grid, and renders that grid as an SVG inside a terminal window frame. Nothing
is mocked up: the text, colours and layout are what a caller sees.

Usage:
    python3 docs/screenshots/capture.py --key ~/.ssh/id_ed25519

Requirements: python3 (stdlib only), the `ssh` client, and a running board
with key auth enrolled for the capture account (see README.md next to this
script).

The terminal emulator handles the sequences Bubble Tea emits for this UI:
cursor home/position/up/down/left/right, erase in line/screen, SGR colours
(16/256/truecolour), reverse video, and the alternate screen. It intentionally
ignores scroll regions, mouse reports and bracketed-paste modes.
"""

import argparse
import html
import os
import pty
import select
import shutil
import struct
import subprocess
import sys
import termios
import time
import fcntl
import unicodedata
from pathlib import Path

# --- rendering geometry -----------------------------------------------------
FONT_SIZE = 14
CHAR_W = FONT_SIZE * 0.6  # monospace advance, in px
LINE_H = 18
PAD = 16
CHROME_H = 30
FONT = "DejaVu Sans Mono, SFMono-Regular, Menlo, Consolas, monospace"

DEF_FG = "#c9d1d9"
DEF_BG = "#0b0f14"
WINDOW_BG = "#161b22"
WINDOW_BORDER = "#30363d"

BASE16 = [
    "#000000", "#cd0000", "#00cd00", "#cdcd00", "#0000ee", "#cd00cd",
    "#00cdcd", "#e5e5e5", "#7f7f7f", "#ff0000", "#00ff00", "#ffff00",
    "#5c5cff", "#ff00ff", "#00ffff", "#ffffff",
]


def xterm_color(n):
    """Map an xterm palette index (0-255) to a CSS colour."""
    if n < 16:
        return BASE16[n]
    if n < 232:
        n -= 16
        r, g, b = n // 36, (n % 36) // 6, n % 6
        conv = lambda x: 0 if x == 0 else 55 + 40 * x  # noqa: E731
        return "#%02x%02x%02x" % (conv(r), conv(g), conv(b))
    v = 8 + 10 * (n - 232)
    return "#%02x%02x%02x" % (v, v, v)


class Cell:
    __slots__ = ("ch", "fg", "bg", "bold", "dim", "rev")

    def __init__(self):
        self.ch = " "
        self.fg = self.bg = None
        self.bold = self.dim = self.rev = False

    def style(self):
        return (self.fg, self.bg, self.bold, self.dim, self.rev)


class Screen:
    """A minimal ANSI terminal: enough to replay Bubble Tea frames."""

    def __init__(self, rows, cols):
        self.rows, self.cols = rows, cols
        self.clear()
        self.r = self.c = 0
        self.fg = self.bg = None
        self.bold = self.dim = self.rev = False

    def clear(self):
        self.grid = [[Cell() for _ in range(self.cols)] for _ in range(self.rows)]
        self.r = self.c = 0

    def scroll(self):
        self.grid.pop(0)
        self.grid.append([Cell() for _ in range(self.cols)])

    def reset_cell(self, r, c):
        cell = self.grid[r][c]
        cell.ch, cell.fg, cell.bg = " ", None, None
        cell.bold = cell.dim = cell.rev = False

    def put(self, ch, width):
        if self.c >= self.cols:
            self.c = 0
            self.r += 1
        if self.r >= self.rows:
            self.scroll()
            self.r = self.rows - 1
        cell = self.grid[self.r][self.c]
        cell.ch, cell.fg, cell.bg = ch, self.fg, self.bg
        cell.bold, cell.dim, cell.rev = self.bold, self.dim, self.rev
        if width == 2 and self.c + 1 < self.cols:
            nxt = self.grid[self.r][self.c + 1]
            nxt.ch, nxt.fg, nxt.bg = "", self.fg, self.bg
            nxt.bold, nxt.dim, nxt.rev = self.bold, self.dim, self.rev
        self.c += width

    def sgr(self, codes):
        if not codes:
            codes = [0]
        i = 0
        while i < len(codes):
            n = codes[i]
            if n == 0:
                self.fg = self.bg = None
                self.bold = self.dim = self.rev = False
            elif n == 1:
                self.bold = True
            elif n == 2:
                self.dim = True
            elif n == 7:
                self.rev = True
            elif n == 22:
                self.bold = self.dim = False
            elif n == 27:
                self.rev = False
            elif n == 39:
                self.fg = None
            elif n == 49:
                self.bg = None
            elif 30 <= n <= 37:
                self.fg = n - 30
            elif 90 <= n <= 97:
                self.fg = n - 90 + 8
            elif 40 <= n <= 47:
                self.bg = n - 40
            elif 100 <= n <= 107:
                self.bg = n - 100 + 8
            elif n in (38, 48):
                slot = "fg" if n == 38 else "bg"
                if i + 2 < len(codes) and codes[i + 1] == 5:
                    setattr(self, slot, codes[i + 2])
                    i += 2
                elif i + 4 < len(codes) and codes[i + 1] == 2:
                    setattr(self, slot, (codes[i + 2], codes[i + 3], codes[i + 4]))
                    i += 4
            i += 1

    def csi(self, params, final):
        private = params.startswith("?")
        body = params[1:] if private else params
        nums = [int(p) if p.isdigit() else 0 for p in body.split(";")] if body else []

        def arg(i, default=0):
            return nums[i] if i < len(nums) else default

        if private and final in "hl" and 1049 in nums:
            if final == "h":
                self.clear()
            return
        if final in "Hf":
            self.r = max(0, min(self.rows - 1, arg(0, 1) - 1))
            self.c = max(0, min(self.cols - 1, arg(1, 1) - 1))
        elif final == "A":
            self.r = max(0, self.r - arg(0, 1))
        elif final == "B":
            self.r = min(self.rows - 1, self.r + arg(0, 1))
        elif final == "C":
            self.c = min(self.cols - 1, self.c + arg(0, 1))
        elif final == "D":
            self.c = max(0, self.c - arg(0, 1))
        elif final == "G":
            self.c = max(0, min(self.cols - 1, arg(0, 1) - 1))
        elif final == "d":
            self.r = max(0, min(self.rows - 1, arg(0, 1) - 1))
        elif final == "J":
            mode = arg(0, 0)
            if mode in (2, 3):
                self.clear()
            elif mode == 0:
                for c in range(self.c, self.cols):
                    self.reset_cell(self.r, c)
                for r in range(self.r + 1, self.rows):
                    for c in range(self.cols):
                        self.reset_cell(r, c)
        elif final == "K":
            mode = arg(0, 0)
            start, end = (self.c, self.cols) if mode == 0 else (
                (0, self.c + 1) if mode == 1 else (0, self.cols))
            for c in range(start, end):
                self.reset_cell(self.r, c)
        elif final == "m":
            self.sgr(nums)
        elif final == "P":
            row = self.grid[self.r]
            for _ in range(arg(0, 1)):
                row.pop(self.c)
                row.append(Cell())
        elif final == "X":
            for c in range(self.c, min(self.cols, self.c + arg(0, 1))):
                self.reset_cell(self.r, c)

    def feed(self, text):
        i, n = 0, len(text)
        while i < n:
            ch = text[i]
            if ch == "\x1b":
                if i + 1 < n and text[i + 1] == "[":
                    j = i + 2
                    while j < n and not ("@" <= text[j] <= "~"):
                        j += 1
                    if j >= n:
                        break
                    self.csi(text[i + 2:j], text[j])
                    i = j + 1
                    continue
                if i + 1 < n and text[i + 1] == "]":
                    j = i + 2
                    while j < n and text[j] != "\x07":
                        if text[j] == "\x1b" and j + 1 < n and text[j + 1] == "\\":
                            j += 1
                            break
                        j += 1
                    i = j + 1
                    continue
                i += 2
                continue
            if ch == "\r":
                self.c = 0
            elif ch == "\n":
                self.r += 1
                if self.r >= self.rows:
                    self.scroll()
                    self.r = self.rows - 1
            elif ch == "\b":
                self.c = max(0, self.c - 1)
            elif ch == "\t":
                self.c = min(self.cols - 1, (self.c // 8 + 1) * 8)
            elif ch == "\x07":
                pass
            elif ch >= " ":
                self.put(ch, 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
            i += 1

    def plain(self):
        return "\n".join("".join(c.ch for c in row).rstrip() for row in self.grid)


class SshSession:
    """One SSH session on a PTY, with timed keystrokes and output capture."""

    def __init__(self, args, user, key):
        self.args = args
        self.user = user
        self.key = key
        self.raw = bytearray()

    def _command(self):
        return [
            "ssh", "-tt", "-i", self.key,
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-p", str(self.args.port),
            f"{self.user}@{self.args.host}",
        ]

    def run(self, keys, settle=1.6, final_wait=0.8):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ,
                    struct.pack("HHHH", self.args.rows, self.args.cols, 0, 0))
        env = dict(os.environ, TERM="xterm-256color",
                   COLUMNS=str(self.args.cols), LINES=str(self.args.rows))
        proc = subprocess.Popen(
            self._command(), stdin=slave, stdout=slave, stderr=slave,
            env=env, preexec_fn=os.setsid)
        os.close(slave)
        os.set_blocking(master, False)

        def pump(seconds):
            end = time.time() + seconds
            while time.time() < end:
                readable, _, _ = select.select([master], [], [], 0.03)
                if not readable:
                    continue
                try:
                    data = os.read(master, 65536)
                except OSError:
                    return
                if not data:
                    return
                self.raw.extend(data)

        try:
            pump(settle)
            for text, delay in keys:
                os.write(master, text.encode())
                pump(delay)
            pump(final_wait)
        finally:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            os.close(master)

        screen = Screen(self.args.rows, self.args.cols)
        screen.feed(self.raw.decode("utf-8", "replace"))
        if not any(cell.ch != " " for row in screen.grid for cell in row):
            raise SystemExit(
                "no screen output: check the host/port/key, that key auth is "
                "enrolled for %s, and that the board is running" % self.user)
        return screen


def to_hex(value):
    if value is None:
        return None
    if isinstance(value, tuple):
        return "#%02x%02x%02x" % value
    return xterm_color(value)


def render_svg(screen, title, out_path):
    cols, rows = screen.cols, screen.rows
    width = PAD * 2 + int(cols * CHAR_W)
    height = CHROME_H + PAD * 2 + rows * LINE_H

    shapes = []
    for r in range(rows):
        col = 0
        while col < cols:
            cell = screen.grid[r][col]
            if cell.ch == "":
                col += 1
                continue
            style = cell.style()
            run = [cell.ch]
            col += 1
            while col < cols:
                nxt = screen.grid[r][col]
                if nxt.ch == "" or nxt.style() != style:
                    break
                run.append(nxt.ch)
                col += 1

            if cell.rev:
                # Reverse video swaps the slots; unset slots use the terminal
                # defaults, which is how the selection bar appears.
                fg = to_hex(cell.bg) or DEF_BG
                bg = to_hex(cell.fg) or DEF_FG
            else:
                fg = to_hex(cell.fg) or DEF_FG
                bg = to_hex(cell.bg)

            text = "".join(run)
            x = PAD + (col - len(run)) * CHAR_W
            y = CHROME_H + PAD + r * LINE_H + 13
            if bg:
                shapes.append(
                    f'<rect x="{x:.1f}" y="{CHROME_H + PAD + r * LINE_H}" '
                    f'width="{len(run) * CHAR_W:.1f}" height="{LINE_H}" fill="{bg}"/>')
            if text.strip() or bg:
                attrs = ""
                if cell.bold:
                    attrs += ' font-weight="bold"'
                if cell.dim:
                    attrs += ' opacity="0.62"'
                shapes.append(
                    f'<text x="{x:.1f}" y="{y}" fill="{fg}"{attrs}>{html.escape(text)}</text>')

    body = "\n    ".join(shapes)
    document = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" xml:space="preserve" role="img" aria-label="{html.escape(title)}">
  <defs><clipPath id="win"><rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="10"/></clipPath></defs>
  <rect x="1" y="1" width="{width - 2}" height="{height - 2}" rx="10" fill="{WINDOW_BG}" stroke="{WINDOW_BORDER}"/>
  <path d="M 1 11 A 10 10 0 0 1 11 1 H {width - 11} A 10 10 0 0 1 {width - 1} 11 V {CHROME_H} H 1 Z" fill="{WINDOW_BG}"/>
  <circle cx="18" cy="15" r="5" fill="#ff5f56" opacity="0.9"/>
  <circle cx="36" cy="15" r="5" fill="#ffbd2e" opacity="0.9"/>
  <circle cx="54" cy="15" r="5" fill="#27c93f" opacity="0.9"/>
  <text x="72" y="19" fill="#6e7681" font-size="11" font-family="{FONT}">{html.escape(title)}</text>
  <g clip-path="url(#win)">
    <rect x="1" y="{CHROME_H}" width="{width - 2}" height="{height - CHROME_H - 1}" fill="{DEF_BG}"/>
    {body}
  </g>
</svg>
'''
    out_path.write_text(document)
    return width, height


SHOTS = [
    # who's online first so the two nodes are 1 and 2 in the screenshot
    ("whos-online", "who's online", [("w", 1.2)]),
    ("main-menu", "main menu", []),
    ("thread", "reading a thread", [("b", 0.9), ("\r", 1.0), ("\r", 1.2)]),
]


def main():
    parser = argparse.ArgumentParser(
        description="Capture hexline TUI screens as SVG terminal windows.")
    parser.add_argument("--host", default="127.0.0.1", help="SSH host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=2222, help="SSH port (default 2222)")
    parser.add_argument("--user", default="sysop", help="capture account (default sysop)")
    parser.add_argument("--key", default="~/.ssh/id_ed25519", help="private key for --user")
    parser.add_argument("--alt-user", default="alice",
                        help="second caller for who's online (default alice)")
    parser.add_argument("--alt-key", default="",
                        help="private key for --alt-user; omit to capture a single node")
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent),
                        help="output directory (default: this script's directory)")
    parser.add_argument("--cols", type=int, default=80, help="terminal columns (default 80)")
    parser.add_argument("--rows", type=int, default=24, help="terminal rows (default 24)")
    parser.add_argument("--only", default="", help="comma-separated shot names to capture")
    parser.add_argument("--no-preview", action="store_true", help="do not print captured screens")
    args = parser.parse_args()

    if not shutil.which("ssh"):
        parser.error("the ssh client is required")
    args.key = os.path.expanduser(args.key)
    if not os.path.isfile(args.key):
        parser.error(f"key not found: {args.key}")
    if args.alt_key:
        args.alt_key = os.path.expanduser(args.alt_key)
        if not os.path.isfile(args.alt_key):
            parser.error(f"alt key not found: {args.alt_key}")

    out_dir = Path(os.path.expanduser(args.out))
    out_dir.mkdir(parents=True, exist_ok=True)
    wanted = {name.strip() for name in args.only.split(",") if name.strip()}

    alt_proc = None
    captured = 0
    for name, label, keys in SHOTS:
        if wanted and name not in wanted:
            continue
        if name == "whos-online" and args.alt_key:
            alt_proc = subprocess.Popen(
                ["ssh", "-tt", "-i", args.alt_key,
                 "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                 "-p", str(args.port), f"{args.alt_user}@{args.host}"],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=dict(os.environ, TERM="xterm-256color"))
            time.sleep(1.4)

        session = SshSession(args, args.user, args.key)
        screen = session.run(keys)
        title = f"{args.user}@hexline — {label}"
        path = out_dir / f"{name}.svg"
        width, height = render_svg(screen, title, path)
        captured += 1
        print(f"wrote {path} ({width}x{height})")
        if not args.no_preview:
            print(screen.plain())
            print()

        if alt_proc is not None:
            alt_proc.kill()
            alt_proc.wait()
            alt_proc = None

    if wanted and captured == 0:
        parser.error(f"--only matched no shots: {', '.join(sorted(wanted))}")


if __name__ == "__main__":
    main()
