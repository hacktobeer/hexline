# Dependencies

Policy: every module is pinned, reviewed, and earns its place. No module may phone home at
runtime. Add a row here when you add a dependency.

| Module | Pinned | Why |
| --- | --- | --- |
| github.com/charmbracelet/bubbletea | v1.3.4 | TUI runtime (v1 line; v2 was RC and renames imports to charm.land) |
| github.com/charmbracelet/bubbles | v0.21.0 | textinput, textarea, viewport primitives |
| github.com/charmbracelet/lipgloss | v1.1.0 | Styling; layout arithmetic |
| github.com/charmbracelet/wish | v1.4.7 | SSH server middleware purpose-built for Bubble Tea |
| github.com/charmbracelet/ssh | v0.0.0-20250128164007-98fd5ae11894 | Maintained fork of gliderlabs/ssh used by Wish |
| github.com/spf13/cobra | v1.10.2 | Subcommand CLI |
| github.com/BurntSushi/toml | v1.6.0 | TOML config with strict unknown-key detection |
| github.com/oklog/ulid/v2 | v2.1.2 | Sortable, opaque entity IDs |
| modernc.org/sqlite | v1.62.0 | cgo-free SQLite with FTS5 compiled in (no build tag) |
| golang.org/x/crypto | v0.59.0 | argon2id, SSH client (loadgen) |
| golang.org/x/text | v0.44.0 | CP437 decoding for ANSI art |

Deliberately absent: ORMs, web frameworks, logging libraries (stdlib slog), Markdown renderers
(custom 400-line parser), and any telemetry.

Upgrade posture: no `charm.land/*` v2 migration before v1.0. Renovate/Dependabot may propose;
CI decides.
