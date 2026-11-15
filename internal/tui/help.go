package tui

import (
	"strings"
)

type helpScreen struct{ BaseScreen }

func newHelpScreen(a *App, _ any) Screen {
	return &helpScreen{BaseScreen: BaseScreen{Route: RouteHelp, TitleText: "Help", Hints: "esc back"}}
}

func (h *helpScreen) View(a *App) string {
	sections := []struct{ title, body string }{
		{"Reading", "- j/k or arrows move, enter opens, esc goes back\n- space/down scrolls a message, / searches posts\n- m marks a thread read, r replies"},
		{"Writing", "Plain text with a little markup:\n  *bold*   _italic_   `code`   > quote   - list\nMessages are wrapped to your terminal width. Escapes are stripped."},
		{"Mail & files", "- Private mail is between handles; quotas apply\n- Files download with: ssh <board> get AREA/FILE > out\n- Uploads are quarantined until a sysop clears them"},
		{"Account", "Settings (s on the main menu): profile, signature, terminal width,\nANSI on/off, CP437 art, password. Guests cannot post."},
		{"Sysop", "a opens the sysop menu: users, areas, bulletins, audit log, stats,\nbackups (bbs backup), broadcast. Every action is audited."},
		{"Keys", "? help   esc back   ctrl+c disconnect   q quit from the main menu"},
	}
	w := a.W
	var b strings.Builder
	for _, s := range sections {
		b.WriteString(Section(w, s.title) + "\n")
		for _, line := range strings.Split(s.body, "\n") {
			b.WriteString("  " + line + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}
