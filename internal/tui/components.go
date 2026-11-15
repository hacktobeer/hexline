package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"

	"github.com/hacktobeer/hexline/internal/render"
)

// TitleBar renders the top line with left and right aligned text.
func TitleBar(w int, left, right string) string {
	left = render.Clip(left, w)
	right = render.Clip(right, w)
	gap := w - render.Width(left) - render.Width(right)
	if gap < 1 {
		return left
	}
	return styleTitle.Render(left) + strings.Repeat(" ", gap) + styleDim.Render(right)
}

// Rule renders a full-width separator.
func Rule(w int) string {
	return styleDim.Render(strings.Repeat("─", max(1, w)))
}

// HintBar renders the footer hint line, clipped to width.
func HintBar(w int, text string) string {
	return styleDim.Render(render.Clip(text, w))
}

// Section renders a heading with a rule underneath.
func Section(w int, title string) string {
	return styleAccent.Render(render.Clip(title, w))
}

// ListRow renders a two-column row, reversed when selected.
func ListRow(w int, left, right string, selected bool) string {
	right = render.Clip(right, w)
	leftWidth := w - render.Width(right) - 1
	if leftWidth < 4 {
		leftWidth = 4
	}
	left = render.PadRight(left, leftWidth)
	line := left + " " + right
	if selected {
		return styleSelected.Render(render.PadRight(line, w))
	}
	return line
}

// MenuItem is a main-menu or admin-menu entry.
type MenuItem struct {
	Key   string // single hotkey, e.g. "b"
	Label string
	Hint  string
	Route Route
	Arg   any
	Admin bool // hidden from non-privileged users unless explicitly added
}

// Menu is a vertical hotkey menu with a moving cursor.
type Menu struct {
	Items  []MenuItem
	Cursor int
}

// Move shifts the cursor by delta, wrapping.
func (m *Menu) Move(delta int) {
	if len(m.Items) == 0 {
		return
	}
	m.Cursor = (m.Cursor + delta + len(m.Items)) % len(m.Items)
}

// Selected returns the highlighted item.
func (m *Menu) Selected() *MenuItem {
	if len(m.Items) == 0 {
		return nil
	}
	return &m.Items[m.Cursor]
}

// HandleKey maps a key press to a selection. activate reports Enter.
func (m *Menu) HandleKey(key string) (item *MenuItem, activate bool) {
	switch key {
	case "up", "k":
		m.Move(-1)
		return nil, false
	case "down", "j":
		m.Move(1)
		return nil, false
	case "enter":
		return m.Selected(), true
	}
	for i := range m.Items {
		if strings.EqualFold(m.Items[i].Key, key) {
			m.Cursor = i
			return &m.Items[i], true
		}
	}
	return nil, false
}

// View renders the menu with hints.
func (m *Menu) View(w int) string {
	var b strings.Builder
	for i, it := range m.Items {
		left := "[" + strings.ToUpper(it.Key) + "] " + it.Label
		row := ListRow(w, "  "+left, it.Hint, i == m.Cursor)
		b.WriteString(row + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// NewInput builds a styled single-line input.
func NewInput(placeholder string, width int) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 200
	ti.Width = max(10, width)
	ti.Prompt = "> "
	return ti
}

// LabeledInput renders a label above an input.
func LabeledInput(label string, ti textinput.Model) string {
	return styleDim.Render(label) + "\n" + ti.View()
}

// pager is a simple scroll window over pre-wrapped lines.
type pager struct {
	lines []string
	top   int
}

// SetText wraps text to width and resets the scroll position. ansi follows the
// caller's preference; the renderer never emits escapes when it is false.
func (p *pager) SetText(text string, width int, ansi bool) {
	text = render.Render(text, render.Options{Width: width, ANSI: ansi})
	p.lines = strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(p.lines) == 1 && p.lines[0] == "" {
		p.lines = nil
	}
	p.top = 0
}

// Lines exposes the wrapped lines (bulletin navigation peeks at them).
func (p *pager) Lines() []string { return p.lines }

// Move scrolls by delta within height.
func (p *pager) Move(delta, height int) {
	maxTop := len(p.lines) - height
	if maxTop < 0 {
		maxTop = 0
	}
	p.top += delta
	if p.top > maxTop {
		p.top = maxTop
	}
	if p.top < 0 {
		p.top = 0
	}
}

// View renders the visible window plus a scroll indicator.
func (p *pager) View(width, height int) string {
	if len(p.lines) == 0 {
		return styleDim.Render("(empty)")
	}
	end := p.top + height
	if end > len(p.lines) {
		end = len(p.lines)
	}
	visible := p.lines[p.top:end]
	if len(p.lines) > height {
		pct := 100
		if maxTop := len(p.lines) - height; maxTop > 0 {
			pct = p.top * 100 / maxTop
		}
		visible = append(visible, styleDim.Render(strings.Repeat("─", min(width, 20))+
			" "+itoa(pct)+"%"))
	}
	return strings.Join(visible, "\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// styleForStatus colours account status text.
func styleForStatus(s string) string {
	switch s {
	case "active":
		return styleOK.Render(s)
	case "probation":
		return styleWarn.Render(s)
	default:
		return styleWarn.Render(s)
	}
}

var _ = lipgloss.NewStyle
