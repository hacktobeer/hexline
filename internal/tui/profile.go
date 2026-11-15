package tui

import (
	"context"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/render"
)

// profileScreen edits profile fields, signature and terminal preferences.
type profileScreen struct {
	BaseScreen
	fields []textinput.Model
	sig    textarea.Model
	focus  int
	err    string
	saved  bool
}

func newProfileScreen(a *App, _ any) Screen {
	u := a.User()
	p := &profileScreen{BaseScreen: BaseScreen{Route: RouteProfile, TitleText: "Settings", Hints: "tab next  ctrl+s save  a ansi  p password  esc back"}}
	if u == nil {
		return p
	}
	p.fields = []textinput.Model{
		NewInput("real name", 40),
		NewInput("email", 40),
		NewInput("location", 40),
		NewInput("timezone", 24),
	}
	p.fields[0].SetValue(u.RealName)
	p.fields[1].SetValue(u.Email)
	p.fields[2].SetValue(u.Location)
	p.fields[3].SetValue(u.Timezone)
	ta := textarea.New()
	ta.Placeholder = "signature (max 4 lines, plain text)"
	ta.SetWidth(60)
	ta.SetHeight(5)
	ta.CharLimit = 400
	ta.SetValue(u.Signature)
	p.sig = ta
	p.fields[0].Focus()
	return p
}

func (p *profileScreen) Init(a *App) tea.Cmd { return textinput.Blink }

func (p *profileScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		if p.focus == len(p.fields) {
			p.sig, cmd = p.sig.Update(msg)
		}
		return cmd
	}
	u := a.User()
	if u == nil {
		return nil
	}
	switch key.String() {
	case "tab", "down":
		p.blur()
		p.focus = (p.focus + 1) % (len(p.fields) + 1)
		p.focusField()
		return nil
	case "shift+tab", "up":
		p.blur()
		p.focus = (p.focus - 1 + len(p.fields) + 1) % (len(p.fields) + 1)
		p.focusField()
		return nil
	case "ctrl+s":
		u.RealName = p.fields[0].Value()
		u.Email = p.fields[1].Value()
		u.Location = p.fields[2].Value()
		u.Timezone = strings.TrimSpace(p.fields[3].Value())
		u.Signature = p.sig.Value()
		if err := a.Auth.UpdateProfile(context.Background(), u); err != nil {
			p.err = friendlyError(err)
			return nil
		}
		a.Flash("settings saved")
		p.saved = true
		p.err = ""
		return nil
	case "a":
		u.Prefs.ANSI = !u.Prefs.ANSI
		if err := a.Auth.UpdatePrefs(context.Background(), u, u.Prefs); err != nil {
			return a.Errorf(err, "save prefs")
		}
		a.Flash("ANSI %s", map[bool]string{true: "on", false: "off"}[u.Prefs.ANSI])
		return nil
	case "p":
		return func() tea.Msg { return NavigateMsg{Route: RoutePassword} }
	}
	if p.focus == len(p.fields) {
		var cmd tea.Cmd
		p.sig, cmd = p.sig.Update(msg)
		return cmd
	}
	var cmd tea.Cmd
	p.fields[p.focus], cmd = p.fields[p.focus].Update(msg)
	return cmd
}

func (p *profileScreen) blur() {
	for i := range p.fields {
		p.fields[i].Blur()
	}
	p.sig.Blur()
}

func (p *profileScreen) focusField() {
	if p.focus == len(p.fields) {
		p.sig.Focus()
		return
	}
	p.fields[p.focus].Focus()
}

func (p *profileScreen) View(a *App) string {
	u := a.User()
	w := a.W
	var b strings.Builder
	if u == nil {
		return styleWarn.Render("Not logged in.")
	}
	b.WriteString(styleBold.Render(u.Handle) + "  " + styleForStatus(string(u.Status)) + "  " + string(u.Role) + "\n")
	b.WriteString(styleDim.Render("member since "+u.CreatedAt.Format("2006-01-02")+
		"  calls "+itoa(u.Calls)+"  online "+u.TimeOnline.Round(1e9).String()) + "\n\n")
	labels := []string{"Real name", "Email", "Location", "Timezone"}
	for i, f := range p.fields {
		b.WriteString(LabeledInput(labels[i], f) + "\n")
	}
	b.WriteString(styleDim.Render("Signature") + "\n" + p.sig.View() + "\n")
	b.WriteString(styleDim.Render("Colour") + ": " +
		map[bool]string{true: "on", false: "off"}[u.Prefs.ANSI] + "   (a toggles)\n")
	if p.err != "" {
		b.WriteString("\n" + styleWarn.Render(render.Clip("! "+p.err, w-2)) + "\n")
	}
	return b.String()
}

// passwordScreen changes the account password.
type passwordScreen struct {
	BaseScreen
	fields []textinput.Model
	focus  int
	err    string
}

func newPasswordScreen(a *App, _ any) Screen {
	p := &passwordScreen{BaseScreen: BaseScreen{Route: RoutePassword, TitleText: "Change password", Hints: "tab next  ctrl+s save  esc back"}}
	for _, ph := range []string{"current password", "new password", "repeat new password"} {
		in := NewInput(ph, 32)
		in.EchoMode = textinput.EchoPassword
		p.fields = append(p.fields, in)
	}
	p.fields[0].Focus()
	return p
}

func (p *passwordScreen) Init(a *App) tea.Cmd { return textinput.Blink }

func (p *passwordScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return nil
	}
	switch key.String() {
	case "tab", "down":
		p.fields[p.focus].Blur()
		p.focus = (p.focus + 1) % len(p.fields)
		p.fields[p.focus].Focus()
		return nil
	case "ctrl+s":
		if p.fields[1].Value() != p.fields[2].Value() {
			p.err = "the new passwords do not match"
			return nil
		}
		u := a.User()
		if u == nil {
			return nil
		}
		err := a.Auth.ChangePassword(context.Background(), u.ID, p.fields[0].Value(), p.fields[1].Value())
		if err != nil {
			p.err = friendlyError(err)
			return nil
		}
		a.Flash("password changed")
		return func() tea.Msg { return PopMsg{} }
	}
	var cmd tea.Cmd
	p.fields[p.focus], cmd = p.fields[p.focus].Update(msg)
	return cmd
}

func (p *passwordScreen) View(a *App) string {
	var b strings.Builder
	b.WriteString(styleBold.Render("Change password") + "\n\n")
	labels := []string{"Current", "New", "Repeat"}
	for i, f := range p.fields {
		b.WriteString(LabeledInput(labels[i], f) + "\n")
	}
	if p.err != "" {
		b.WriteString("\n" + styleWarn.Render("! "+p.err) + "\n")
	}
	return b.String()
}
