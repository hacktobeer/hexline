package tui

import (
	"context"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/render"
	"github.com/hacktobeer/hexline/internal/service"
)

// registerScreen finishes account creation for a handle the SSH layer already
// accepted. The password was collected during SSH auth and is kept in memory
// only for this step.
type registerScreen struct {
	BaseScreen
	handle string
	fields []textinput.Model
	focus  int
	err    string
	busy   bool
}

func newRegisterScreen(a *App, _ any) Screen {
	r := &registerScreen{
		BaseScreen: BaseScreen{Route: RouteRegister, TitleText: "New caller", Hints: "tab next  enter create account  esc cancel"},
		handle:     a.Sess.PendingHandle,
	}
	r.fields = []textinput.Model{
		NewInput("real name (optional)", 40),
		NewInput("email (optional, not verified)", 40),
		NewInput("location (optional)", 40),
		NewInput("timezone (e.g. Europe/Amsterdam)", 40),
	}
	r.fields[3].SetValue("UTC")
	r.fields[0].Focus()
	return r
}

func (r *registerScreen) Init(a *App) tea.Cmd { return textinput.Blink }

func (r *registerScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return nil
	}
	switch key.String() {
	case "tab", "down":
		r.fields[r.focus].Blur()
		r.focus = (r.focus + 1) % len(r.fields)
		r.fields[r.focus].Focus()
		return nil
	case "shift+tab", "up":
		r.fields[r.focus].Blur()
		r.focus = (r.focus - 1 + len(r.fields)) % len(r.fields)
		r.fields[r.focus].Focus()
		return nil
	case "ctrl+s":
		return r.submit(a)
	}
	var cmd tea.Cmd
	r.fields[r.focus], cmd = r.fields[r.focus].Update(msg)
	return cmd
}

func (r *registerScreen) submit(a *App) tea.Cmd {
	if r.busy {
		return nil
	}
	if a.Sess.PendingPassword == "" {
		r.err = "no password was captured at connect; reconnect to register"
		return nil
	}
	r.busy = true
	req := service.RegisterRequest{
		Handle:   r.handle,
		Password: a.Sess.PendingPassword,
		RealName: r.fields[0].Value(),
		Email:    r.fields[1].Value(),
		Location: r.fields[2].Value(),
		Timezone: strings.TrimSpace(r.fields[3].Value()),
		IPHash:   a.Sess.IPHash,
	}
	u, err := a.Auth.Register(context.Background(), req)
	if err != nil {
		r.busy = false
		r.err = friendlyError(err)
		return nil
	}
	a.Sess.User = u
	a.Sess.PendingHandle = ""
	a.Sess.PendingPassword = ""
	a.Flash("Welcome aboard, %s. Your account is on probation until 3 days and 10 posts.", u.Handle)
	// Replace, not push: esc from the menu must not return to a form whose
	// password was already consumed.
	return a.Replace(RouteMain, nil)
}

func (r *registerScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(styleBold.Render("New caller registration") + "\n\n")
	b.WriteString("Handle: " + styleAccent.Render(r.handle) + "\n")
	b.WriteString(styleDim.Render("Your password was set when you connected.") + "\n\n")
	labels := []string{"Real name", "Email", "Location", "Timezone"}
	for i, f := range r.fields {
		b.WriteString(LabeledInput(labels[i], f) + "\n")
	}
	if r.busy {
		b.WriteString(styleDim.Render("creating account…") + "\n")
	}
	if r.err != "" {
		b.WriteString("\n" + styleWarn.Render("! "+render.Clip(r.err, w-2)) + "\n")
	}
	b.WriteString("\n" + styleDim.Render("Probation (D9): posting is capped, uploads and links stay off until\n3 days and 10 posts, or a moderator promotes you early.") + "\n")
	return b.String()
}
