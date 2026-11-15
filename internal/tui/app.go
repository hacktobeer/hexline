// Package tui implements hexline's terminal interface on Bubble Tea.
//
// Every screen implements Screen. Screens never touch SQL: they call the
// services on App. Feature files register their constructors in routes.go.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
)

// Session is one connected caller.
type Session struct {
	User     *domain.User
	Node     int
	IPHash   string
	Started  time.Time
	ReadOnly bool
	// PendingHandle is set when the SSH layer accepted a new handle and the
	// caller still has to finish registration in the TUI.
	PendingHandle   string
	PendingPassword string
}

// Screen is one navigable view.
type Screen interface {
	ID() Route
	Title() string
	Init(a *App) tea.Cmd
	Update(a *App, msg tea.Msg) tea.Cmd
	View(a *App) string
	// keyHints is the footer help text for this screen.
	keyHints() string
}

// BaseScreen supplies defaults so screens only implement what they need.
type BaseScreen struct {
	Route     Route
	TitleText string
	Hints     string
}

// ID implements Screen.
func (b *BaseScreen) ID() Route { return b.Route }

// Title implements Screen.
func (b *BaseScreen) Title() string { return b.TitleText }

// Init implements Screen.
func (b *BaseScreen) Init(a *App) tea.Cmd { return nil }

// Update implements Screen.
func (b *BaseScreen) Update(a *App, msg tea.Msg) tea.Cmd { return nil }

// View implements Screen.
func (b *BaseScreen) View(a *App) string { return "" }

func (b *BaseScreen) keyHints() string { return b.Hints }

// App is the root Bubble Tea model.
type App struct {
	Cfg       *config.Config
	Store     *store.Store
	Auth      *service.Auth
	Boards    *service.Boards
	Mail      *service.Mail
	Files     *service.Files
	Community *service.Community
	Admin     *service.Admin
	Hub       *hub.Broker
	Presence  *hub.Presence
	// SessionID identifies this connection in the presence registry.
	SessionID string
	// Touch reports screen changes for who's-online activity.
	Touch func(activity string)

	Sess *Session

	W, H int

	stack []Screen
	flash string
	// flashUntil hides stale flashes.
	flashUntil time.Time
	quitting   bool
}

// New builds the app for one session.
func New(cfg *config.Config, st *store.Store, auth *service.Auth, boards *service.Boards,
	mail *service.Mail, files *service.Files, community *service.Community,
	admin *service.Admin, broker *hub.Broker, sess *Session) *App {
	a := &App{
		Cfg: cfg, Store: st, Auth: auth, Boards: boards, Mail: mail, Files: files,
		Community: community, Admin: admin, Hub: broker, Sess: sess,
		W: cfg.UI.DefaultWidth, H: cfg.UI.DefaultRows,
	}
	if a.W < 80 {
		a.W = 80
	}
	var root Screen
	if sess.PendingHandle != "" {
		root = newRegisterScreen(a, nil)
	} else {
		root = newMainMenu(a, nil)
	}
	a.stack = []Screen{root}
	return a
}

// Init starts the root screen.
func (a *App) Init() tea.Cmd { return a.top().Init(a) }

// Update routes messages to the active screen and handles global keys.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.W, a.H = m.Width, m.Height
		if a.W < 40 {
			a.W = 40
		}
		if a.H < 12 {
			a.H = 12
		}
		return a, nil
	case tea.KeyMsg:
		switch m.String() {
		case "ctrl+c":
			a.quitting = true
			return a, tea.Quit
		case "esc":
			if len(a.stack) > 1 {
				return a, a.Pop()
			}
			return a, nil
		case "f1", "?":
			return a, a.Push(RouteHelp, nil)
		}
	case NavigateMsg:
		return a, a.Push(m.Route, m.Arg)
	case PopMsg:
		return a, a.Pop()
	case FlashMsg:
		a.Flash("%s", m.Text)
		return a, nil
	case ErrMsg:
		a.Flash("%s", friendlyError(m.Err))
		return a, nil
	case QuitMsg:
		a.quitting = true
		return a, tea.Quit
	}
	cmd := a.top().Update(a, msg)
	return a, cmd
}

// View renders header, active screen body and footer.
func (a *App) View() string {
	if a.quitting {
		return "Goodbye.\n"
	}
	top := a.top()
	left := fmt.Sprintf("%s · node %d", a.Cfg.UI.ServerName, a.Sess.Node)
	right := "not logged in"
	if u := a.User(); u != nil {
		right = fmt.Sprintf("%s · %s UTC", u.Handle, time.Now().UTC().Format("15:04"))
	}
	head := TitleBar(a.W, left, right)
	rule := Rule(a.W)

	body := top.View(a)
	body = strings.TrimRight(body, "\n")
	lines := strings.Split(body, "\n")
	height := a.BodyHeight()
	if len(lines) > height {
		lines = lines[:height]
	}
	for len(lines) < height {
		lines = append(lines, "")
	}

	keys := top.keyHints()
	if keys == "" {
		keys = "? help  esc back  ctrl+c quit"
	}
	foot := HintBar(a.W, keys)
	if a.flash != "" && time.Now().Before(a.flashUntil) {
		foot = HintBar(a.W, "» "+a.flash)
	}
	return strings.Join([]string{head, rule, strings.Join(lines, "\n"), foot}, "\n") + "\n"
}

// BodyHeight is the number of rows available to a screen.
func (a *App) BodyHeight() int {
	h := a.H - 3
	if h < 4 {
		h = 4
	}
	return h
}

// Push navigates to route with an optional argument.
func (a *App) Push(route Route, arg any) tea.Cmd {
	s := newScreen(a, route, arg)
	if s == nil {
		a.Flash("screen %q is not available", route)
		return nil
	}
	a.stack = append(a.stack, s)
	if a.Touch != nil {
		a.Touch(string(route))
	}
	if len(a.stack) > 12 {
		// Keep a bounded stack; drop the oldest non-root entry.
		a.stack = append(a.stack[:1], a.stack[2:]...)
	}
	return s.Init(a)
}

// ScreenLeaver is implemented by screens holding resources that must be
// released when the screen is popped (chat subscriptions, timers).
type ScreenLeaver interface{ OnLeave() }

// Pop returns to the previous screen; the root screen stays put.
func (a *App) Pop() tea.Cmd {
	if len(a.stack) <= 1 {
		return nil
	}
	if l, ok := a.top().(ScreenLeaver); ok {
		l.OnLeave()
	}
	a.stack = a.stack[:len(a.stack)-1]
	return a.top().Init(a)
}

// Replace swaps the current screen (used after splash/registration).
func (a *App) Replace(route Route, arg any) tea.Cmd {
	s := newScreen(a, route, arg)
	if s == nil {
		return nil
	}
	if len(a.stack) == 0 {
		a.stack = []Screen{s}
	} else {
		if l, ok := a.top().(ScreenLeaver); ok {
			l.OnLeave()
		}
		a.stack[len(a.stack)-1] = s
	}
	return s.Init(a)
}

// Flash shows a one-line message in the footer.
func (a *App) Flash(format string, args ...any) {
	a.flash = fmt.Sprintf(format, args...)
	a.flashUntil = time.Now().Add(6 * time.Second)
}

// Errorf flashes an error message and returns no command.
func (a *App) Errorf(err error, format string, args ...any) tea.Cmd {
	msg := fmt.Sprintf(format, args...)
	if err != nil {
		if msg != "" {
			msg += ": "
		}
		msg += friendlyError(err)
	}
	a.Flash("%s", msg)
	return nil
}

// User returns the logged-in user, or nil.
func (a *App) User() *domain.User { return a.Sess.User }

// Handle returns the current handle or "guest".
func (a *App) Handle() string {
	if u := a.User(); u != nil {
		return u.Handle
	}
	return "guest"
}

// IsSysop reports sysop authority.
func (a *App) IsSysop() bool {
	u := a.User()
	return u != nil && u.Role == domain.RoleSysop
}

// IsModerator reports moderator authority or higher.
func (a *App) IsModerator() bool {
	u := a.User()
	return u != nil && u.Role.AtLeast(domain.RoleModerator)
}

// CanWrite reports whether the current session may create content.
func (a *App) CanWrite() bool {
	if a.Sess.ReadOnly {
		return false
	}
	u := a.User()
	return u != nil && u.CanWrite()
}

// now is a seam for tests.
func (a *App) now() time.Time { return time.Now().UTC() }

func (a *App) top() Screen { return a.stack[len(a.stack)-1] }

// --- messages shared by screens ---

// NavigateMsg pushes a route.
type NavigateMsg struct {
	Route Route
	Arg   any
}

// PopMsg returns to the previous screen.
type PopMsg struct{}

// FlashMsg shows transient footer text.
type FlashMsg struct{ Text string }

// ErrMsg reports a handled error to the user.
type ErrMsg struct{ Err error }

// QuitMsg disconnects.
type QuitMsg struct{}

// HubEventMsg wraps a broker event for chat/presence screens.
type HubEventMsg struct{ Event hub.Event }

// WaitForHub blocks until the broker sends an event. Screens return it from
// Init/Update to receive live events.
func WaitForHub(ch <-chan hub.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return HubEventMsg{Event: ev}
	}
}

// friendlyError maps domain errors to short user text.
func friendlyError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case isErr(err, domain.ErrPermission):
		return "permission denied"
	case isErr(err, domain.ErrNotFound):
		return "not found"
	case isErr(err, domain.ErrConflict):
		return strings.TrimPrefix(err.Error(), "conflict: ")
	case isErr(err, domain.ErrRateLimited):
		return strings.TrimPrefix(err.Error(), "rate limited: ")
	case isErr(err, domain.ErrQuota):
		return strings.TrimPrefix(err.Error(), "quota exceeded: ")
	case isErr(err, domain.ErrInvalid):
		return strings.TrimPrefix(err.Error(), "invalid input: ")
	case isErr(err, domain.ErrSuspended):
		return "this account is suspended"
	case isErr(err, domain.ErrProbation):
		return "not available while on probation"
	case isErr(err, domain.ErrClosed):
		return "this thread is locked"
	case isErr(err, domain.ErrUnavailable):
		return "temporarily unavailable, try again"
	}
	return err.Error()
}

func isErr(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
