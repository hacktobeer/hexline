package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/service"
)

// flowApp builds an App with every service wired, for tests that press keys
// rather than only render.
func flowApp(t *testing.T) (*App, *domain.User) {
	t.Helper()
	st := boardTestStore(t)
	cfg := config.Default()
	broker := hub.NewBroker(16)
	admin := service.NewAdmin(st, cfg, broker)
	auth := service.NewAuth(st, cfg, nil)
	auth.SetPasswordParams(service.PasswordParams{Memory: 8 * 1024, Time: 1, Threads: 1, KeyLen: 32}, 1)
	u := &domain.User{
		Handle: "flow-user", Role: domain.RoleUser, Status: domain.StatusActive,
		PassHash: "x", PassParams: "m=1,t=1,p=1", Prefs: domain.DefaultPrefs(),
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	app := &App{
		Cfg: cfg, Store: st, Auth: auth,
		Boards:    service.NewBoards(st, cfg),
		Mail:      service.NewMail(st, cfg),
		Files:     service.NewFiles(st, cfg),
		Community: service.NewCommunity(st, cfg, broker),
		Admin:     admin,
		Hub:       broker,
		Presence:  hub.NewPresence(),
		Sess:      &Session{User: u, Node: 1},
		SessionID: "flow-session",
		W:         80, H: 24,
	}
	return app, u
}

func TestRegisterReplacesRootSoEscCannotReturnToTheForm(t *testing.T) {
	app, _ := flowApp(t)
	app.Sess.User = nil
	app.Sess.PendingHandle = "newbie"
	app.Sess.PendingPassword = "password123"
	app.Sess.IPHash = "iphash"
	app.stack = []Screen{newRegisterScreen(app, nil)}

	rs, ok := app.stack[0].(*registerScreen)
	if !ok {
		t.Fatalf("root is %T", app.stack[0])
	}
	rs.fields[0].SetValue("Newbie Person")
	rs.Update(app, tea.KeyMsg{Type: tea.KeyCtrlS})

	if app.Sess.User == nil || app.Sess.User.Handle != "newbie" {
		t.Fatalf("session user not set: %+v", app.Sess.User)
	}
	if len(app.stack) != 1 || app.top().ID() != RouteMain {
		t.Fatalf("stack after register = %d screens, top %q", len(app.stack), app.top().ID())
	}
	if _, err := app.Store.UserByHandle("newbie"); err != nil {
		t.Fatalf("account not persisted: %v", err)
	}
	// The dead-form bug: esc must not bring the registration form back.
	app.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if app.top().ID() != RouteMain {
		t.Fatalf("esc after register landed on %q", app.top().ID())
	}
}

func TestComposeSubmitCreatesThread(t *testing.T) {
	app, u := flowApp(t)
	general, err := app.Store.BoardAreaByTag("general")
	if err != nil {
		t.Fatal(err)
	}
	screen := newComposeScreen(app, boardComposeArg{
		Mode: "thread", AreaID: general.ID, AreaTag: general.Tag,
	})
	screen.Init(app)
	cs, ok := screen.(*composeScreen)
	if !ok {
		t.Fatalf("compose screen is %T", screen)
	}
	cs.subject.SetValue("Flow subject")
	cs.body.SetValue("Flow body from the keyboard")
	cs.Update(app, tea.KeyMsg{Type: tea.KeyCtrlS})
	if cs.err != "" {
		t.Fatalf("compose error: %s", cs.err)
	}

	threads, err := app.Boards.Threads(context.Background(), u, general.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(threads) != 1 || threads[0].Subject != "Flow subject" {
		t.Fatalf("threads = %+v", threads)
	}
	if threads[0].PostCount != 1 {
		t.Fatalf("post count = %d", threads[0].PostCount)
	}
}

func TestEscFromChatReleasesTheSubscription(t *testing.T) {
	app, _ := flowApp(t)
	app.stack = []Screen{newMainMenu(app, nil)}
	if cmd := app.Push(RouteChat, nil); cmd != nil {
		// Init returns a blocking hub wait; do not run it in the test.
		_ = cmd
	}
	if got := app.Hub.SubscriptionCount(); got != 1 {
		t.Fatalf("subscriptions after opening chat = %d, want 1", got)
	}
	app.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if got := app.Hub.SubscriptionCount(); got != 0 {
		t.Fatalf("subscriptions after esc = %d, want 0 (leak)", got)
	}
}

func TestANSIThemeFollowsTheCallerPreference(t *testing.T) {
	app, u := flowApp(t)
	var p pager
	p.SetText("this is *bold*", 40, false)
	if strings.Contains(p.View(40, 10), "\x1b") {
		t.Fatal("ANSI-off pager still emitted escapes")
	}
	p.SetText("this is *bold*", 40, true)
	if !strings.Contains(p.View(40, 10), "\x1b") {
		t.Fatal("ANSI-on pager emitted no styling")
	}

	u.Prefs.ANSI = false
	if err := app.Auth.UpdatePrefs(context.Background(), u, u.Prefs); err != nil {
		t.Fatal(err)
	}
	if app.ANSI() {
		t.Fatal("App.ANSI ignores the preference")
	}
}
