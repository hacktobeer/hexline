package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
)

// mailTestEnv is a real temp store plus an App for one caller.
type mailTestEnv struct {
	st    *store.Store
	cfg   *config.Config
	mail  *service.Mail
	alice *domain.User
	bob   *domain.User
	app   *App
}

func mailTestEnvNew(t *testing.T) *mailTestEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := st.Seed(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg := config.Default()
	mail := service.NewMail(st, cfg)
	alice := &domain.User{
		Handle: "alice", PassHash: "x", Status: domain.StatusActive, Role: domain.RoleUser,
		Signature: "alice sig",
	}
	bob := &domain.User{
		Handle: "bob", PassHash: "x", Status: domain.StatusActive, Role: domain.RoleUser,
	}
	for _, u := range []*domain.User{alice, bob} {
		if err := st.CreateUser(u); err != nil {
			t.Fatalf("create %s: %v", u.Handle, err)
		}
	}
	app := New(cfg, st, nil, nil, mail, nil, nil, nil, nil,
		&Session{User: bob, Node: 1})
	app.W, app.H = 80, 24
	return &mailTestEnv{st: st, cfg: cfg, mail: mail, alice: alice, bob: bob, app: app}
}

// appFor returns an App view of the same board for another caller.
func (e *mailTestEnv) appFor(t *testing.T, u *domain.User) *App {
	t.Helper()
	app := New(e.cfg, e.st, nil, nil, e.mail, nil, nil, nil, nil, &Session{User: u, Node: 2})
	app.W, app.H = 80, 24
	return app
}

// mailDrive runs a screen's Init command and feeds the result back once.
func mailDrive(t *testing.T, app *App, s Screen) {
	t.Helper()
	cmd := s.Init(app)
	if cmd == nil {
		return
	}
	msg := cmd()
	if msg == nil {
		return
	}
	s.Update(app, msg)
}

func mailKey(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "ctrl+s":
		return tea.KeyMsg{Type: tea.KeyCtrlS}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestMailInboxViewShowsMessages(t *testing.T) {
	env := mailTestEnvNew(t)
	ctx := context.Background()
	if _, err := env.mail.Send(ctx, env.alice, "bob", "Lunch plans", "Meet at noon.\nBring the disks."); err != nil {
		t.Fatalf("send: %v", err)
	}

	inbox := newMailInbox(env.app, nil)
	mailDrive(t, env.app, inbox)
	view := inbox.View(env.app)

	for _, want := range []string{"Lunch plans", "from alice", "●", "quota 1/200", "unread 1"} {
		if !strings.Contains(view, want) {
			t.Fatalf("inbox view missing %q:\n%s", want, view)
		}
	}
}

func TestMailInboxUnreadMarkerClearsAfterReading(t *testing.T) {
	env := mailTestEnvNew(t)
	ctx := context.Background()
	msg, err := env.mail.Send(ctx, env.alice, "bob", "Unread topic", "body")
	if err != nil {
		t.Fatal(err)
	}

	// Opening the message marks it read.
	reader := newMailView(env.app, mailViewArg{IDs: []string{msg.ID}, Pos: 0})
	mailDrive(t, env.app, reader)
	if !strings.Contains(reader.View(env.app), "Unread topic") {
		t.Fatal("reader did not show the message")
	}

	inbox := newMailInbox(env.app, nil)
	mailDrive(t, env.app, inbox)
	view := inbox.View(env.app)
	if strings.Contains(view, "●") {
		t.Fatalf("read message still marked unread:\n%s", view)
	}
	if !strings.Contains(view, "Unread topic") {
		t.Fatalf("inbox lost the message:\n%s", view)
	}
	if !strings.Contains(view, "unread 0") {
		t.Fatalf("unread count not refreshed:\n%s", view)
	}
}

func TestMailSentTabView(t *testing.T) {
	env := mailTestEnvNew(t)
	ctx := context.Background()
	if _, err := env.mail.Send(ctx, env.alice, "bob", "Outgoing note", "body"); err != nil {
		t.Fatal(err)
	}
	app := env.appFor(t, env.alice)
	inbox := newMailInbox(app, mailInboxArg{Tab: "sent"})
	mailDrive(t, app, inbox)
	view := inbox.View(app)
	if !strings.Contains(view, "Mail · sent") || !strings.Contains(view, "to bob") ||
		!strings.Contains(view, "Outgoing note") {
		t.Fatalf("sent view wrong:\n%s", view)
	}
	if strings.Contains(view, "from alice") {
		t.Fatalf("sent view used inbox wording:\n%s", view)
	}
}

func TestMailReaderViewAndReplyPrefill(t *testing.T) {
	env := mailTestEnvNew(t)
	ctx := context.Background()
	msg, err := env.mail.Send(ctx, env.alice, "bob", "Disk swap", "I have five 3.5 inch disks.")
	if err != nil {
		t.Fatal(err)
	}

	reader := newMailView(env.app, mailViewArg{IDs: []string{msg.ID}, Pos: 0})
	mailDrive(t, env.app, reader)
	view := reader.View(env.app)
	for _, want := range []string{"Disk swap", "From: alice", "To: bob", "five 3.5 inch disks", "alice sig"} {
		if !strings.Contains(view, want) {
			t.Fatalf("reader view missing %q:\n%s", want, view)
		}
	}

	// r navigates to the composer with recipient, "Re:" subject and a quote.
	cmd := reader.Update(env.app, mailKey("r"))
	if cmd == nil {
		t.Fatal("reply returned no command")
	}
	nav, ok := cmd().(NavigateMsg)
	if !ok || nav.Route != RouteMailCompose {
		t.Fatalf("reply navigation = %#v", nav)
	}
	pre, ok := nav.Arg.(mailComposeArg)
	if !ok {
		t.Fatalf("reply arg type = %T", nav.Arg)
	}
	if pre.To != "alice" {
		t.Fatalf("reply recipient = %q, want alice", pre.To)
	}
	if pre.Subject != "Re: Disk swap" {
		t.Fatalf("reply subject = %q", pre.Subject)
	}
	if !strings.Contains(pre.Body, "alice wrote:") || !strings.Contains(pre.Body, "> I have five") {
		t.Fatalf("reply body not quoted:\n%s", pre.Body)
	}

	composer := newMailCompose(env.app, nav.Arg)
	composerView := composer.View(env.app)
	if !strings.Contains(composerView, "alice") || !strings.Contains(composerView, "Re: Disk swap") {
		t.Fatalf("composer lost the prefill:\n%s", composerView)
	}
}

func TestMailReaderNextPrevAndDeleteConfirm(t *testing.T) {
	env := mailTestEnvNew(t)
	ctx := context.Background()
	first, err := env.mail.Send(ctx, env.alice, "bob", "First message", "one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := env.mail.Send(ctx, env.alice, "bob", "Second message", "two")
	if err != nil {
		t.Fatal(err)
	}

	ids := []string{first.ID, second.ID}
	reader := newMailView(env.app, mailViewArg{IDs: ids, Pos: 0})
	mailDrive(t, env.app, reader)
	if got := reader.View(env.app); !strings.Contains(got, "First message") {
		t.Fatalf("reader did not open the first message:\n%s", got)
	}

	// n moves to the next message in the mailbox.
	cmd := reader.Update(env.app, mailKey("n"))
	if cmd == nil {
		t.Fatal("next returned no command")
	}
	reader.Update(env.app, cmd())
	if got := reader.View(env.app); !strings.Contains(got, "Second message") {
		t.Fatalf("n did not advance:\n%s", got)
	}
	// p goes back.
	cmd = reader.Update(env.app, mailKey("p"))
	if cmd == nil {
		t.Fatal("prev returned no command")
	}
	reader.Update(env.app, cmd())
	if got := reader.View(env.app); !strings.Contains(got, "First message") {
		t.Fatalf("p did not go back:\n%s", got)
	}

	// d asks once, then deletes on the second press.
	if cmd := reader.Update(env.app, mailKey("d")); cmd != nil {
		t.Fatal("first d should only ask for confirmation")
	}
	if !strings.Contains(reader.View(env.app), "press d again") {
		t.Fatal("delete confirmation not shown")
	}
	cmd = reader.Update(env.app, mailKey("d"))
	if cmd == nil {
		t.Fatal("confirmed delete returned no command")
	}
	pop := reader.Update(env.app, cmd())
	if pop == nil {
		t.Fatal("delete did not pop the reader")
	}
	if _, ok := pop().(PopMsg); !ok {
		t.Fatal("delete should return PopMsg")
	}
	if in, _ := env.mail.Inbox(ctx, env.bob, 10, 0); len(in) != 1 || in[0].ID != second.ID {
		t.Fatalf("inbox after delete = %+v", in)
	}
}

func TestMailComposerSendsAndReportsValidation(t *testing.T) {
	env := mailTestEnvNew(t)
	ctx := context.Background()

	// Empty recipient is reported inline, and nothing is stored.
	empty := newMailCompose(env.app, nil)
	cmd := empty.Update(env.app, mailKey("ctrl+s"))
	if cmd != nil {
		t.Fatal("invalid compose should not send")
	}
	if got := empty.View(env.app); !strings.Contains(got, "recipient handle is required") {
		t.Fatalf("validation error not shown:\n%s", got)
	}
	if n, _ := env.mail.UnreadCount(ctx, env.alice.ID); n != 0 {
		t.Fatalf("validation failure stored mail: %d", n)
	}

	composer := newMailCompose(env.app, nil).(*mailComposer)
	composer.to.SetValue("alice")
	composer.subject.SetValue("Hello there")
	composer.body.SetValue("First line\nsecond line")
	cmd = composer.Update(env.app, mailKey("ctrl+s"))
	if cmd == nil {
		t.Fatal("valid compose returned no command")
	}
	msg := cmd()
	if _, ok := msg.(mailSentMsg); !ok {
		t.Fatalf("send result = %T", msg)
	}
	pop := composer.Update(env.app, msg)
	if pop == nil {
		t.Fatal("successful send did not pop the composer")
	}
	if _, ok := pop().(PopMsg); !ok {
		t.Fatal("successful send should return PopMsg")
	}
	if !strings.Contains(env.app.flash, "mail sent to alice") {
		t.Fatalf("flash = %q, want a send confirmation", env.app.flash)
	}

	inbox, err := env.mail.Inbox(ctx, env.alice, 10, 0)
	if err != nil || len(inbox) != 1 {
		t.Fatalf("recipient inbox = %+v, %v", inbox, err)
	}
	if inbox[0].Subject != "Hello there" || inbox[0].From != "bob" {
		t.Fatalf("stored mail = %+v", inbox[0])
	}
}

func TestMailBlocklistScreen(t *testing.T) {
	env := mailTestEnvNew(t)
	ctx := context.Background()
	if err := env.mail.Block(ctx, env.bob, "alice", true); err != nil {
		t.Fatal(err)
	}

	inbox := newMailInbox(env.app, nil)
	mailDrive(t, env.app, inbox)
	// b switches to the blocklist and loads handles.
	cmd := inbox.Update(env.app, mailKey("b"))
	if cmd == nil {
		t.Fatal("blocklist switch returned no command")
	}
	if msg := cmd(); msg != nil {
		inbox.Update(env.app, msg)
	}
	view := inbox.View(env.app)
	if !strings.Contains(view, "blocked senders") || !strings.Contains(view, "alice") {
		t.Fatalf("blocklist view missing entries:\n%s", view)
	}

	// Enter unblocks the selected handle.
	cmd = inbox.Update(env.app, mailKey("enter"))
	if cmd == nil {
		t.Fatal("unblock returned no command")
	}
	if msg := cmd(); msg != nil {
		// The done message reloads the blocklist; run that follow-up too.
		if next := inbox.Update(env.app, msg); next != nil {
			if reload := next(); reload != nil {
				inbox.Update(env.app, reload)
			}
		}
	}
	if !strings.Contains(env.app.flash, "unblocked alice") {
		t.Fatalf("flash = %q", env.app.flash)
	}
	if view := inbox.View(env.app); strings.Contains(view, "  alice") {
		t.Fatalf("blocklist still lists alice:\n%s", view)
	}
	if blocked, err := env.mail.Blocked(ctx, env.bob); err != nil || len(blocked) != 0 {
		t.Fatalf("blocked after unblock = %v, %v", blocked, err)
	}
}
