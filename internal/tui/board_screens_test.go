package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
)

func boardTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "tui-board.db"))
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
	return st
}

func boardTestApp(t *testing.T, st *store.Store, cfg *config.Config) (*App, *domain.User) {
	t.Helper()
	u := &domain.User{
		Handle: "tui-user", Role: domain.RoleUser, Status: domain.StatusActive,
		PassHash: "x", PassParams: "m=1,t=1,p=1",
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	app := &App{
		Cfg:    cfg,
		Store:  st,
		Auth:   service.NewAuth(st, cfg, nil),
		Boards: service.NewBoards(st, cfg),
		Sess:   &Session{User: u, Node: 1},
		W:      80,
		H:      24,
	}
	return app, u
}

// boardRun drives a screen's loader commands to completion so View sees the
// same state a caller would after rendering.
func boardRun(t *testing.T, app *App, screen Screen) {
	t.Helper()
	cmd := screen.Init(app)
	for i := 0; cmd != nil; i++ {
		if i > 10 {
			t.Fatal("screen loader did not settle")
		}
		msg := cmd()
		if msg == nil {
			return
		}
		cmd = screen.Update(app, msg)
	}
}

func TestBoardListViewRendersAreasAndUnread(t *testing.T) {
	st := boardTestStore(t)
	cfg := config.Default()
	app, u := boardTestApp(t, st, cfg)
	general, err := st.BoardAreaByTag("general")
	if err != nil {
		t.Fatal(err)
	}

	screen := newBoardList(app, nil)
	boardRun(t, app, screen)
	view := screen.View(app)
	for _, want := range []string{"Message boards", "[general]", "General",
		"[tech]", "Tech", "all read", "Anything and everything"} {
		if !strings.Contains(view, want) {
			t.Fatalf("board list view missing %q:\n%s", want, view)
		}
	}

	if _, err := app.Boards.CreateThread(context.Background(), u, general.ID,
		"Unread seed", "hello"); err != nil {
		t.Fatalf("create thread: %v", err)
	}
	screen = newBoardList(app, nil)
	boardRun(t, app, screen)
	view = screen.View(app)
	if !strings.Contains(view, "1 unread") {
		t.Fatalf("board list view missing unread count:\n%s", view)
	}
}

func TestThreadListViewRendersThreadsUnreadAndMarkers(t *testing.T) {
	st := boardTestStore(t)
	cfg := config.Default()
	app, u := boardTestApp(t, st, cfg)
	general, err := st.BoardAreaByTag("general")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	thread, err := app.Boards.CreateThread(ctx, u, general.ID, "Welcome thread", "first post")
	if err != nil {
		t.Fatalf("create thread: %v", err)
	}
	if _, err := app.Boards.Reply(ctx, u, thread.ID, "second post"); err != nil {
		t.Fatalf("reply: %v", err)
	}

	arg := boardAreaArg{AreaID: general.ID, Tag: general.Tag, Name: general.Name}
	screen := newThreadList(app, arg)
	boardRun(t, app, screen)
	view := screen.View(app)
	for _, want := range []string{"[general] General", "Welcome thread",
		"tui-user", "2 replies", "2 new", "S sticky", "L locked"} {
		if !strings.Contains(view, want) {
			t.Fatalf("thread list view missing %q:\n%s", want, view)
		}
	}

	if err := st.SetThreadFlags(thread.ID, true, true); err != nil {
		t.Fatalf("set flags: %v", err)
	}
	screen = newThreadList(app, arg)
	boardRun(t, app, screen)
	view = screen.View(app)
	if !strings.Contains(view, "SL Welcome thread") {
		t.Fatalf("thread list view missing sticky/locked marker:\n%s", view)
	}
}

func TestPostViewRendersSignatureAndMarksRead(t *testing.T) {
	st := boardTestStore(t)
	cfg := config.Default()
	app, u := boardTestApp(t, st, cfg)
	u.Signature = "— tui-user, testing"
	if err := st.UpdateUserProfile(u); err != nil {
		t.Fatalf("update profile: %v", err)
	}
	general, err := st.BoardAreaByTag("general")
	if err != nil {
		t.Fatal(err)
	}
	thread, err := app.Boards.CreateThread(context.Background(), u, general.ID,
		"Signature thread", "body text")
	if err != nil {
		t.Fatalf("create thread: %v", err)
	}

	screen := newPostView(app, boardThreadArg{ThreadID: thread.ID, Subject: thread.Subject})
	boardRun(t, app, screen)
	view := screen.View(app)
	for _, want := range []string{"Signature thread", "tui-user", "body text",
		"testing"} {
		if !strings.Contains(view, want) {
			t.Fatalf("post view missing %q:\n%s", want, view)
		}
	}
	total, err := app.Boards.UnreadTotal(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("opening a thread left %d unread posts, want 0", total)
	}
}
