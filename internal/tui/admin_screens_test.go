package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
)

func admTUIApp(t *testing.T, role domain.Role) (*App, *store.Store, *domain.User) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "tui-admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := st.Seed(); err != nil {
		t.Fatal(err)
	}
	u := &domain.User{
		Handle: "tester", Role: role, Status: domain.StatusActive,
		PassHash: "x", PassParams: "x", CreatedAt: time.Now().UTC(),
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	broker := hub.NewBroker(16)
	auth := service.NewAuth(st, cfg, nil)
	app := New(cfg, st, auth, service.NewBoards(st, cfg), service.NewMail(st, cfg),
		service.NewFiles(st, cfg), service.NewCommunity(st, cfg, broker),
		service.NewAdmin(st, cfg, broker), broker,
		&Session{User: u, Node: 1})
	app.W, app.H = 100, 30
	return app, st, u
}

func TestAdminStatsViewWithRealStore(t *testing.T) {
	app, st, _ := admTUIApp(t, domain.RoleSysop)
	area := &domain.Area{Tag: "stats", Name: "Stats", ACL: domain.DefaultACL(), IsPublic: true}
	if err := st.CreateArea(area); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO threads(id, area_id, subject, author_id, created_at, last_post_at)
		VALUES ('t1', ?, 'subject', ?, ?, ?)`, area.ID, app.User().ID,
		time.Now().Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO posts(thread_id, author_id, body, created_at)
		VALUES ('t1', ?, 'body', ?)`, app.User().ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	stats, err := app.Admin.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	screen := newAdminStats(app, nil)
	view := screen.View(app)
	for _, want := range []string{"Board stats", "Users", "Message areas", "Threads", "Posts", "Database"} {
		if !strings.Contains(view, want) {
			t.Errorf("stats view missing %q:\n%s", want, view)
		}
	}
	if !strings.Contains(view, itoa(stats.Users)) {
		t.Errorf("stats view missing user count %d:\n%s", stats.Users, view)
	}
	if !strings.Contains(view, itoa(stats.Posts)) {
		t.Errorf("stats view missing post count %d:\n%s", stats.Posts, view)
	}
}

func TestAdminAuditViewWithRealStore(t *testing.T) {
	app, st, u := admTUIApp(t, domain.RoleSysop)
	if err := st.RecordAudit(domain.AuditEntry{
		ActorID: u.ID, Actor: u.Handle, Action: "test.audit.action",
		TargetKind: "user", TargetID: u.ID,
	}); err != nil {
		t.Fatal(err)
	}
	screen := newAdminAudit(app, nil)
	view := screen.View(app)
	for _, want := range []string{"Audit log", "test.audit.action", u.Handle, "user:" + u.ID} {
		if !strings.Contains(view, want) {
			t.Errorf("audit view missing %q:\n%s", want, view)
		}
	}
}

func TestAdminAuditFilterByUser(t *testing.T) {
	app, st, u := admTUIApp(t, domain.RoleSysop)
	other := &domain.User{Handle: "other", Role: domain.RoleUser, Status: domain.StatusActive,
		PassHash: "x", PassParams: "x", CreatedAt: time.Now().UTC()}
	if err := st.CreateUser(other); err != nil {
		t.Fatal(err)
	}
	_ = st.RecordAudit(domain.AuditEntry{ActorID: u.ID, Actor: u.Handle, Action: "mine.action"})
	_ = st.RecordAudit(domain.AuditEntry{ActorID: other.ID, Actor: other.Handle, Action: "other.action"})
	screen := newAdminAudit(app, admAuditFilter{UserID: u.ID, Handle: u.Handle})
	view := screen.View(app)
	if !strings.Contains(view, "mine.action") {
		t.Errorf("filtered audit missing own action:\n%s", view)
	}
	if strings.Contains(view, "other.action") {
		t.Errorf("filtered audit leaked another user's action:\n%s", view)
	}
}

func TestAdminMenuDeniesPlainUser(t *testing.T) {
	app, _, _ := admTUIApp(t, domain.RoleUser)
	menu := newAdminMenu(app, nil)
	if cmd := menu.Init(app); cmd != nil {
		t.Error("plain user menu should not load stats")
	}
	view := menu.View(app)
	if !strings.Contains(view, "permission denied") {
		t.Fatalf("menu view = %q, want permission denied", view)
	}
	// The denial must not leak counters or menu entries.
	for _, leak := range []string{"Users", "Stats", "Broadcast", "areas"} {
		if strings.Contains(view, leak) {
			t.Errorf("denied menu leaked %q:\n%s", leak, view)
		}
	}
}

func TestAdminMenuAllowsModerator(t *testing.T) {
	app, _, _ := admTUIApp(t, domain.RoleModerator)
	menu := newAdminMenu(app, nil)
	view := menu.View(app)
	if strings.Contains(view, "permission denied") {
		t.Fatalf("moderator denied:\n%s", view)
	}
	for _, want := range []string{"Users", "Areas", "Audit log", "Stats", "Broadcast"} {
		if !strings.Contains(view, want) {
			t.Errorf("menu missing %q:\n%s", want, view)
		}
	}
}

func TestAdminAreasViewListsMessageAndFileAreas(t *testing.T) {
	app, _, _ := admTUIApp(t, domain.RoleSysop)
	if _, err := app.Admin.CreateArea(context.Background(), app.User(), "retro",
		"Retro", "old computers", 10, "user", "user", "moderator"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Admin.CreateFileArea(context.Background(), app.User(), "downloads",
		"Downloads", "files", 10, "user", "user", 0); err != nil {
		t.Fatal(err)
	}
	screen := newAdminAreas(app, nil)
	view := screen.View(app)
	for _, want := range []string{"Message areas", "retro", "File areas", "downloads"} {
		if !strings.Contains(view, want) {
			t.Errorf("areas view missing %q:\n%s", want, view)
		}
	}
}

func TestAdminBroadcastViewDeniesModerator(t *testing.T) {
	app, _, _ := admTUIApp(t, domain.RoleModerator)
	screen := newAdminBroadcast(app, nil)
	if view := screen.View(app); !strings.Contains(view, "permission denied") {
		t.Fatalf("broadcast view = %q", view)
	}
}
