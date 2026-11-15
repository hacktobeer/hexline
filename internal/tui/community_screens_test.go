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

func commTestApp(t *testing.T) (*App, *store.Store, *service.Community, *hub.Broker) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
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
	cfg := config.Default()
	broker := hub.NewBroker(16)
	svc := service.NewCommunity(st, cfg, broker)
	user := commTestUser(t, st, "ada", domain.RoleUser)
	a := &App{
		Cfg:       cfg,
		Store:     st,
		Community: svc,
		Hub:       broker,
		Presence:  hub.NewPresence(),
		Sess:      &Session{User: user, Node: 1},
		W:         80,
		H:         24,
	}
	return a, st, svc, broker
}

func commTestUser(t *testing.T, st *store.Store, handle string, role domain.Role) *domain.User {
	t.Helper()
	u := &domain.User{
		Handle:     handle,
		Role:       role,
		Status:     domain.StatusActive,
		CreatedAt:  time.Now().UTC(),
		PassHash:   "x",
		PassParams: "x",
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", handle, err)
	}
	return u
}

func TestOnelinerScreenView(t *testing.T) {
	a, st, svc, _ := commTestApp(t)
	ctx := context.Background()

	posted, err := svc.PostOneliner(ctx, a.User(), "hello from the wall")
	if err != nil {
		t.Fatal(err)
	}
	s := newOnelinerScreen(a, nil)
	view := s.View(a)
	if !strings.Contains(view, "hello from the wall") {
		t.Fatalf("oneliner body missing from view:\n%s", view)
	}
	if !strings.Contains(view, a.User().Handle) {
		t.Fatalf("oneliner author missing from view:\n%s", view)
	}
	if strings.Contains(view, "(coming soon)") {
		t.Fatal("oneliner screen is still a stub")
	}

	// Hidden entries stay invisible to regular users...
	mod := commTestUser(t, st, "mod", domain.RoleModerator)
	if err := svc.HideOneliner(ctx, mod, posted.ID, true); err != nil {
		t.Fatal(err)
	}
	s = newOnelinerScreen(a, nil)
	if strings.Contains(s.View(a), "hello from the wall") {
		t.Fatal("hidden oneliner visible to a regular user")
	}

	// ...but moderators see them, flagged.
	a.Sess.User = mod
	s = newOnelinerScreen(a, nil)
	view = s.View(a)
	if !strings.Contains(view, "[hidden]") || !strings.Contains(view, "hello from the wall") {
		t.Fatalf("moderator cannot see hidden oneliner:\n%s", view)
	}
}

func TestWhoScreenView(t *testing.T) {
	a, st, _, _ := commTestApp(t)
	ada := a.User()
	grace := commTestUser(t, st, "grace", domain.RoleUser)

	n1 := a.Presence.Join("s1", ada.ID, ada.Handle, "ip")
	n2 := a.Presence.Join("s2", grace.ID, grace.Handle, "ip")
	n1.Activity = "reading boards"
	n2.Activity = "chat"
	n1.LastSeen = time.Now().UTC().Add(-2 * time.Minute)

	s := newWhoScreen(a, nil)
	view := s.View(a)
	for _, want := range []string{"Who's online", ada.Handle, grace.Handle, "reading boards", "chat", "2m"} {
		if !strings.Contains(view, want) {
			t.Fatalf("who view missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "(coming soon)") {
		t.Fatal("who screen is still a stub")
	}
	if cmd := s.Init(a); cmd == nil {
		t.Fatal("who screen did not schedule its refresh tick")
	}
	if cmd := s.Update(a, commWhoTickMsg{}); cmd == nil {
		t.Fatal("who screen did not re-arm its refresh tick")
	}
}

func TestChatScreenViewWithHistory(t *testing.T) {
	a, st, svc, _ := commTestApp(t)
	ctx := context.Background()

	if err := svc.ChatSend(ctx, a.User(), "global", "hello chat room"); err != nil {
		t.Fatal(err)
	}
	screen := newChatScreen(a, nil)
	chat, ok := screen.(*chatScreen)
	if !ok {
		t.Fatalf("newChatScreen returned %T", screen)
	}
	if chat.channel != "global" {
		t.Fatalf("default channel = %q, want global", chat.channel)
	}
	if cmd := chat.Init(a); cmd == nil {
		t.Fatal("chat screen did not start its subscription")
	}
	t.Cleanup(func() { chat.releaseSubscription(a) })

	view := chat.View(a)
	if !strings.Contains(view, "hello chat room") || !strings.Contains(view, a.User().Handle) {
		t.Fatalf("chat history missing from view:\n%s", view)
	}

	// Live chat and presence notices are appended as they arrive.
	chat.Update(a, HubEventMsg{Event: hub.Event{
		Kind: hub.KindChat, Scope: "chat:global", From: "grace", Text: "live line", At: time.Now().UTC(),
	}})
	chat.Update(a, HubEventMsg{Event: hub.Event{
		Kind: hub.KindPresence, Scope: "*", Text: "grace called in", At: time.Now().UTC(),
	}})
	view = chat.View(a)
	if !strings.Contains(view, "live line") || !strings.Contains(view, "grace called in") {
		t.Fatalf("live chat/presence events missing from view:\n%s", view)
	}

	// A regular user cannot join the sysop channel by passing an argument.
	downgraded := newChatScreen(a, "sysop").(*chatScreen)
	if downgraded.channel != "global" {
		t.Fatalf("non-mod sysop screen joined %q", downgraded.channel)
	}

	// The sysop channel is available to moderators.
	mod := commTestUser(t, st, "mod", domain.RoleModerator)
	a.Sess.User = mod
	sysop := newChatScreen(a, "sysop").(*chatScreen)
	if sysop.channel != "sysop" {
		t.Fatalf("moderator sysop screen joined %q", sysop.channel)
	}
}
