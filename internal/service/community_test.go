package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/store"
)

type commClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *commClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *commClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func commTestService(t *testing.T) (*Community, *store.Store, *commClock) {
	t.Helper()
	st := testStore(t)
	cfg := testConfig()
	cfg.Limits.ChatRatePerMinute = 30
	svc := NewCommunity(st, cfg, hub.NewBroker(16))
	clk := &commClock{now: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)}
	svc.SetClock(clk.Now)
	return svc, st, clk
}

func commTestUser(t *testing.T, st *store.Store, handle string, role domain.Role, status domain.Status) *domain.User {
	t.Helper()
	u := &domain.User{
		Handle:     handle,
		Role:       role,
		Status:     status,
		CreatedAt:  time.Now().UTC(),
		PassHash:   "x",
		PassParams: "x",
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", handle, err)
	}
	return u
}

func commTestGuest() *domain.User {
	return &domain.User{Handle: "guest", Role: domain.RoleUser, Status: domain.StatusActive, IsGuest: true}
}

func TestOnelinerAuthzSanitizeAndAudit(t *testing.T) {
	svc, st, _ := commTestService(t)
	ctx := context.Background()
	user := commTestUser(t, st, "ada", domain.RoleUser, domain.StatusActive)
	mod := commTestUser(t, st, "mod", domain.RoleModerator, domain.StatusActive)
	guest := commTestGuest()

	if _, err := svc.PostOneliner(ctx, guest, "hello"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("guest post: want ErrPermission, got %v", err)
	}
	if _, err := svc.PostOneliner(ctx, user, ""); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty post: want ErrInvalid, got %v", err)
	}
	if _, err := svc.PostOneliner(ctx, user, strings.Repeat("a", 201)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("oversize post: want ErrInvalid, got %v", err)
	}

	o, err := svc.PostOneliner(ctx, user, "\x1b[31mhello\nworld\x1b[0m")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(o.Body, "\x1b") || strings.Contains(o.Body, "\n") {
		t.Fatalf("stored body was not sanitized: %q", o.Body)
	}
	if o.Body != "[31mhello world[0m" {
		t.Fatalf("body = %q, want flattened sanitized text", o.Body)
	}

	stored, err := st.ListOneliners(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].Body != o.Body || stored[0].Author != user.Handle {
		t.Fatalf("stored oneliner mismatch: %+v", stored)
	}

	if err := svc.HideOneliner(ctx, user, o.ID, true); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("non-mod hide: want ErrPermission, got %v", err)
	}
	if err := svc.HideOneliner(ctx, mod, o.ID, true); err != nil {
		t.Fatal(err)
	}
	stored, err = st.ListOneliners(5)
	if err != nil {
		t.Fatal(err)
	}
	if !stored[0].Hidden {
		t.Fatal("moderator hide was not persisted")
	}
	audit, err := st.ListAudit(20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range audit {
		if e.Action == "oneliner.hide" && e.ActorID == mod.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("hide was not audited: %+v", audit)
	}
	if err := svc.HideOneliner(ctx, mod, o.ID, false); err != nil {
		t.Fatal(err)
	}
}

func TestOnelinerRateLimitWithFakeClock(t *testing.T) {
	svc, st, clk := commTestService(t)
	ctx := context.Background()
	user := commTestUser(t, st, "ada", domain.RoleUser, domain.StatusActive)
	other := commTestUser(t, st, "grace", domain.RoleUser, domain.StatusActive)

	for i := 0; i < 5; i++ {
		if _, err := svc.PostOneliner(ctx, user, fmt.Sprintf("post %d", i)); err != nil {
			t.Fatalf("post %d: %v", i, err)
		}
	}
	if _, err := svc.PostOneliner(ctx, user, "one too many"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	clk.Advance(9 * time.Minute)
	if _, err := svc.PostOneliner(ctx, user, "still too early"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("window expired too soon: %v", err)
	}
	clk.Advance(2 * time.Minute)
	if _, err := svc.PostOneliner(ctx, user, "window rolled over"); err != nil {
		t.Fatalf("after window: %v", err)
	}
	if _, err := svc.PostOneliner(ctx, other, "different user"); err != nil {
		t.Fatalf("per-user limit leaked: %v", err)
	}
}

func TestPollAuthzValidationVotesAndClosed(t *testing.T) {
	svc, st, clk := commTestService(t)
	ctx := context.Background()
	user := commTestUser(t, st, "ada", domain.RoleUser, domain.StatusActive)
	other := commTestUser(t, st, "grace", domain.RoleUser, domain.StatusActive)
	mod := commTestUser(t, st, "mod", domain.RoleModerator, domain.StatusActive)
	guest := commTestGuest()

	if _, err := svc.CreatePoll(ctx, user, "q", []string{"a", "b"}, time.Time{}); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("non-mod create: want ErrPermission, got %v", err)
	}

	eleven := make([]string, 11)
	for i := range eleven {
		eleven[i] = fmt.Sprintf("option %d", i)
	}
	invalid := []struct {
		name     string
		question string
		options  []string
		closes   time.Time
	}{
		{"empty question", "", []string{"a", "b"}, time.Time{}},
		{"too few options", "q", []string{"a"}, time.Time{}},
		{"too many options", "q", eleven, time.Time{}},
		{"empty option", "q", []string{"a", ""}, time.Time{}},
		{"long question", strings.Repeat("q", 161), []string{"a", "b"}, time.Time{}},
		{"long option", "q", []string{"a", strings.Repeat("o", 81)}, time.Time{}},
		{"past close", "q", []string{"a", "b"}, clk.Now().Add(-time.Minute)},
	}
	for _, tc := range invalid {
		if _, err := svc.CreatePoll(ctx, mod, tc.question, tc.options, tc.closes); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", tc.name, err)
		}
	}

	closes := clk.Now().Add(time.Hour)
	p, err := svc.CreatePoll(ctx, mod, " Tabs or spaces? ", []string{" tabs ", "spaces"}, closes)
	if err != nil {
		t.Fatal(err)
	}
	if p.Question != "Tabs or spaces?" || len(p.Options) != 2 || p.Options[0].Label != "tabs" {
		t.Fatalf("poll not sanitized/filled: %+v", p)
	}

	if err := svc.Vote(ctx, guest, p.ID, p.Options[0].ID); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("guest vote: want ErrPermission, got %v", err)
	}
	if err := svc.Vote(ctx, user, p.ID, p.Options[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Vote(ctx, user, p.ID, p.Options[1].ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second vote: want ErrConflict, got %v", err)
	}
	if err := svc.Vote(ctx, other, p.ID, 999999); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("foreign option: want ErrInvalid, got %v", err)
	}

	got, err := svc.Poll(ctx, user, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalVotes != 1 || got.MyVote != p.Options[0].ID {
		t.Fatalf("results wrong: %+v", got)
	}
	list, err := svc.Polls(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != p.ID {
		t.Fatalf("poll list wrong: %+v", list)
	}
	if _, err := svc.Polls(ctx, guest); err != nil {
		t.Fatalf("guest cannot read polls: %v", err)
	}

	// The clock moves past closes_at: no more votes.
	clk.Advance(2 * time.Hour)
	err = svc.Vote(ctx, other, p.ID, p.Options[0].ID)
	if !errors.Is(err, domain.ErrConflict) || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed poll vote: want closed conflict, got %v", err)
	}
}

func TestBulletinAuthzSanitizeDismissAndPerUser(t *testing.T) {
	svc, st, _ := commTestService(t)
	ctx := context.Background()
	user := commTestUser(t, st, "ada", domain.RoleUser, domain.StatusActive)
	other := commTestUser(t, st, "grace", domain.RoleUser, domain.StatusActive)
	mod := commTestUser(t, st, "mod", domain.RoleModerator, domain.StatusActive)
	guest := commTestGuest()

	if _, err := svc.CreateBulletin(ctx, user, "title", "body", 1); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("non-mod create: want ErrPermission, got %v", err)
	}
	if err := svc.UpdateBulletin(ctx, user, "welcome", "t", "b", true); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("non-mod update: want ErrPermission, got %v", err)
	}
	if err := svc.DeleteBulletin(ctx, user, "welcome"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("non-mod delete: want ErrPermission, got %v", err)
	}

	if _, err := svc.CreateBulletin(ctx, mod, "", "body", 1); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty title: want ErrInvalid, got %v", err)
	}
	if _, err := svc.CreateBulletin(ctx, mod, "title", "", 1); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty body: want ErrInvalid, got %v", err)
	}

	b, err := svc.CreateBulletin(ctx, mod, " Hello \x1b[31mworld ", "\x1b[2Jnotice\nline two", 5)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.Title, "\x1b") || strings.Contains(b.Body, "\x1b") {
		t.Fatalf("bulletin kept escape sequences: %+v", b)
	}
	if !strings.Contains(b.Body, "\n") {
		t.Fatalf("bulletin body lost its newline: %q", b.Body)
	}

	forUser, err := svc.Bulletins(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if !commHasBulletinID(forUser, b.ID) {
		t.Fatal("bulletin missing for user")
	}
	forOther, err := svc.Bulletins(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if !commHasBulletinID(forOther, b.ID) {
		t.Fatal("bulletin missing for other user")
	}

	if err := svc.Dismiss(ctx, user, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Dismiss(ctx, user, b.ID); err != nil {
		t.Fatalf("dismiss is not idempotent: %v", err)
	}
	forUser, err = svc.Bulletins(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if commHasBulletinID(forUser, b.ID) {
		t.Fatal("dismissal did not hide the bulletin for its user")
	}
	forOther, err = svc.Bulletins(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if !commHasBulletinID(forOther, b.ID) {
		t.Fatal("dismissal leaked to another user")
	}
	if err := svc.Dismiss(ctx, guest, b.ID); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("guest dismiss: want ErrPermission, got %v", err)
	}

	if err := svc.UpdateBulletin(ctx, mod, b.ID, "updated", "updated body", false); err != nil {
		t.Fatal(err)
	}
	forOther, err = svc.Bulletins(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	if commHasBulletinID(forOther, b.ID) {
		t.Fatal("inactive bulletin still listed")
	}
	if err := svc.DeleteBulletin(ctx, mod, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateBulletin(ctx, mod, "missing", "t", "b", true); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("update missing: want ErrNotFound, got %v", err)
	}
	if err := svc.DeleteBulletin(ctx, mod, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing: want ErrNotFound, got %v", err)
	}
}

func commHasBulletinID(list []domain.Bulletin, id string) bool {
	for _, b := range list {
		if b.ID == id {
			return true
		}
	}
	return false
}

func TestChatAuthzSanitizeChannelsAndEvents(t *testing.T) {
	svc, st, _ := commTestService(t)
	ctx := context.Background()
	user := commTestUser(t, st, "ada", domain.RoleUser, domain.StatusActive)
	mod := commTestUser(t, st, "mod", domain.RoleModerator, domain.StatusActive)
	guest := commTestGuest()

	if err := svc.ChatSend(ctx, guest, "global", "hi"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("guest send: want ErrPermission, got %v", err)
	}
	if err := svc.ChatSend(ctx, user, "sysop", "hi"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("non-mod sysop send: want ErrPermission, got %v", err)
	}
	if err := svc.ChatSend(ctx, user, "bogus", "hi"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("unknown channel: want ErrInvalid, got %v", err)
	}
	if err := svc.ChatSend(ctx, user, "global", "   "); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty message: want ErrInvalid, got %v", err)
	}
	if err := svc.ChatSend(ctx, user, "global", strings.Repeat("x", 401)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("oversize message: want ErrInvalid, got %v", err)
	}
	if err := svc.ChatSend(ctx, user, "global", "  hi \x1b[31mthere\x1b[0m "); err != nil {
		t.Fatal(err)
	}
	history := svc.ChatHistory("global")
	if len(history) != 1 {
		t.Fatalf("history length = %d, want 1", len(history))
	}
	ev := history[0]
	if ev.Kind != hub.KindChat || ev.Scope != "chat:global" || ev.FromID != user.ID || ev.From != user.Handle {
		t.Fatalf("event metadata wrong: %+v", ev)
	}
	if strings.Contains(ev.Text, "\x1b") || ev.Text != "hi [31mthere[0m" {
		t.Fatalf("chat text not sanitized: %q", ev.Text)
	}
	if svc.ChatLastSend(user.ID).IsZero() {
		t.Fatal("last send time not recorded")
	}
	if !svc.ChatLastSend(mod.ID).IsZero() {
		t.Fatal("last send leaked between users")
	}
	if got := len(svc.ChatHistory("global")); got != 1 {
		t.Fatalf("guest cannot read history: %d", got)
	}

	if err := svc.ChatSend(ctx, mod, "sysop", "mods only"); err != nil {
		t.Fatal(err)
	}
	if n := len(svc.ChatHistory("sysop")); n != 1 {
		t.Fatalf("sysop history length = %d, want 1", n)
	}
	if n := len(svc.ChatHistory("global")); n != 1 {
		t.Fatalf("sysop message leaked into global: %d", n)
	}

	// Publishing reaches broker subscribers with the same scope.
	ch, cancel := svc.broker.Subscribe("chat:global")
	defer cancel()
	if err := svc.ChatSend(ctx, user, "global", "event test"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got.Text != "event test" || got.Scope != "chat:global" {
			t.Fatalf("broker event wrong: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not deliver the chat event")
	}

	// History is a copy: callers cannot mutate the ring buffer.
	copied := svc.ChatHistory("global")
	copied[0].Text = "tampered"
	if svc.ChatHistory("global")[0].Text == "tampered" {
		t.Fatal("ChatHistory returned a mutable alias")
	}
	if got := svc.ChatHistory("bogus"); got != nil {
		t.Fatalf("unknown channel history = %+v, want nil", got)
	}
}

func TestChatRateLimitAndHistoryRing(t *testing.T) {
	svc, st, clk := commTestService(t)
	ctx := context.Background()
	user := commTestUser(t, st, "ada", domain.RoleUser, domain.StatusActive)
	svc.cfg.Limits.ChatRatePerMinute = 2

	if err := svc.ChatSend(ctx, user, "global", "one"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ChatSend(ctx, user, "global", "two"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ChatSend(ctx, user, "global", "three"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	clk.Advance(31 * time.Second)
	if err := svc.ChatSend(ctx, user, "global", "four"); err != nil {
		t.Fatalf("after refill: %v", err)
	}
	if err := svc.ChatSend(ctx, user, "global", "five"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("burst not limited: %v", err)
	}
	clk.Advance(30 * time.Second)
	if err := svc.ChatSend(ctx, user, "global", "six"); err != nil {
		t.Fatalf("after second refill: %v", err)
	}

	// A fresh service with a high limit exercises the 100-event ring buffer.
	svc2, st2, _ := commTestService(t)
	svc2.cfg.Limits.ChatRatePerMinute = 1000
	user2 := commTestUser(t, st2, "grace", domain.RoleUser, domain.StatusActive)
	for i := 0; i < 120; i++ {
		if err := svc2.ChatSend(ctx, user2, "global", fmt.Sprintf("m%03d", i)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	history := svc2.ChatHistory("global")
	if len(history) != 100 {
		t.Fatalf("ring buffer length = %d, want 100", len(history))
	}
	if history[0].Text != "m020" || history[99].Text != "m119" {
		t.Fatalf("ring buffer boundary wrong: first=%q last=%q", history[0].Text, history[99].Text)
	}
}
