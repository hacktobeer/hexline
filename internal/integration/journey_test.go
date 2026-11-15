// Package integration exercises the services together the way a caller and a
// sysop actually use them: one real SQLite database, no fakes.
package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
)

type board struct {
	t         *testing.T
	cfg       *config.Config
	st        *store.Store
	auth      *service.Auth
	boards    *service.Boards
	mail      *service.Mail
	files     *service.Files
	community *service.Community
	admin     *service.Admin
	broker    *hub.Broker
}

func newBoard(t *testing.T) *board {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Server.DataDir = dir
	cfg.Database.Path = "hexline.db"
	cfg.Storage.FilesDir = "files"
	cfg.Limits.PostRatePerHour = 1000
	cfg.Limits.ChatRatePerMinute = 1000

	st, err := store.Open(filepath.Join(dir, "hexline.db"))
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
	broker := hub.NewBroker(32)
	auth := service.NewAuth(st, cfg, func(e domain.AuditEntry) { _ = st.RecordAudit(e) })
	admin := service.NewAdmin(st, cfg, broker)
	auth.SetBanChecker(admin.IsBanned)
	return &board{
		t: t, cfg: cfg, st: st, auth: auth,
		boards:    service.NewBoards(st, cfg),
		mail:      service.NewMail(st, cfg),
		files:     service.NewFiles(st, cfg),
		community: service.NewCommunity(st, cfg, broker),
		admin:     admin,
		broker:    broker,
	}
}

// account registers a caller and puts them in the requested state.
func (b *board) account(handle string, role domain.Role, status domain.Status) *domain.User {
	b.t.Helper()
	u, err := b.auth.Register(context.Background(), service.RegisterRequest{
		Handle: handle, Password: "password-" + handle, AllowClosed: true,
	})
	if err != nil {
		b.t.Fatalf("register %s: %v", handle, err)
	}
	if err := b.st.SetStatus(u.ID, status); err != nil {
		b.t.Fatal(err)
	}
	if err := b.st.SetRole(u.ID, role); err != nil {
		b.t.Fatal(err)
	}
	u.Status, u.Role = status, role
	return u
}

func (b *board) areaByTag(u *domain.User, tag string) *domain.Area {
	b.t.Helper()
	a, err := b.boards.AreaByTag(context.Background(), u, tag)
	if err != nil {
		b.t.Fatalf("area %s: %v", tag, err)
	}
	return a
}

func TestCallerJourney(t *testing.T) {
	b := newBoard(t)
	ctx := context.Background()

	alice := b.account("alice", domain.RoleUser, domain.StatusActive)
	bob := b.account("bob", domain.RoleUser, domain.StatusActive)
	mod := b.account("moderator1", domain.RoleModerator, domain.StatusActive)
	sysop := b.account("sysop1", domain.RoleSysop, domain.StatusActive)

	general := b.areaByTag(alice, "general")

	// --- boards: post, read, unread, search, moderation -------------------
	thread, err := b.boards.CreateThread(ctx, alice, general.ID, "Hello hexline",
		"first post on this board\n\n*be nice*")
	if err != nil {
		t.Fatalf("create thread: %v", err)
	}
	if n, err := b.boards.UnreadTotal(ctx, bob.ID); err != nil || n != 1 {
		t.Fatalf("bob unread = %d (%v), want 1", n, err)
	}
	if _, err := b.boards.Reply(ctx, bob, thread.ID, "welcome!"); err != nil {
		t.Fatalf("reply: %v", err)
	}
	th, posts, err := b.boards.Thread(ctx, alice, thread.ID)
	if err != nil {
		t.Fatalf("thread: %v", err)
	}
	if th.PostCount != 2 || len(posts) != 2 {
		t.Fatalf("thread has %d posts (count %d), want 2", len(posts), th.PostCount)
	}
	if n, _ := b.boards.UnreadTotal(ctx, alice.ID); n != 1 {
		t.Fatalf("alice unread = %d, want 1 (bob's reply)", n)
	}
	if err := b.boards.MarkRead(ctx, bob, thread.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := b.boards.UnreadTotal(ctx, bob.ID); n != 0 {
		t.Fatalf("bob unread after mark read = %d", n)
	}
	hits, err := b.boards.Search(ctx, bob, "welcome", "", 10)
	if err != nil || len(hits) == 0 {
		t.Fatalf("search: %d hits, %v", len(hits), err)
	}
	if err := b.boards.DeletePost(ctx, bob, posts[0].ID, "not allowed"); err == nil {
		t.Fatal("plain user was allowed to delete a post")
	}
	if err := b.boards.DeletePost(ctx, mod, posts[0].ID, "off topic"); err != nil {
		t.Fatalf("moderator delete: %v", err)
	}
	if _, visible, _ := b.boards.Thread(ctx, bob, thread.ID); len(visible) != 1 {
		t.Fatalf("deleted post still visible: %d posts", len(visible))
	}

	// --- mail -------------------------------------------------------------
	msg, err := b.mail.Send(ctx, alice, "bob", "hello", "private words")
	if err != nil {
		t.Fatalf("send mail: %v", err)
	}
	if n, _ := b.mail.UnreadCount(ctx, bob.ID); n != 1 {
		t.Fatalf("bob unread mail = %d", n)
	}
	got, err := b.mail.Message(ctx, bob, msg.ID)
	if err != nil || got.Body != "private words" {
		t.Fatalf("read mail: %+v %v", got, err)
	}
	if n, _ := b.mail.UnreadCount(ctx, bob.ID); n != 0 {
		t.Fatalf("mail still unread: %d", n)
	}
	if _, err := b.mail.Message(ctx, mod, msg.ID); err == nil {
		t.Fatal("third party could read private mail")
	}

	// --- files: upload, download, hash ------------------------------------
	payload := []byte("hexline file round trip\n")
	sum := sha256.Sum256(payload)
	file, err := b.files.Upload(ctx, alice, "uploads", "journey.txt", "test artifact",
		bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if file.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %s", file.SHA256)
	}
	rc, gotFile, err := b.files.OpenDownload(ctx, bob, "uploads", "journey.txt")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(body, payload) || gotFile.SizeBytes != int64(len(payload)) {
		t.Fatalf("download mismatch: %q", body)
	}

	// --- community --------------------------------------------------------
	if _, err := b.community.PostOneliner(ctx, bob, "hello wall"); err != nil {
		t.Fatalf("oneliner: %v", err)
	}
	poll, err := b.community.CreatePoll(ctx, sysop, "Tabs or spaces?", []string{"tabs", "spaces"}, time.Time{})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if err := b.community.Vote(ctx, alice, poll.ID, poll.Options[0].ID); err != nil {
		t.Fatalf("vote: %v", err)
	}
	if err := b.community.Vote(ctx, alice, poll.ID, poll.Options[1].ID); err == nil {
		t.Fatal("double vote accepted")
	}
	if _, err := b.community.CreateBulletin(ctx, sysop, "Maintenance", "Tonight 23:00 UTC", 10); err != nil {
		t.Fatalf("bulletin: %v", err)
	}
	bulletins, err := b.community.Bulletins(ctx, alice)
	if err != nil || len(bulletins) == 0 {
		t.Fatalf("bulletins: %d (%v)", len(bulletins), err)
	}
	if err := b.community.Dismiss(ctx, alice, bulletins[0].ID); err != nil {
		t.Fatal(err)
	}
	after, _ := b.community.Bulletins(ctx, alice)
	if len(after) != len(bulletins)-1 {
		t.Fatalf("dismiss did not hide bulletin: %d -> %d", len(bulletins), len(after))
	}
	if err := b.community.ChatSend(ctx, alice, "global", "hi from alice"); err != nil {
		t.Fatalf("chat: %v", err)
	}
	if len(b.community.ChatHistory("global")) == 0 {
		t.Fatal("chat history empty after send")
	}
	if err := b.community.ChatSend(ctx, alice, "sysop", "not allowed"); err == nil {
		t.Fatal("plain user posted to the sysop channel")
	}

	// --- sysop: stats, audit, bans ----------------------------------------
	stats, err := b.admin.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Users < 4 || stats.Areas < 3 || stats.Posts != 2 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	audit, err := b.admin.ListAudit(ctx, 100)
	if err != nil || len(audit) == 0 {
		t.Fatalf("audit: %d (%v)", len(audit), err)
	}
	actions := map[string]bool{}
	for _, e := range audit {
		actions[e.Action] = true
	}
	for _, want := range []string{"auth.register", "post.delete"} {
		if !actions[want] {
			t.Errorf("audit missing %q", want)
		}
	}
	if _, err := b.admin.SetBan(ctx, alice, "handle", "bob", "test", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("non-sysop set a ban")
	}
	if _, err := b.admin.SetBan(ctx, sysop, "handle", "bob", "spam", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("ban: %v", err)
	}
	if banned, _, _ := b.admin.IsBanned(ctx, "BOB", ""); !banned {
		t.Fatal("ban lookup is not case-insensitive")
	}
	if _, err := b.auth.Authenticate(ctx, "bob", "password-bob", "ip1"); err == nil {
		t.Fatal("banned caller logged in")
	}

	// --- retention dry run ------------------------------------------------
	pruned, err := b.admin.Prune(ctx, true)
	if err != nil {
		t.Fatalf("prune dry run: %v", err)
	}
	if pruned.Sessions != 0 || pruned.DeletedPosts != 0 {
		t.Fatalf("dry run removed something: %+v", pruned)
	}
}
