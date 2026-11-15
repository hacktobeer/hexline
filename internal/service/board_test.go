package service

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/store"
)

func boardTestEnv(t *testing.T) (*store.Store, *config.Config, *Boards) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service-board.db"))
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
	return st, cfg, NewBoards(st, cfg)
}

func boardTestUser(t *testing.T, st *store.Store, handle string, role domain.Role, status domain.Status) *domain.User {
	t.Helper()
	u := &domain.User{
		Handle: handle, Role: role, Status: status,
		PassHash: "x", PassParams: "m=1,t=1,p=1",
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", handle, err)
	}
	return u
}

func boardTestAreaWithACL(t *testing.T, st *store.Store, tag, read, post, moderate string) *domain.Area {
	t.Helper()
	_, err := st.DB().Exec(`INSERT INTO areas(id, tag, name, description, sort_order,
		acl_read, acl_post, acl_moderate, created_at) VALUES (?, ?, ?, '', 100, ?, ?, ?, ?)`,
		"area-"+tag, tag, strings.ToUpper(tag), read, post, moderate, time.Now().Unix())
	if err != nil {
		t.Fatalf("create area %s: %v", tag, err)
	}
	area, err := st.BoardAreaByTag(tag)
	if err != nil {
		t.Fatalf("lookup area %s: %v", tag, err)
	}
	return area
}

func TestBoardsACLEnforcement(t *testing.T) {
	st, _, boards := boardTestEnv(t)
	ctx := context.Background()
	general, err := st.BoardAreaByTag("general")
	if err != nil {
		t.Fatal(err)
	}
	private := boardTestAreaWithACL(t, st, "private", "moderator", "moderator", "sysop")
	readonly := boardTestAreaWithACL(t, st, "readonly", "user", "moderator", "sysop")

	user := boardTestUser(t, st, "plainuser", domain.RoleUser, domain.StatusActive)
	mod := boardTestUser(t, st, "moduser", domain.RoleModerator, domain.StatusActive)
	sysop := boardTestUser(t, st, "sysuser", domain.RoleSysop, domain.StatusActive)
	guest := &domain.User{Handle: "guest", IsGuest: true, Status: domain.StatusActive}

	// Read ACL: unreadable areas are absent from the list and deny direct use.
	areas, err := boards.Areas(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range areas {
		if a.ID == private.ID {
			t.Fatal("private area leaked into a plain user's area list")
		}
	}
	foundGeneral, foundReadonly := false, false
	for _, a := range areas {
		if a.ID == general.ID {
			foundGeneral = true
		}
		if a.ID == readonly.ID {
			foundReadonly = true
		}
	}
	if !foundGeneral || !foundReadonly {
		t.Fatalf("expected general and readonly areas, got %+v", areas)
	}
	if _, err := boards.AreaByTag(ctx, user, "private"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("AreaByTag private = %v, want permission", err)
	}
	if _, err := boards.Threads(ctx, user, private.ID, 10, 0); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("Threads private = %v, want permission", err)
	}

	// Post ACL: reading is allowed, posting is not.
	if _, err := boards.Threads(ctx, user, readonly.ID, 10, 0); err != nil {
		t.Fatalf("readonly area should be readable: %v", err)
	}
	if _, err := boards.CreateThread(ctx, user, readonly.ID, "nope", "body"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("CreateThread readonly = %v, want permission", err)
	}
	thread, err := boards.CreateThread(ctx, mod, readonly.ID, "mod thread", "body")
	if err != nil {
		t.Fatalf("moderator post in readonly: %v", err)
	}

	// Moderate ACL is area scoped: a moderator cannot lock in a sysop area.
	if err := boards.SetThreadFlags(ctx, mod, thread.ID, false, true); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("moderator lock in sysop area = %v, want permission", err)
	}
	if err := boards.SetThreadFlags(ctx, sysop, thread.ID, false, true); err != nil {
		t.Fatalf("sysop lock: %v", err)
	}
	locked, _, err := boards.Thread(ctx, sysop, thread.ID)
	if err != nil || !locked.Locked {
		t.Fatalf("thread not locked: %+v, %v", locked, err)
	}

	// Guests may read public areas but never write.
	guestAreas, err := boards.Areas(ctx, guest)
	if err != nil {
		t.Fatal(err)
	}
	if len(guestAreas) == 0 {
		t.Fatal("guest should see at least one readable area")
	}
	if _, err := boards.CreateThread(ctx, guest, general.ID, "guest post", "body"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("guest CreateThread = %v, want permission", err)
	}
	if _, err := boards.AreaByTag(ctx, guest, "private"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("guest read of private = %v, want permission", err)
	}

}

func TestBoardsLockedThreadRejectsReply(t *testing.T) {
	st, _, boards := boardTestEnv(t)
	ctx := context.Background()
	general, _ := st.BoardAreaByTag("general")
	user := boardTestUser(t, st, "lockuser", domain.RoleUser, domain.StatusActive)
	mod := boardTestUser(t, st, "lockmod", domain.RoleModerator, domain.StatusActive)

	thread, err := boards.CreateThread(ctx, user, general.ID, "Lock me", "first")
	if err != nil {
		t.Fatal(err)
	}
	if err := boards.SetThreadFlags(ctx, mod, thread.ID, false, true); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if _, err := boards.Reply(ctx, user, thread.ID, "should fail"); !errors.Is(err, domain.ErrClosed) {
		t.Fatalf("reply to locked thread = %v, want closed", err)
	}
	if _, err := boards.Reply(ctx, mod, thread.ID, "mod reply"); !errors.Is(err, domain.ErrClosed) {
		t.Fatalf("moderator reply to locked thread = %v, want closed", err)
	}
	if err := boards.SetThreadFlags(ctx, mod, thread.ID, false, false); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := boards.Reply(ctx, user, thread.ID, "works now"); err != nil {
		t.Fatalf("reply after unlock: %v", err)
	}
}

func TestBoardsProbationLinkRejection(t *testing.T) {
	st, _, boards := boardTestEnv(t)
	ctx := context.Background()
	general, _ := st.BoardAreaByTag("general")
	probation := boardTestUser(t, st, "probuser", domain.RoleUser, domain.StatusProbation)
	active := boardTestUser(t, st, "activeuser", domain.RoleUser, domain.StatusActive)

	for _, body := range []string{
		"see https://example.com for details",
		"http://example.com",
		"visit www.example.com",
	} {
		if _, err := boards.CreateThread(ctx, probation, general.ID, "link", body); !errors.Is(err, domain.ErrProbation) {
			t.Fatalf("probation body %q = %v, want probation", body, err)
		}
	}
	thread, err := boards.CreateThread(ctx, probation, general.ID, "no link", "plain words only")
	if err != nil {
		t.Fatalf("probation plain post: %v", err)
	}
	if _, err := boards.Reply(ctx, probation, thread.ID, "reply https://example.com"); !errors.Is(err, domain.ErrProbation) {
		t.Fatalf("probation reply link = %v, want probation", err)
	}

	// Active accounts may post links.
	if _, err := boards.CreateThread(ctx, active, general.ID, "links ok", "https://example.com"); err != nil {
		t.Fatalf("active link post: %v", err)
	}
}

func TestBoardsPostRateLimit(t *testing.T) {
	st, cfg, boards := boardTestEnv(t)
	cfg.Limits.PostRatePerHour = 1
	ctx := context.Background()
	general, _ := st.BoardAreaByTag("general")
	user := boardTestUser(t, st, "rateuser", domain.RoleUser, domain.StatusActive)
	other := boardTestUser(t, st, "rateother", domain.RoleUser, domain.StatusActive)

	thread, err := boards.CreateThread(ctx, user, general.ID, "first", "one")
	if err != nil {
		t.Fatalf("first post: %v", err)
	}
	if _, err := boards.Reply(ctx, user, thread.ID, "second"); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("second post = %v, want rate limited", err)
	}
	// Rate limits are per account.
	if _, err := boards.Reply(ctx, other, thread.ID, "other user"); err != nil {
		t.Fatalf("other user post: %v", err)
	}
}

func TestBoardsSoftDeleteVisibilityAndAudit(t *testing.T) {
	st, _, boards := boardTestEnv(t)
	ctx := context.Background()
	general, _ := st.BoardAreaByTag("general")
	author := boardTestUser(t, st, "delauthor", domain.RoleUser, domain.StatusActive)
	mod := boardTestUser(t, st, "delmod", domain.RoleModerator, domain.StatusActive)

	thread, err := boards.CreateThread(ctx, author, general.ID, "Delete me", "first post")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := boards.Reply(ctx, author, thread.ID, "second post"); err != nil {
		t.Fatal(err)
	}
	_, posts, err := boards.Thread(ctx, mod, thread.ID)
	if err != nil || len(posts) != 2 {
		t.Fatalf("moderator posts = %d, %v; want 2", len(posts), err)
	}
	first := posts[0]

	if err := boards.DeletePost(ctx, author, first.ID, "self delete"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("author delete = %v, want permission", err)
	}
	if err := boards.DeletePost(ctx, mod, first.ID, "spam"); err != nil {
		t.Fatalf("moderator delete: %v", err)
	}
	if err := boards.DeletePost(ctx, mod, first.ID, "again"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("double delete = %v, want conflict", err)
	}

	_, regularPosts, err := boards.Thread(ctx, author, thread.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(regularPosts) != 1 || regularPosts[0].Body != "second post" {
		t.Fatalf("regular user sees deleted post: %+v", regularPosts)
	}
	_, modPosts, err := boards.Thread(ctx, mod, thread.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(modPosts) != 2 || !modPosts[0].Deleted || modPosts[0].DeleteWhy != "spam" {
		t.Fatalf("moderator deleted view = %+v", modPosts)
	}

	entries, err := st.ListAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "post.delete" && e.TargetID == strconv.FormatInt(first.ID, 10) {
			found = true
		}
	}
	if !found {
		t.Fatalf("post.delete audit row missing: %+v", entries)
	}
}

func TestBoardsValidationAndSanitization(t *testing.T) {
	st, cfg, boards := boardTestEnv(t)
	cfg.Limits.PostMaxBytes = 1024
	ctx := context.Background()
	general, _ := st.BoardAreaByTag("general")
	user := boardTestUser(t, st, "validuser", domain.RoleUser, domain.StatusActive)

	if _, err := boards.CreateThread(ctx, user, general.ID, "", "body"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty subject = %v, want invalid", err)
	}
	if _, err := boards.CreateThread(ctx, user, general.ID, strings.Repeat("x", 121), "body"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("long subject = %v, want invalid", err)
	}
	if _, err := boards.CreateThread(ctx, user, general.ID, "subject", "   \n\t "); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty body = %v, want invalid", err)
	}
	if _, err := boards.CreateThread(ctx, user, general.ID, "subject", strings.Repeat("a", 1025)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("long body = %v, want invalid", err)
	}

	thread, err := boards.CreateThread(ctx, user, general.ID,
		"clean\x01\r\nsubject", "danger\x07body\x00")
	if err != nil {
		t.Fatalf("sanitizing create: %v", err)
	}
	got, posts, err := boards.Thread(ctx, user, thread.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "clean subject" {
		t.Fatalf("stored subject = %q, want %q", got.Subject, "clean subject")
	}
	if len(posts) != 1 || posts[0].Body != "dangerbody" {
		t.Fatalf("stored body = %+v, want sanitized", posts)
	}
}

func TestBoardsSearchRespectsACLAndUnreadTotal(t *testing.T) {
	st, _, boards := boardTestEnv(t)
	ctx := context.Background()
	general, _ := st.BoardAreaByTag("general")
	private := boardTestAreaWithACL(t, st, "secret", "moderator", "moderator", "moderator")
	user := boardTestUser(t, st, "searchacl", domain.RoleUser, domain.StatusActive)
	mod := boardTestUser(t, st, "searchmod", domain.RoleModerator, domain.StatusActive)

	if _, err := boards.CreateThread(ctx, mod, private.ID, "secret plans", "pineapple protocol"); err != nil {
		t.Fatal(err)
	}
	thread, err := boards.CreateThread(ctx, user, general.ID, "public plans", "pineapple protocol")
	if err != nil {
		t.Fatal(err)
	}
	hits, err := boards.Search(ctx, user, "pineapple", "", 20)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 || hits[0].ThreadID != thread.ID {
		t.Fatalf("regular search leaked private area: %+v", hits)
	}
	if _, err := boards.Search(ctx, user, "pineapple", private.ID, 20); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("search in private area = %v, want permission", err)
	}
	if _, err := boards.Search(ctx, user, "   ", "", 20); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty search = %v, want invalid", err)
	}

	// Authors do not get an unread badge for their own posts; a reply from
	// someone else is what makes the thread unread.
	if _, err := boards.Reply(ctx, mod, thread.ID, "reply in the public thread"); err != nil {
		t.Fatal(err)
	}
	total, err := boards.UnreadTotal(ctx, user.ID)
	if err != nil || total != 1 {
		t.Fatalf("unread total = %d, %v; want 1", total, err)
	}
	if err := boards.MarkAllRead(ctx, user, general.ID); err != nil {
		t.Fatal(err)
	}
	total, err = boards.UnreadTotal(ctx, user.ID)
	if err != nil || total != 0 {
		t.Fatalf("unread total after mark all = %d, %v; want 0", total, err)
	}
}

func TestThreadLoadsLatestPageAndOlderPosts(t *testing.T) {
	st, _, boards := boardTestEnv(t)
	ctx := context.Background()
	user := boardTestUser(t, st, "pager", domain.RoleUser, domain.StatusActive)
	general, err := st.BoardAreaByTag("general")
	if err != nil {
		t.Fatal(err)
	}
	thread, err := boards.CreateThread(ctx, user, general.ID, "long thread", "post 0")
	if err != nil {
		t.Fatal(err)
	}
	// Seed directly: the service rate limit is intentionally low.
	for i := 1; i < 60; i++ {
		if _, err := st.CreatePost(thread.ID, user.ID, "post "+strconv.Itoa(i), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}

	th, page, err := boards.Thread(ctx, user, thread.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 50 {
		t.Fatalf("first page = %d posts, want 50", len(page))
	}
	if page[len(page)-1].Body != "post 59" {
		t.Fatalf("latest post missing: %q", page[len(page)-1].Body)
	}
	if th.PostCount != 60 {
		t.Fatalf("thread count = %d, want 60", th.PostCount)
	}

	older, err := boards.OlderPosts(ctx, user, thread.ID, page[0].ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(older) != 10 {
		t.Fatalf("older page = %d posts, want 10", len(older))
	}
	if older[len(older)-1].ID >= page[0].ID {
		t.Fatal("older page overlaps the first page")
	}
}
