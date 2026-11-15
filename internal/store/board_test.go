package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

func boardTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "board.db"))
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

func boardTestUser(t *testing.T, st *Store, handle string, role domain.Role, status domain.Status) *domain.User {
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

func boardTestArea(t *testing.T, st *Store, tag string) *domain.Area {
	t.Helper()
	a, err := st.BoardAreaByTag(tag)
	if err != nil {
		t.Fatalf("area %s: %v", tag, err)
	}
	return a
}

func TestBoardUnreadMathAcrossUsers(t *testing.T) {
	st := boardTestStore(t)
	area := boardTestArea(t, st, "general")
	alice := boardTestUser(t, st, "alice", domain.RoleUser, domain.StatusActive)
	bob := boardTestUser(t, st, "bob", domain.RoleUser, domain.StatusActive)

	t0 := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Second)
	thread, err := st.CreateThread(area.ID, alice.ID, "Unread test", "first post", t0)
	if err != nil {
		t.Fatalf("create thread: %v", err)
	}
	reply1, err := st.CreatePost(thread.ID, bob.ID, "second", t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("reply 1: %v", err)
	}
	reply2, err := st.CreatePost(thread.ID, alice.ID, "third", t0.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("reply 2: %v", err)
	}
	reply3, err := st.CreatePost(thread.ID, bob.ID, "fourth", t0.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("reply 3: %v", err)
	}

	// Two users, no read state: every live post is unread.
	for _, u := range []*domain.User{alice, bob} {
		got, err := st.ListThreads(area.ID, u.ID, 10, 0)
		if err != nil || len(got) != 1 {
			t.Fatalf("list for %s = %d, %v", u.Handle, len(got), err)
		}
		if got[0].Unread != 4 {
			t.Fatalf("%s unread before reading = %d, want 4", u.Handle, got[0].Unread)
		}
	}

	// Alice reads through the first reply: two later posts remain unread for her.
	if err := st.MarkThreadRead(alice.ID, thread.ID, reply1.ID, t0.Add(4*time.Minute)); err != nil {
		t.Fatalf("mark read: %v", err)
	}
	aliceThread, err := st.ThreadByID(thread.ID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if aliceThread.Unread != 2 {
		t.Fatalf("alice unread after partial read = %d, want 2", aliceThread.Unread)
	}
	bobThread, err := st.ThreadByID(thread.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bobThread.Unread != 4 {
		t.Fatalf("bob unread changed unexpectedly: %d", bobThread.Unread)
	}
	aliceTotal, err := st.UnreadTotalForAreas(alice.ID, []string{area.ID})
	if err != nil || aliceTotal != 2 {
		t.Fatalf("alice total = %d, %v; want 2", aliceTotal, err)
	}
	bobTotal, err := st.UnreadTotalForAreas(bob.ID, []string{area.ID})
	if err != nil || bobTotal != 4 {
		t.Fatalf("bob total = %d, %v; want 4", bobTotal, err)
	}
	counts, err := st.UnreadCountsByArea(alice.ID, []string{area.ID})
	if err != nil || counts[area.ID] != 2 {
		t.Fatalf("alice area counts = %v, %v; want 2", counts, err)
	}

	// Deleting a post removes it from every user's unread math.
	if err := st.SoftDeletePost(reply2.ID, alice.ID, "spam"); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	aliceThread, _ = st.ThreadByID(thread.ID, alice.ID)
	if aliceThread.Unread != 1 {
		t.Fatalf("alice unread after delete = %d, want 1", aliceThread.Unread)
	}
	bobThread, _ = st.ThreadByID(thread.ID, bob.ID)
	if bobThread.Unread != 3 {
		t.Fatalf("bob unread after delete = %d, want 3", bobThread.Unread)
	}
	if bobThread.PostCount != 3 {
		t.Fatalf("post_count after delete = %d, want 3", bobThread.PostCount)
	}

	// Mark-all-read is per user and only moves forward.
	if err := st.MarkAreaRead(alice.ID, area.ID, t0.Add(5*time.Minute)); err != nil {
		t.Fatalf("mark area read: %v", err)
	}
	aliceThread, _ = st.ThreadByID(thread.ID, alice.ID)
	if aliceThread.Unread != 0 {
		t.Fatalf("alice unread after mark-all = %d, want 0", aliceThread.Unread)
	}
	if err := st.MarkThreadRead(alice.ID, thread.ID, reply1.ID, t0.Add(6*time.Minute)); err != nil {
		t.Fatalf("backward mark: %v", err)
	}
	last, err := st.ThreadRead(alice.ID, thread.ID)
	if err != nil {
		t.Fatal(err)
	}
	if last != reply3.ID {
		t.Fatalf("read pointer moved backwards to %d, want %d", last, reply3.ID)
	}
	bobThread, _ = st.ThreadByID(thread.ID, bob.ID)
	if bobThread.Unread != 3 {
		t.Fatalf("bob unread after alice mark-all = %d, want 3", bobThread.Unread)
	}
}

func TestBoardPostInsertUpdatesThreadCounters(t *testing.T) {
	st := boardTestStore(t)
	area := boardTestArea(t, st, "general")
	u := boardTestUser(t, st, "countuser", domain.RoleUser, domain.StatusActive)

	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	thread, err := st.CreateThread(area.ID, u.ID, "Counters", "one", t0)
	if err != nil {
		t.Fatal(err)
	}
	if thread.PostCount != 1 || !thread.LastPostAt.Equal(t0) {
		t.Fatalf("new thread count=%d last=%v, want 1/%v", thread.PostCount, thread.LastPostAt, t0)
	}
	if _, err := st.CreatePost(thread.ID, u.ID, "two", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePost(thread.ID, u.ID, "three", t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	thread, err = st.ThreadByID(thread.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if thread.PostCount != 3 {
		t.Fatalf("post_count = %d, want 3", thread.PostCount)
	}
	if !thread.LastPostAt.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("last_post_at = %v, want %v", thread.LastPostAt, t0.Add(2*time.Minute))
	}
	posts, err := st.PostsByThreadPage(thread.ID, 0, 100, false)
	if err != nil || len(posts) != 3 {
		t.Fatalf("posts = %d, %v; want 3", len(posts), err)
	}
	if posts[0].Body != "one" || posts[2].Body != "three" {
		t.Fatalf("posts out of order: %q ... %q", posts[0].Body, posts[2].Body)
	}
}

func TestBoardFTSSearchFindsBodiesAndExcludesDeleted(t *testing.T) {
	st := boardTestStore(t)
	general := boardTestArea(t, st, "general")
	tech := boardTestArea(t, st, "tech")
	u := boardTestUser(t, st, "searchuser", domain.RoleUser, domain.StatusActive)

	now := time.Now().UTC()
	generalThread, err := st.CreateThread(general.ID, u.ID, "Welcome to Hexline",
		"The quick brown fox jumps over the lazy dog", now)
	if err != nil {
		t.Fatal(err)
	}
	generalReply, err := st.CreatePost(generalThread.ID, u.ID,
		"A kernel debugging session is attached", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateThread(tech.ID, u.ID, "Kernel patch", "kernel patch notes", now); err != nil {
		t.Fatal(err)
	}

	hits, err := st.SearchPosts("kernel", []string{general.ID, tech.ID}, 10)
	if err != nil {
		t.Fatalf("search kernel: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("kernel hits = %d, want 2", len(hits))
	}
	if hits[0].ThreadID == "" {
		t.Fatal("search hit missing thread id")
	}

	hits, err = st.SearchPosts("quick", []string{general.ID, tech.ID}, 10)
	if err != nil || len(hits) != 1 {
		t.Fatalf("quick hits = %d, %v; want 1", len(hits), err)
	}
	if hits[0].Body != "The quick brown fox jumps over the lazy dog" {
		t.Fatalf("unexpected quick hit body %q", hits[0].Body)
	}

	// Area filtering is applied after the FTS match.
	hits, err = st.SearchPosts("kernel", []string{general.ID}, 10)
	if err != nil || len(hits) != 1 || hits[0].ThreadID != generalThread.ID {
		t.Fatalf("general kernel hits = %+v, %v", hits, err)
	}

	if _, err := st.SearchPosts("zebra", []string{general.ID, tech.ID}, 10); err != nil {
		t.Fatalf("no-match search: %v", err)
	}
	// Operator-looking input must be treated as text, never as FTS syntax.
	if _, err := st.SearchPosts(`" OR 1=1 --`, []string{general.ID, tech.ID}, 10); err != nil {
		t.Fatalf("injection-shaped search returned error: %v", err)
	}

	if err := st.SoftDeletePost(generalReply.ID, u.ID, "test"); err != nil {
		t.Fatal(err)
	}
	hits, err = st.SearchPosts("kernel", []string{general.ID}, 10)
	if err != nil {
		t.Fatalf("search after delete: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("deleted post still searchable: %+v", hits)
	}
	all, err := st.PostsByThreadPage(generalThread.ID, 0, 100, true)
	if err != nil || len(all) != 2 {
		t.Fatalf("moderator post view = %d, %v; want 2 including deleted", len(all), err)
	}
	if !all[1].Deleted || all[1].DeletedBy != u.ID || all[1].DeleteWhy != "test" {
		t.Fatalf("deleted post metadata = %+v", all[1])
	}
}

func TestBoardMoveThreadPreservesPosts(t *testing.T) {
	st := boardTestStore(t)
	general := boardTestArea(t, st, "general")
	tech := boardTestArea(t, st, "tech")
	u := boardTestUser(t, st, "moveuser", domain.RoleUser, domain.StatusActive)
	now := time.Now().UTC()

	thread, err := st.CreateThread(general.ID, u.ID, "Movable", "first", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreatePost(thread.ID, u.ID, "second", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	before, err := st.PostsByThreadPage(thread.ID, 0, 100, false)
	if err != nil {
		t.Fatal(err)
	}

	if err := st.MoveThread(thread.ID, tech.ID); err != nil {
		t.Fatalf("move: %v", err)
	}
	moved, err := st.ThreadByID(thread.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if moved.AreaID != tech.ID || moved.AreaTag != "tech" {
		t.Fatalf("moved thread area = %s/%s, want tech", moved.AreaID, moved.AreaTag)
	}
	after, err := st.PostsByThreadPage(thread.ID, 0, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("posts changed on move: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i].ID != after[i].ID || before[i].Body != after[i].Body {
			t.Fatalf("post %d changed on move: %+v -> %+v", i, before[i], after[i])
		}
	}

	generalThreads, err := st.ListThreads(general.ID, u.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(generalThreads) != 0 {
		t.Fatalf("moved thread still listed in general: %+v", generalThreads)
	}
	techThreads, err := st.ListThreads(tech.ID, u.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(techThreads) != 1 || techThreads[0].ID != thread.ID {
		t.Fatalf("moved thread missing from tech: %+v", techThreads)
	}

	var movedFrom string
	if err := st.DB().QueryRow(`SELECT COALESCE(moved_from_area_id, '') FROM threads WHERE id = ?`,
		thread.ID).Scan(&movedFrom); err != nil {
		t.Fatal(err)
	}
	if movedFrom != general.ID {
		t.Fatalf("moved_from_area_id = %q, want %q", movedFrom, general.ID)
	}
}
