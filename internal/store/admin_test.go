package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

func admTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "admin.db"))
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

func admTestUser(t *testing.T, st *Store, handle string, role domain.Role, status domain.Status) *domain.User {
	t.Helper()
	u := &domain.User{
		Handle: handle, Role: role, Status: status,
		PassHash: "x", PassParams: "x", CreatedAt: time.Now().UTC(),
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", handle, err)
	}
	return u
}

func admTestArea(t *testing.T, st *Store, tag string) *domain.Area {
	t.Helper()
	a := &domain.Area{
		Tag: tag, Name: strings.ToUpper(tag), IsPublic: true,
		ACL: domain.DefaultACL(), CreatedAt: time.Now().UTC(),
	}
	if err := st.CreateArea(a); err != nil {
		t.Fatalf("create area %s: %v", tag, err)
	}
	return a
}

func admInsertPost(t *testing.T, st *Store, areaID, authorID string, at time.Time, deleted bool) (string, int64) {
	t.Helper()
	threadID := newID()
	if _, err := st.DB().Exec(`INSERT INTO threads(id, area_id, subject, author_id, created_at, last_post_at)
		VALUES (?, ?, ?, ?, ?, ?)`, threadID, areaID, "subject", authorID, at.Unix(), at.Unix()); err != nil {
		t.Fatalf("insert thread: %v", err)
	}
	res, err := st.DB().Exec(`INSERT INTO posts(thread_id, author_id, body, created_at, is_deleted)
		VALUES (?, ?, ?, ?, ?)`, threadID, authorID, "body", at.Unix(), boolInt(deleted))
	if err != nil {
		t.Fatalf("insert post: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return threadID, id
}

func TestAdminCounts(t *testing.T) {
	st := admTestStore(t)
	active := admTestUser(t, st, "active1", domain.RoleUser, domain.StatusActive)
	admTestUser(t, st, "prob1", domain.RoleUser, domain.StatusProbation)
	admTestUser(t, st, "susp1", domain.RoleUser, domain.StatusSuspended)
	area := admTestArea(t, st, "extra")
	fa := &domain.FileArea{Tag: "downloads", Name: "Downloads", ACL: domain.DefaultACL()}
	if err := st.CreateFileArea(fa); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	_, _ = admInsertPost(t, st, area.ID, active.ID, now, false)
	if _, err := st.DB().Exec(`INSERT INTO files(id, area_id, filename, stored_path, size_bytes, sha256, uploader_id, uploaded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, newID(), fa.ID, "x.zip", "/tmp/x", 10, "abc", active.ID, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO mail(id, from_id, to_id, subject, body, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, newID(), active.ID, active.ID, "hi", "body", now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO oneliners(author_id, body, created_at) VALUES (?, ?, ?)`,
		active.ID, "hello", now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO sessions(id, user_id, node, started_at) VALUES (?, ?, ?, ?)`,
		newID(), active.ID, 1, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO sessions(id, user_id, node, started_at) VALUES (?, ?, ?, ?)`,
		newID(), active.ID, 2, now.Add(-48*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}

	c, err := st.AdminCounts()
	if err != nil {
		t.Fatal(err)
	}
	if c.Users != 3 || c.Active != 1 || c.Probation != 1 || c.Suspended != 1 {
		t.Fatalf("user counts = %+v", c)
	}
	if c.Areas != 4 { // three seeded + extra
		t.Errorf("areas = %d, want 4", c.Areas)
	}
	if c.Threads != 1 || c.Posts != 1 {
		t.Errorf("threads/posts = %d/%d", c.Threads, c.Posts)
	}
	if c.FileAreas != 2 || c.Files != 1 { // seeded uploads + downloads
		t.Errorf("file areas/files = %d/%d", c.FileAreas, c.Files)
	}
	if c.Mail != 1 || c.Oneliners != 1 {
		t.Errorf("mail/oneliners = %d/%d", c.Mail, c.Oneliners)
	}
	if c.Sessions24h != 1 {
		t.Errorf("sessions24h = %d, want 1", c.Sessions24h)
	}
	if c.DBBytes <= 0 {
		t.Errorf("db bytes = %d", c.DBBytes)
	}
}

func TestAdminAreaCRUDConflict(t *testing.T) {
	st := admTestStore(t)
	author := admTestUser(t, st, "author", domain.RoleUser, domain.StatusActive)
	area := admTestArea(t, st, "retro")

	got, err := st.AdminAreaByTag("RETRO")
	if err != nil || got.ID != area.ID {
		t.Fatalf("lookup by tag = %+v, %v", got, err)
	}
	if _, err := st.AdminAreaByID(area.ID); err != nil {
		t.Fatalf("lookup by id: %v", err)
	}

	dup := &domain.Area{Tag: "retro", Name: "Dup", ACL: domain.DefaultACL()}
	if err := st.CreateArea(dup); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate tag error = %v, want conflict", err)
	}

	area.Name = "Retro Computing"
	area.Description = "8-bit and beyond"
	area.ACL.Read = []domain.Role{domain.RoleModerator}
	area.RetentionDays = 14
	area.RateLimitPerHour = 5
	if err := st.UpdateArea(area); err != nil {
		t.Fatal(err)
	}
	got, err = st.AdminAreaByID(area.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Retro Computing" || got.RetentionDays != 14 || got.RateLimitPerHour != 5 {
		t.Fatalf("update not persisted: %+v", got)
	}
	if !got.ACL.CanRead(domain.RoleModerator) || got.ACL.CanRead(domain.RoleUser) {
		t.Fatalf("read ACL not persisted: %v", got.ACL.Read)
	}

	admInsertPost(t, st, area.ID, author.ID, time.Now().UTC(), false)
	if err := st.DeleteArea(area.ID, false); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("delete with threads = %v, want conflict", err)
	}
	if err := st.DeleteArea(area.ID, true); err != nil {
		t.Fatalf("forced delete: %v", err)
	}
	if _, err := st.AdminAreaByID(area.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("area still present: %v", err)
	}
	if n, _ := st.CountAreaThreads(area.ID); n != 0 {
		t.Fatalf("threads survived cascade: %d", n)
	}

	// File area tags are unique too.
	fa := &domain.FileArea{Tag: "warez", Name: "Files", ACL: domain.DefaultACL()}
	if err := st.CreateFileArea(fa); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateFileArea(&domain.FileArea{Tag: "WAREZ", Name: "Dup", ACL: domain.DefaultACL()}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate file area tag = %v, want conflict", err)
	}
	gotFA, err := st.FileAreaByTag("warez")
	if err != nil {
		t.Fatal(err)
	}
	gotFA.Name = "Warez"
	gotFA.QuotaBytes = 1024
	if err := st.UpdateFileArea(gotFA); err != nil {
		t.Fatal(err)
	}
	reloaded, err := st.FileAreaByID(gotFA.ID)
	if err != nil || reloaded.Name != "Warez" || reloaded.QuotaBytes != 1024 {
		t.Fatalf("file area update = %+v, %v", reloaded, err)
	}
	if err := st.DeleteFileArea(gotFA.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteFileArea(gotFA.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second file area delete = %v", err)
	}
}

func TestAdminBansExpiryAndLookup(t *testing.T) {
	st := admTestStore(t)
	now := time.Now().UTC()
	live := &domain.Ban{Scope: "handle", Value: "Troll", Reason: "abuse", CreatedBy: "sysop",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	expired := &domain.Ban{Scope: "handle", Value: "oldhandle", Reason: "old", CreatedBy: "sysop",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	ip := &domain.Ban{Scope: "ip", Value: "deadbeef", Reason: "flood", CreatedBy: "sysop", CreatedAt: now}
	for _, b := range []*domain.Ban{live, expired, ip} {
		if err := st.CreateBan(b); err != nil {
			t.Fatalf("create ban: %v", err)
		}
	}

	got, err := st.ActiveBan("handle", "troll", now)
	if err != nil || got.ID != live.ID {
		t.Fatalf("case-insensitive active ban = %+v, %v", got, err)
	}
	if _, err := st.ActiveBan("handle", "oldhandle", now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expired ban returned: %v", err)
	}
	if got, err := st.ActiveBan("ip", "DEADBEEF", now); err != nil || got.ID != ip.ID {
		t.Fatalf("ip ban = %+v, %v", got, err)
	}
	bans, err := st.ListBans()
	if err != nil || len(bans) != 3 {
		t.Fatalf("list bans = %d, %v", len(bans), err)
	}
	if err := st.RemoveBan(live.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveBan(live.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second remove = %v, want not found", err)
	}
	if bans, _ := st.ListBans(); len(bans) != 2 {
		t.Fatalf("bans after remove = %d", len(bans))
	}
}

func TestAdminPrunePrimitives(t *testing.T) {
	st := admTestStore(t)
	user := admTestUser(t, st, "pruner", domain.RoleUser, domain.StatusActive)
	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)

	for _, at := range []time.Time{old, time.Now().UTC()} {
		if _, err := st.DB().Exec(`INSERT INTO sessions(id, user_id, node, started_at) VALUES (?, ?, ?, ?)`,
			newID(), user.ID, 1, at.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB().Exec(`INSERT INTO login_attempts(at, ip_hash, handle, ok) VALUES (?, ?, ?, 0)`,
			at.Unix(), "iphash", user.Handle); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB().Exec(`INSERT INTO oneliners(author_id, body, created_at) VALUES (?, ?, ?)`,
			user.ID, "old wall", at.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordAudit(domain.AuditEntry{At: old, Actor: "sysop", Action: "old.action"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAudit(domain.AuditEntry{At: time.Now().UTC(), Actor: "sysop", Action: "new.action"}); err != nil {
		t.Fatal(err)
	}
	area := admTestArea(t, st, "prunearea")
	admInsertPost(t, st, area.ID, user.ID, old, true)
	admInsertPost(t, st, area.ID, user.ID, time.Now().UTC(), true)
	admInsertPost(t, st, area.ID, user.ID, old, false)

	if n, err := st.CountSessionsBefore(cutoff); err != nil || n != 1 {
		t.Fatalf("sessions before = %d, %v", n, err)
	}
	if n, err := st.CountAuditBefore(cutoff); err != nil || n != 1 {
		t.Fatalf("audit before = %d, %v", n, err)
	}
	if n, err := st.CountOnelinersBefore(cutoff); err != nil || n != 1 {
		t.Fatalf("oneliners before = %d, %v", n, err)
	}
	if n, err := st.CountDeletedPostsBefore(cutoff); err != nil || n != 1 {
		t.Fatalf("deleted posts before = %d, %v", n, err)
	}

	// Counts do not delete; the real prune is idempotent.
	if _, err := st.CountSessionsBefore(cutoff); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PruneSessions(cutoff); err != nil || n != 1 {
		t.Fatalf("prune sessions = %d, %v", n, err)
	}
	if n, err := st.PruneLoginAttempts(cutoff); err != nil || n != 1 {
		t.Fatalf("prune login attempts = %d, %v", n, err)
	}
	if n, err := st.PruneAudit(cutoff); err != nil || n != 1 {
		t.Fatalf("prune audit = %d, %v", n, err)
	}
	if n, err := st.PruneOneliners(cutoff); err != nil || n != 1 {
		t.Fatalf("prune oneliners = %d, %v", n, err)
	}
	if n, err := st.PruneDeletedPosts(cutoff); err != nil || n != 1 {
		t.Fatalf("prune deleted posts = %d, %v", n, err)
	}
	if n, err := st.PruneDeletedPosts(cutoff); err != nil || n != 0 {
		t.Fatalf("second prune not idempotent: %d, %v", n, err)
	}
	// The live post and the live audit row survive.
	var livePosts, liveAudit int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM posts WHERE is_deleted = 0`).Scan(&livePosts); err != nil {
		t.Fatal(err)
	}
	if livePosts != 1 {
		t.Fatalf("live posts = %d, want 1", livePosts)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'new.action'`).Scan(&liveAudit); err != nil {
		t.Fatal(err)
	}
	if liveAudit != 1 {
		t.Fatalf("live audit rows = %d", liveAudit)
	}
}

func TestAdminAuditListAndSettings(t *testing.T) {
	st := admTestStore(t)
	if err := st.RecordAudit(domain.AuditEntry{Actor: "sysop", Action: "first.action", Detail: `{"n":1}`}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAudit(domain.AuditEntry{Actor: "mod", Action: "second.action", TargetKind: "user", TargetID: "u1"}); err != nil {
		t.Fatal(err)
	}
	entries, err := st.ListAudit(1)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list audit = %d, %v", len(entries), err)
	}
	if entries[0].Action != "second.action" || entries[0].Detail != "{}" {
		t.Fatalf("newest audit entry = %+v", entries[0])
	}
	entries, err = st.ListAudit(10)
	if err != nil || len(entries) != 2 || entries[0].Action != "second.action" {
		t.Fatalf("audit order = %+v, %v", entries, err)
	}

	if err := st.SetSetting("motd.enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("motd.enabled", "false"); err != nil {
		t.Fatal(err)
	}
	settings, err := st.ListSettings()
	if err != nil || settings["motd.enabled"] != "false" {
		t.Fatalf("settings = %v, %v", settings, err)
	}
}
