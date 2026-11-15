package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/store"
)

func admServiceFixture(t *testing.T) (*Admin, *store.Store, *domain.User, *domain.User, *domain.User) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "admin.db"))
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
	admin := NewAdmin(st, cfg, broker)
	sysop := admServiceUser(t, st, "root", domain.RoleSysop)
	mod := admServiceUser(t, st, "mod", domain.RoleModerator)
	plain := admServiceUser(t, st, "caller", domain.RoleUser)
	return admin, st, sysop, mod, plain
}

func admServiceUser(t *testing.T, st *store.Store, handle string, role domain.Role) *domain.User {
	t.Helper()
	u := &domain.User{
		Handle: handle, Role: role, Status: domain.StatusActive,
		PassHash: "x", PassParams: "x", CreatedAt: time.Now().UTC(),
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create %s: %v", handle, err)
	}
	return u
}

func admServiceArea(t *testing.T, admin *Admin, actor *domain.User, tag string) *domain.Area {
	t.Helper()
	a, err := admin.CreateArea(context.Background(), actor, tag, tag+" area", "desc", 10, "user", "user", "moderator")
	if err != nil {
		t.Fatalf("create area %s: %v", tag, err)
	}
	return a
}

func admServicePost(t *testing.T, st *store.Store, areaID, userID string, at time.Time, deleted bool) {
	t.Helper()
	threadID := fmt.Sprintf("thread-%s-%d-%t-%d", userID, at.UnixNano(), deleted, time.Now().UnixNano())
	if _, err := st.DB().Exec(`INSERT INTO threads(id, area_id, subject, author_id, created_at, last_post_at)
		VALUES (?, ?, ?, ?, ?, ?)`, threadID, areaID, "s", userID, at.Unix(), at.Unix()); err != nil {
		t.Fatal(err)
	}
	v := 0
	if deleted {
		v = 1
	}
	if _, err := st.DB().Exec(`INSERT INTO posts(thread_id, author_id, body, created_at, is_deleted)
		VALUES (?, ?, ?, ?, ?)`, threadID, userID, "body", at.Unix(), v); err != nil {
		t.Fatal(err)
	}
}

func TestAdminMutationsRequireSysop(t *testing.T) {
	admin, st, sysop, mod, plain := admServiceFixture(t)
	ctx := context.Background()
	area := admServiceArea(t, admin, sysop, "existing")
	fa, err := admin.CreateFileArea(ctx, sysop, "files", "Files", "", 10, "user", "user", 0)
	if err != nil {
		t.Fatal(err)
	}
	ban, err := admin.SetBan(ctx, sysop, "handle", "badactor", "spam", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	bulletin, err := admin.CreateBulletin(ctx, sysop, "Notice", "hello", 10)
	if err != nil {
		t.Fatal(err)
	}
	_ = fa

	mutations := []struct {
		name string
		call func(actor *domain.User) error
	}{
		{"Broadcast", func(actor *domain.User) error {
			return admin.Broadcast(ctx, actor, "hello")
		}},
		{"CreateArea", func(actor *domain.User) error {
			_, err := admin.CreateArea(ctx, actor, "newarea", "New", "", 10, "user", "user", "moderator")
			return err
		}},
		{"UpdateArea", func(actor *domain.User) error {
			return admin.UpdateArea(ctx, actor, area.ID, "Renamed", "", 10, "user", "user", "moderator", 0, 0)
		}},
		{"DeleteArea", func(actor *domain.User) error {
			return admin.DeleteArea(ctx, actor, area.ID, false)
		}},
		{"CreateFileArea", func(actor *domain.User) error {
			_, err := admin.CreateFileArea(ctx, actor, "other", "Other", "", 10, "user", "user", 0)
			return err
		}},
		{"SetBan", func(actor *domain.User) error {
			_, err := admin.SetBan(ctx, actor, "handle", "someone", "", time.Time{})
			return err
		}},
		{"RemoveBan", func(actor *domain.User) error {
			return admin.RemoveBan(ctx, actor, ban.ID)
		}},
		{"SetUserStatus", func(actor *domain.User) error {
			return admin.SetUserStatus(ctx, actor, plain.ID, domain.StatusSuspended)
		}},
		{"SetUserRole", func(actor *domain.User) error {
			return admin.SetUserRole(ctx, actor, plain.ID, domain.RoleSysop)
		}},
		{"CreateBulletin", func(actor *domain.User) error {
			_, err := admin.CreateBulletin(ctx, actor, "T", "B", 10)
			return err
		}},
		{"DeleteBulletin", func(actor *domain.User) error {
			return admin.DeleteBulletin(ctx, actor, bulletin.ID)
		}},
		{"CreatePoll", func(actor *domain.User) error {
			_, err := admin.CreatePoll(ctx, actor, "Q?", []string{"a", "b"}, time.Time{})
			return err
		}},
		{"Prune", func(actor *domain.User) error {
			_, err := admin.Prune(WithAdminActor(ctx, actor), false)
			return err
		}},
	}
	for _, m := range mutations {
		for _, actor := range []*domain.User{plain, mod, nil} {
			if err := m.call(actor); !errors.Is(err, domain.ErrPermission) {
				t.Errorf("%s as %v = %v, want permission denied", m.name, admActorName(actor), err)
			}
		}
	}
	// Nothing was mutated by the denied calls.
	if got, err := st.AdminCounts(); err != nil {
		t.Fatal(err)
	} else if got.Areas != 4 {
		t.Errorf("areas after denied calls = %d, want 4", got.Areas)
	}
}

func admActorName(u *domain.User) string {
	if u == nil {
		return "nil"
	}
	return string(u.Role)
}

func TestAdminAuditsEveryMutation(t *testing.T) {
	admin, _, sysop, _, plain := admServiceFixture(t)
	ctx := context.Background()
	area := admServiceArea(t, admin, sysop, "audited")
	fa, err := admin.CreateFileArea(ctx, sysop, "auditfiles", "Audit files", "", 20, "user", "user", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.UpdateArea(ctx, sysop, area.ID, "Audited area", "changed", 20,
		"user", "user", "moderator", 7, 3); err != nil {
		t.Fatal(err)
	}
	ban, err := admin.SetBan(ctx, sysop, "handle", "naughty", "reason", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.RemoveBan(ctx, sysop, ban.ID); err != nil {
		t.Fatal(err)
	}
	if err := admin.Broadcast(ctx, sysop, "maintenance at midnight"); err != nil {
		t.Fatal(err)
	}
	if err := admin.SetUserStatus(ctx, sysop, plain.ID, domain.StatusSuspended); err != nil {
		t.Fatal(err)
	}
	if err := admin.SetUserRole(ctx, sysop, plain.ID, domain.RoleModerator); err != nil {
		t.Fatal(err)
	}
	bulletin, err := admin.CreateBulletin(ctx, sysop, "Audit bulletin", "body", 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.DeleteBulletin(ctx, sysop, bulletin.ID); err != nil {
		t.Fatal(err)
	}
	poll, err := admin.CreatePoll(ctx, sysop, "Coffee?", []string{"yes", "no"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	_ = poll
	_ = fa
	if _, err := admin.Prune(WithAdminActor(ctx, sysop), false); err != nil {
		t.Fatal(err)
	}
	if err := admin.DeleteArea(ctx, sysop, area.ID, false); err != nil {
		t.Fatal(err)
	}

	entries, err := admin.ListAudit(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range entries {
		seen[e.Action]++
		if e.Action == "admin.broadcast" && e.Actor != sysop.Handle {
			t.Errorf("broadcast actor = %q", e.Actor)
		}
	}
	for _, action := range []string{
		"area.create", "area.update", "area.delete", "filearea.create",
		"ban.add", "ban.remove", "admin.broadcast", "admin.prune",
		"user.status", "user.role", "bulletin.create", "bulletin.delete", "poll.create",
	} {
		if seen[action] == 0 {
			t.Errorf("no audit row for %s (seen: %v)", action, seen)
		}
	}
}

func TestAdminPruneDryRunThenReal(t *testing.T) {
	admin, st, sysop, _, _ := admServiceFixture(t)
	admin.cfg.Retention = config.Retention{
		SessionsDays: 30, AuditDays: 30, OnelinerDays: 30, DeletedPostsDays: 30,
	}
	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	now := time.Now().UTC()
	area := &domain.Area{Tag: "prunable", Name: "Prunable", ACL: domain.DefaultACL(), IsPublic: true}
	if err := st.CreateArea(area); err != nil {
		t.Fatal(err)
	}

	for _, at := range []time.Time{old, now} {
		if _, err := st.DB().Exec(`INSERT INTO sessions(id, user_id, node, started_at) VALUES (?, ?, 1, ?)`,
			"session-"+at.Format("150405.000000000"), sysop.ID, at.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB().Exec(`INSERT INTO login_attempts(at, ip_hash, handle, ok) VALUES (?, 'ip', 'root', 0)`,
			at.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB().Exec(`INSERT INTO oneliners(author_id, body, created_at) VALUES (?, 'wall', ?)`,
			sysop.ID, at.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordAudit(domain.AuditEntry{At: old, Actor: "root", Action: "ancient.action"}); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordAudit(domain.AuditEntry{At: now, Actor: "root", Action: "recent.action"}); err != nil {
		t.Fatal(err)
	}
	admServicePost(t, st, area.ID, sysop.ID, old, true)
	admServicePost(t, st, area.ID, sysop.ID, now, true)
	admServicePost(t, st, area.ID, sysop.ID, old, false)

	ctx := WithAdminActor(context.Background(), sysop)
	dry, err := admin.Prune(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	want := PruneResult{Sessions: 1, Audit: 1, Oneliners: 1, DeletedPosts: 1}
	if dry != want {
		t.Fatalf("dry run = %+v, want %+v", dry, want)
	}
	// Dry run must not delete anything.
	var sessions, attempts, audits, oneliners int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM login_attempts`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM oneliners`).Scan(&oneliners); err != nil {
		t.Fatal(err)
	}
	if sessions != 2 || attempts != 2 || audits != 2 || oneliners != 2 {
		t.Fatalf("dry run removed rows: sessions=%d attempts=%d audit=%d oneliners=%d",
			sessions, attempts, audits, oneliners)
	}

	real, err := admin.Prune(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if real != want {
		t.Fatalf("real run = %+v, want %+v", real, want)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM login_attempts`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM oneliners`).Scan(&oneliners); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 || attempts != 1 || oneliners != 1 {
		t.Fatalf("real prune counts: sessions=%d attempts=%d oneliners=%d", sessions, attempts, oneliners)
	}
	var liveDeleted int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM posts WHERE is_deleted = 1`).Scan(&liveDeleted); err != nil {
		t.Fatal(err)
	}
	if liveDeleted != 1 {
		t.Fatalf("deleted posts after prune = %d, want 1 recent", liveDeleted)
	}
	// Prune itself is audited, so the recent audit row survives and a new one exists.
	entries, err := admin.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "admin.prune" {
			found = true
		}
	}
	if !found {
		t.Fatal("real prune did not write an audit row")
	}
}

func TestAdminStatsAfterFixtures(t *testing.T) {
	admin, st, sysop, _, plain := admServiceFixture(t)
	ctx := context.Background()
	before, err := admin.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Users != 3 || before.Active != 3 {
		t.Fatalf("baseline users = %+v", before)
	}
	area := admServiceArea(t, admin, sysop, "statsarea")
	admServicePost(t, st, area.ID, sysop.ID, time.Now().UTC(), false)
	fa, err := admin.CreateFileArea(ctx, sysop, "statsfiles", "Stats files", "", 10, "user", "user", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO files(id, area_id, filename, stored_path, size_bytes, sha256, uploader_id, uploaded_at)
		VALUES ('f1', ?, 'one.zip', '/tmp/one', 12, 'abc', ?, ?)`, fa.ID, plain.ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO mail(id, from_id, to_id, subject, body, created_at)
		VALUES ('m1', ?, ?, 'hi', 'there', ?)`, sysop.ID, plain.ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO oneliners(author_id, body, created_at) VALUES (?, 'hello', ?)`,
		plain.ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`INSERT INTO sessions(id, user_id, node, started_at) VALUES ('s1', ?, 1, ?)`,
		sysop.ID, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	after, err := admin.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Areas != before.Areas+1 || after.Threads != before.Threads+1 || after.Posts != before.Posts+1 {
		t.Errorf("area/thread/post deltas: before %+v after %+v", before, after)
	}
	if after.FileAreas != before.FileAreas+1 || after.Files != before.Files+1 {
		t.Errorf("file deltas: before %+v after %+v", before, after)
	}
	if after.Mail != before.Mail+1 || after.Oneliners != before.Oneliners+1 {
		t.Errorf("community deltas: before %+v after %+v", before, after)
	}
	if after.Sessions24h != before.Sessions24h+1 {
		t.Errorf("sessions24h = %d, want %d", after.Sessions24h, before.Sessions24h+1)
	}
	if after.DBBytes <= 0 {
		t.Errorf("db bytes = %d", after.DBBytes)
	}
}

func TestAdminBanSemantics(t *testing.T) {
	admin, _, sysop, _, _ := admServiceFixture(t)
	ctx := context.Background()
	live, err := admin.SetBan(ctx, sysop, "handle", "Troll", "abuse", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SetBan(ctx, sysop, "handle", "oldguy", "expired", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ipHash := "AbCdEfGhIjKlMnOpQrStUv" // shape of the server's HMAC
	if _, err := admin.SetBan(ctx, sysop, "ip", ipHash, "flood", time.Time{}); err != nil {
		t.Fatal(err)
	}

	entriesBefore, _ := admin.ListAudit(ctx, 100)
	if banned, reason, err := admin.IsBanned(ctx, "troll", ""); err != nil || !banned || reason != "abuse" {
		t.Fatalf("handle ban = %v %q %v", banned, reason, err)
	}
	if banned, _, err := admin.IsBanned(ctx, "nobody", ipHash); err != nil || !banned {
		t.Fatalf("ip ban = %v %v", banned, err)
	}
	if banned, _, err := admin.IsBanned(ctx, "oldguy", ""); err != nil || banned {
		t.Fatalf("expired ban active = %v %v", banned, err)
	}
	if banned, _, err := admin.IsBanned(ctx, "", ""); err != nil || banned {
		t.Fatalf("empty lookup = %v %v", banned, err)
	}
	entriesAfter, _ := admin.ListAudit(ctx, 100)
	if len(entriesAfter) != len(entriesBefore) {
		t.Fatalf("IsBanned wrote audit rows: %d -> %d", len(entriesBefore), len(entriesAfter))
	}
	bans, err := admin.ListBans(ctx)
	if err != nil || len(bans) != 3 {
		t.Fatalf("list bans = %d, %v", len(bans), err)
	}
	if err := admin.RemoveBan(ctx, sysop, live.ID); err != nil {
		t.Fatal(err)
	}
	if banned, _, err := admin.IsBanned(ctx, "troll", ""); err != nil || banned {
		t.Fatalf("removed ban still active: %v %v", banned, err)
	}
}

func TestAdminAreaValidationAndForceDelete(t *testing.T) {
	admin, st, sysop, _, _ := admServiceFixture(t)
	ctx := context.Background()
	if _, err := admin.CreateArea(ctx, sysop, "BAD", "bad", "", 10, "user", "user", "moderator"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("uppercase tag = %v", err)
	}
	if _, err := admin.CreateArea(ctx, sysop, "x", "x", "", 10, "user", "user", "moderator"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("short tag = %v", err)
	}
	if _, err := admin.CreateArea(ctx, sysop, "okay", "", "", 10, "user", "user", "moderator"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty name = %v", err)
	}
	if _, err := admin.CreateArea(ctx, sysop, "okay", "Okay", "", 10, "wizard", "user", "moderator"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("bad acl = %v", err)
	}
	area := admServiceArea(t, admin, sysop, "conflict")
	if _, err := admin.CreateArea(ctx, sysop, "conflict", "Again", "", 10, "user", "user", "moderator"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate tag = %v, want conflict", err)
	}
	admServicePost(t, st, area.ID, sysop.ID, time.Now().UTC(), false)
	if err := admin.DeleteArea(ctx, sysop, area.ID, false); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("delete with threads = %v, want conflict", err)
	}
	if err := admin.DeleteArea(ctx, sysop, area.ID, true); err != nil {
		t.Fatalf("force delete: %v", err)
	}
	if _, err := admin.SetBan(ctx, sysop, "banana", "x", "", time.Time{}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("bad ban scope = %v", err)
	}
	if _, err := admin.SetBan(ctx, sysop, "handle", "", "", time.Time{}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty ban value = %v", err)
	}
	if _, err := admin.CreatePoll(ctx, sysop, "Q", []string{"only"}, time.Time{}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("one-option poll = %v", err)
	}
}

func TestSetBanRejectsRawIPForIPScope(t *testing.T) {
	admin, _, sysop, _, _ := admServiceFixture(t)
	ctx := context.Background()
	if _, err := admin.SetBan(ctx, sysop, "ip", "203.0.113.5", "spam", time.Time{}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("raw IP accepted as ban value: %v", err)
	}
	b, err := admin.SetBan(ctx, sysop, "ip", "AbCdEfGhIjKlMnOpQrStUv", "spam", time.Time{})
	if err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	if b.Scope != "ip" {
		t.Fatalf("scope = %q", b.Scope)
	}
}
