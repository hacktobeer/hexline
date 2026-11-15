package service

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/store"
)

func mailTestConfig() *config.Config {
	c := config.Default()
	c.Limits.MailQuota = 200
	return c
}

func mailTestStore(t *testing.T) *store.Store {
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
	return st
}

func mailTestUser(t *testing.T, st *store.Store, handle string, status domain.Status, guest bool) *domain.User {
	t.Helper()
	u := &domain.User{
		Handle:   handle,
		PassHash: "x",
		Status:   status,
		Role:     domain.RoleUser,
		IsGuest:  guest,
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create %s: %v", handle, err)
	}
	return u
}

func mailTestService(t *testing.T) (*Mail, *store.Store) {
	t.Helper()
	st := mailTestStore(t)
	return NewMail(st, mailTestConfig()), st
}

func TestMailSendReadAndQuotaCount(t *testing.T) {
	ctx := context.Background()
	m, st := mailTestService(t)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	bob := mailTestUser(t, st, "bob", domain.StatusActive, false)

	msg, err := m.Send(ctx, alice, "bob", "  hello  ", "hi bob\nsecond line")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if msg.Subject != "hello" {
		t.Fatalf("subject = %q, want trimmed", msg.Subject)
	}
	if msg.To != "bob" || msg.From != "alice" {
		t.Fatalf("routing = %s -> %s", msg.From, msg.To)
	}
	if msg.ThreadKey != msg.ID {
		t.Fatalf("new mail thread key = %q, want own id %q", msg.ThreadKey, msg.ID)
	}

	if n, err := m.UnreadCount(ctx, bob.ID); err != nil || n != 1 {
		t.Fatalf("unread = %d, %v; want 1", n, err)
	}
	inbox, err := m.Inbox(ctx, bob, 10, 0)
	if err != nil || len(inbox) != 1 || inbox[0].ID != msg.ID {
		t.Fatalf("inbox = %+v, %v", inbox, err)
	}
	read, err := m.Message(ctx, bob, msg.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if read.ReadAt.IsZero() {
		t.Fatal("reading did not mark the message read")
	}
	if n, _ := m.UnreadCount(ctx, bob.ID); n != 0 {
		t.Fatalf("unread after read = %d, want 0", n)
	}
	sent, err := m.Sent(ctx, alice, 10, 0)
	if err != nil || len(sent) != 1 || sent[0].ID != msg.ID {
		t.Fatalf("sent = %+v, %v", sent, err)
	}
	// Reading again keeps the original read timestamp.
	again, err := m.Message(ctx, bob, msg.ID)
	if err != nil || again.ReadAt.Unix() != read.ReadAt.Unix() {
		t.Fatalf("second read changed read_at: %v, %v", again.ReadAt, err)
	}
}

func TestMailOwnershipEnforced(t *testing.T) {
	ctx := context.Background()
	m, st := mailTestService(t)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	bob := mailTestUser(t, st, "bob", domain.StatusActive, false)
	carol := mailTestUser(t, st, "carol", domain.StatusActive, false)

	msg, err := m.Send(ctx, alice, "bob", "private", "for bob only")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.Message(ctx, carol, msg.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider read = %v, want ErrNotFound", err)
	}
	if err := m.Delete(ctx, carol, msg.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider delete = %v, want ErrNotFound", err)
	}
	if n, _ := m.UnreadCount(ctx, carol.ID); n != 0 {
		t.Fatalf("outsider unread = %d", n)
	}
	if in, err := m.Inbox(ctx, carol, 10, 0); err != nil || len(in) != 0 {
		t.Fatalf("outsider inbox = %+v, %v", in, err)
	}
	// Both participants may read; the sender does not consume the read flag.
	if _, err := m.Message(ctx, alice, msg.ID); err != nil {
		t.Fatalf("sender read: %v", err)
	}
	if n, _ := m.UnreadCount(ctx, bob.ID); n != 1 {
		t.Fatalf("sender read consumed recipient's unread flag: %d", n)
	}
}

func TestMailBlockedSender(t *testing.T) {
	ctx := context.Background()
	m, st := mailTestService(t)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	bob := mailTestUser(t, st, "bob", domain.StatusActive, false)

	if err := m.Block(ctx, bob, "alice", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	blocked, err := m.Blocked(ctx, bob)
	if err != nil || len(blocked) != 1 || blocked[0] != "alice" {
		t.Fatalf("blocked = %v, %v", blocked, err)
	}
	_, err = m.Send(ctx, alice, "bob", "hi", "let me in")
	if !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("blocked send = %v, want ErrPermission", err)
	}
	if !strings.Contains(err.Error(), "does not accept mail from you") {
		t.Fatalf("blocked send message = %q, want a clear reason", err)
	}
	// The blocklist is one-directional: bob can still mail alice.
	if _, err := m.Send(ctx, bob, "alice", "hi", "from bob"); err != nil {
		t.Fatalf("reverse send: %v", err)
	}

	if err := m.Block(ctx, bob, "alice", false); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if _, err := m.Send(ctx, alice, "bob", "hi again", "back in"); err != nil {
		t.Fatalf("send after unblock: %v", err)
	}
	if err := m.Block(ctx, alice, "alice", true); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("self block = %v, want ErrInvalid", err)
	}
	if err := m.Block(ctx, alice, "nobody", true); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("block unknown handle = %v, want ErrNotFound", err)
	}
}

func TestMailQuotaExceeded(t *testing.T) {
	ctx := context.Background()
	st := mailTestStore(t)
	cfg := mailTestConfig()
	cfg.Limits.MailQuota = 2
	m := NewMail(st, cfg)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	bob := mailTestUser(t, st, "bob", domain.StatusActive, false)

	first, err := m.Send(ctx, alice, "bob", "one", "body")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Send(ctx, alice, "bob", "two", "body"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Send(ctx, alice, "bob", "three", "body"); !errors.Is(err, domain.ErrQuota) {
		t.Fatalf("send over quota = %v, want ErrQuota", err)
	}
	if used, max, err := m.Quota(ctx, alice); err != nil || used != 2 || max != 2 {
		t.Fatalf("quota = %d/%d, %v", used, max, err)
	}
	// Deleting a message from the sender's own mailbox frees a slot; the
	// recipient's copy still counts for them.
	if err := m.Delete(ctx, alice, first.ID); err != nil {
		t.Fatal(err)
	}
	if used, _, _ := m.Quota(ctx, alice); used != 1 {
		t.Fatalf("quota after delete = %d, want 1", used)
	}
	if _, err := m.Send(ctx, alice, "bob", "four", "body"); err != nil {
		t.Fatalf("send after freeing a slot: %v", err)
	}
	if used, _, _ := m.Quota(ctx, bob); used != 3 {
		t.Fatalf("recipient quota = %d, want 3", used)
	}
	if _, _, err := m.Quota(ctx, nil); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("nil user quota = %v, want ErrPermission", err)
	}

	// Quota 0 means unlimited.
	unlimitedCfg := mailTestConfig()
	unlimitedCfg.Limits.MailQuota = 0
	unlimited := NewMail(st, unlimitedCfg)
	for i := 0; i < 4; i++ {
		if _, err := unlimited.Send(ctx, bob, "alice", "unlimited", "body"); err != nil {
			t.Fatalf("send %d with unlimited quota: %v", i, err)
		}
	}
}

func TestMailGuestAndRecipientStatus(t *testing.T) {
	ctx := context.Background()
	m, st := mailTestService(t)
	guest := mailTestUser(t, st, "visitor", domain.StatusActive, true)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	mailTestUser(t, st, "suspended", domain.StatusSuspended, false)
	mailTestUser(t, st, "deleted", domain.StatusDeleted, false)

	if _, err := m.Send(ctx, guest, "alice", "hi", "body"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("guest send = %v, want ErrPermission", err)
	}
	if _, err := m.Send(ctx, nil, "alice", "hi", "body"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("nil sender = %v, want ErrPermission", err)
	}
	if _, err := m.Send(ctx, alice, "suspended", "hi", "body"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("suspended recipient = %v, want ErrPermission", err)
	}
	if _, err := m.Send(ctx, alice, "deleted", "hi", "body"); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("deleted recipient = %v, want ErrPermission", err)
	}
	if _, err := m.Send(ctx, alice, "ghost", "hi", "body"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown recipient = %v, want ErrNotFound", err)
	}
	// Nothing was stored by the rejected attempts.
	if n, _ := m.UnreadCount(ctx, alice.ID); n != 0 {
		t.Fatalf("rejected sends stored mail: %d", n)
	}
}

func TestMailSubjectAndBodyValidation(t *testing.T) {
	ctx := context.Background()
	m, st := mailTestService(t)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	mailTestUser(t, st, "bob", domain.StatusActive, false)

	cases := []struct {
		name, subject, body string
	}{
		{"empty subject", "   ", "body"},
		{"long subject", strings.Repeat("s", 121), "body"},
		{"empty body", "subject", "  \n "},
	}
	for _, tc := range cases {
		if _, err := m.Send(ctx, alice, "bob", tc.subject, tc.body); !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("%s = %v, want ErrInvalid", tc.name, err)
		}
	}

	small := NewMail(st, func() *config.Config {
		c := mailTestConfig()
		c.Limits.PostMaxBytes = 10
		c.Limits.MaxBodyLines = 2
		return c
	}())
	if _, err := small.Send(ctx, alice, "bob", "subject", "0123456789abc"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("oversize body = %v, want ErrInvalid", err)
	}
	if _, err := small.Send(ctx, alice, "bob", "subject", "a\nb\nc"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("too many lines = %v, want ErrInvalid", err)
	}
}

func TestMailSanitizesEscapeSequences(t *testing.T) {
	ctx := context.Background()
	m, st := mailTestService(t)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	bob := mailTestUser(t, st, "bob", domain.StatusActive, false)

	subject := "safe\x1b[31mred\x00 text"
	body := "line one\x1b]0;pwned\x07\nline two\u200b with zero width"
	msg, err := m.Send(ctx, alice, "bob", subject, body)
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	// The stored copy (not just the returned value) is free of control bytes.
	stored, err := m.Message(ctx, bob, msg.ID)
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{"subject": stored.Subject, "body": stored.Body} {
		if strings.ContainsRune(s, 0x1b) || strings.ContainsRune(s, 0x00) ||
			strings.ContainsRune(s, 0x07) || strings.ContainsRune(s, '\u200b') {
			t.Fatalf("%s kept dangerous characters: %q", name, s)
		}
	}
	if !strings.Contains(stored.Subject, "safeed text") && !strings.Contains(stored.Subject, "safe") {
		t.Fatalf("subject content lost: %q", stored.Subject)
	}
	if !strings.Contains(stored.Body, "line one") || !strings.Contains(stored.Body, "line two") {
		t.Fatalf("body content lost: %q", stored.Body)
	}

	// A multi-line subject is flattened to one line rather than stored raw.
	flat, err := m.Send(ctx, alice, "bob", "two\nlines\tof subject", "body")
	if err != nil {
		t.Fatalf("multi-line subject send: %v", err)
	}
	if flat.Subject != "two lines of subject" {
		t.Fatalf("subject = %q, want flattened single line", flat.Subject)
	}
}

func TestMailReplyThreading(t *testing.T) {
	ctx := context.Background()
	m, st := mailTestService(t)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	bob := mailTestUser(t, st, "bob", domain.StatusActive, false)

	root, err := m.Send(ctx, alice, "bob", "topic", "original")
	if err != nil {
		t.Fatal(err)
	}
	reply, err := m.Reply(ctx, bob, root.ID, "> quoted\nmy answer")
	if err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply.To != "alice" || reply.From != "bob" {
		t.Fatalf("reply routing = %s -> %s", reply.From, reply.To)
	}
	if reply.Subject != "Re: topic" {
		t.Fatalf("reply subject = %q", reply.Subject)
	}
	if reply.ThreadKey != root.ThreadKey {
		t.Fatalf("reply thread key = %q, want %q", reply.ThreadKey, root.ThreadKey)
	}
	// Replying reads the parent.
	if n, _ := m.UnreadCount(ctx, bob.ID); n != 0 {
		t.Fatalf("parent still unread after reply: %d", n)
	}
	// Replying to our own sent message addresses the recipient.
	selfReply, err := m.Reply(ctx, alice, root.ID, "follow up")
	if err != nil {
		t.Fatalf("reply to own sent message: %v", err)
	}
	if selfReply.To != "bob" {
		t.Fatalf("self reply routed to %q, want bob", selfReply.To)
	}
	// Outsiders cannot reply.
	carol := mailTestUser(t, st, "carol", domain.StatusActive, false)
	if _, err := m.Reply(ctx, carol, root.ID, "me too"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("outsider reply = %v, want ErrNotFound", err)
	}
}

func TestMailPerSideDelete(t *testing.T) {
	ctx := context.Background()
	m, st := mailTestService(t)
	alice := mailTestUser(t, st, "alice", domain.StatusActive, false)
	bob := mailTestUser(t, st, "bob", domain.StatusActive, false)

	msg, err := m.Send(ctx, alice, "bob", "keep or bin", "body")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, alice, msg.ID); err != nil {
		t.Fatalf("sender delete: %v", err)
	}
	if _, err := m.Message(ctx, alice, msg.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("sender read after delete = %v, want ErrNotFound", err)
	}
	// The recipient is unaffected.
	if _, err := m.Message(ctx, bob, msg.ID); err != nil {
		t.Fatalf("recipient read after sender delete: %v", err)
	}
	if in, _ := m.Inbox(ctx, bob, 10, 0); len(in) != 1 {
		t.Fatalf("recipient inbox after sender delete = %d, want 1", len(in))
	}
	if err := m.Delete(ctx, bob, msg.ID); err != nil {
		t.Fatalf("recipient delete: %v", err)
	}
	if in, _ := m.Inbox(ctx, bob, 10, 0); len(in) != 0 {
		t.Fatalf("recipient inbox after own delete = %d, want 0", len(in))
	}
}
