package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

func mailOpenStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
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

func mailUser(t *testing.T, st *Store, handle string) *domain.User {
	t.Helper()
	u := &domain.User{
		Handle:   handle,
		PassHash: "x",
		Status:   domain.StatusActive,
		Role:     domain.RoleUser,
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", handle, err)
	}
	return u
}

func mailInsert(t *testing.T, st *Store, from, to *domain.User, subject, body, threadKey string) *domain.Mail {
	t.Helper()
	m := &domain.Mail{
		FromID:    from.ID,
		ToID:      to.ID,
		Subject:   subject,
		Body:      body,
		ThreadKey: threadKey,
	}
	if err := st.InsertMail(m); err != nil {
		t.Fatalf("insert mail: %v", err)
	}
	return m
}

func TestMailRoundTrip(t *testing.T) {
	st := mailOpenStore(t)
	alice := mailUser(t, st, "alice")
	bob := mailUser(t, st, "bob")

	sent := mailInsert(t, st, alice, bob, "hello", "first line\nsecond line", "")
	if sent.ID == "" {
		t.Fatal("insert did not assign an id")
	}
	if sent.ThreadKey != sent.ID {
		t.Fatalf("new mail thread_key = %q, want own id %q", sent.ThreadKey, sent.ID)
	}

	got, err := st.MailByID(sent.ID)
	if err != nil {
		t.Fatalf("mail by id: %v", err)
	}
	if got.From != "alice" || got.To != "bob" {
		t.Fatalf("handles = %q -> %q, want alice -> bob", got.From, got.To)
	}
	if got.Subject != "hello" || got.Body != "first line\nsecond line" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if !got.ReadAt.IsZero() {
		t.Fatalf("fresh mail should be unread, read_at=%v", got.ReadAt)
	}

	inbox, err := st.MailInbox(bob.ID, 10, 0)
	if err != nil || len(inbox) != 1 || inbox[0].ID != sent.ID {
		t.Fatalf("inbox = %+v, %v", inbox, err)
	}
	outbox, err := st.MailSent(alice.ID, 10, 0)
	if err != nil || len(outbox) != 1 || outbox[0].ID != sent.ID {
		t.Fatalf("sent = %+v, %v", outbox, err)
	}

	if err := st.MarkMailRead(sent.ID, bob.ID, time.Now().UTC()); err != nil {
		t.Fatalf("mark read: %v", err)
	}
	got, err = st.MailByID(sent.ID)
	if err != nil || got.ReadAt.IsZero() {
		t.Fatalf("read_at not stamped: %+v, %v", got, err)
	}
	// Only the recipient may mark read; the sender's stamp is a no-op.
	if err := st.MarkMailRead(sent.ID, alice.ID, time.Now().UTC()); err != nil {
		t.Fatalf("mark read as sender: %v", err)
	}
}

func TestMailPerSideDelete(t *testing.T) {
	st := mailOpenStore(t)
	alice := mailUser(t, st, "alice")
	bob := mailUser(t, st, "bob")
	m := mailInsert(t, st, alice, bob, "subject", "body", "")

	if err := st.DeleteMailForUser(m.ID, alice.ID); err != nil {
		t.Fatalf("sender delete: %v", err)
	}
	// Sender's copy is gone...
	if out, err := st.MailSent(alice.ID, 10, 0); err != nil || len(out) != 0 {
		t.Fatalf("sender sent list = %+v, %v; want hidden", out, err)
	}
	if _, err := st.MailByIDForUser(m.ID, alice.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("sender lookup after delete = %v, want ErrNotFound", err)
	}
	// ...but the recipient still has it.
	if in, err := st.MailInbox(bob.ID, 10, 0); err != nil || len(in) != 1 {
		t.Fatalf("recipient inbox = %+v, %v; want 1 message", in, err)
	}
	if _, err := st.MailByIDForUser(m.ID, bob.ID); err != nil {
		t.Fatalf("recipient lookup after sender delete: %v", err)
	}

	// Recipient deletes their copy: now neither side sees the message, but the
	// row survives for quota and for the other side's history.
	if err := st.DeleteMailForUser(m.ID, bob.ID); err != nil {
		t.Fatalf("recipient delete: %v", err)
	}
	if in, err := st.MailInbox(bob.ID, 10, 0); err != nil || len(in) != 0 {
		t.Fatalf("recipient inbox after delete = %+v, %v", in, err)
	}
	if _, err := st.MailByID(m.ID); err != nil {
		t.Fatalf("row should survive soft delete: %v", err)
	}
	if err := st.DeleteMailForUser(m.ID, mailUser(t, st, "carol").ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete by outsider = %v, want ErrNotFound", err)
	}
}

func TestMailUnreadCount(t *testing.T) {
	st := mailOpenStore(t)
	alice := mailUser(t, st, "alice")
	bob := mailUser(t, st, "bob")

	first := mailInsert(t, st, alice, bob, "one", "body", "")
	second := mailInsert(t, st, alice, bob, "two", "body", "")

	if n, err := st.UnreadMailCount(bob.ID); err != nil || n != 2 {
		t.Fatalf("unread = %d, %v; want 2", n, err)
	}
	if n, err := st.UnreadMailCount(alice.ID); err != nil || n != 0 {
		t.Fatalf("sender unread = %d, %v; want 0", n, err)
	}
	if err := st.MarkMailRead(first.ID, bob.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.UnreadMailCount(bob.ID); n != 1 {
		t.Fatalf("unread after read = %d, want 1", n)
	}
	// Deleting an unread message removes it from the badge.
	if err := st.DeleteMailForUser(second.ID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.UnreadMailCount(bob.ID); n != 0 {
		t.Fatalf("unread after delete = %d, want 0", n)
	}
}

func TestMailQuotaCounting(t *testing.T) {
	st := mailOpenStore(t)
	alice := mailUser(t, st, "alice")
	bob := mailUser(t, st, "bob")
	carol := mailUser(t, st, "carol")

	// alice: 2 sent + 1 received = 3 mailbox rows.
	toBob := mailInsert(t, st, alice, bob, "one", "body", "")
	mailInsert(t, st, alice, carol, "two", "body", "")
	mailInsert(t, st, carol, alice, "three", "body", "")

	if used, err := st.MailQuotaUsed(alice.ID); err != nil || used != 3 {
		t.Fatalf("alice quota used = %d, %v; want 3", used, err)
	}
	if used, err := st.MailQuotaUsed(bob.ID); err != nil || used != 1 {
		t.Fatalf("bob quota used = %d, %v; want 1", used, err)
	}

	// Deleting one side of a message frees a slot for that side only.
	if err := st.DeleteMailForUser(toBob.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	if used, _ := st.MailQuotaUsed(alice.ID); used != 2 {
		t.Fatalf("alice quota after delete = %d, want 2", used)
	}
	if used, _ := st.MailQuotaUsed(bob.ID); used != 1 {
		t.Fatalf("bob quota after alice delete = %d, want 1", used)
	}
}

func TestMailThreadKeyInheritance(t *testing.T) {
	st := mailOpenStore(t)
	alice := mailUser(t, st, "alice")
	bob := mailUser(t, st, "bob")

	root := mailInsert(t, st, alice, bob, "topic", "body", "")
	reply := mailInsert(t, st, bob, alice, "Re: topic", "body", root.ThreadKey)

	got, err := st.MailByID(reply.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ThreadKey != root.ThreadKey {
		t.Fatalf("reply thread_key = %q, want parent %q", got.ThreadKey, root.ThreadKey)
	}
	if err := st.InsertMail(&domain.Mail{FromID: alice.ID, ToID: bob.ID, Subject: "x", Body: "y"}); err != nil {
		t.Fatal(err)
	}
	second, err := st.MailByIDForUser(reply.ID, bob.ID)
	if err != nil || second.ThreadKey != root.ThreadKey {
		t.Fatalf("reply visible to sender: %+v, %v", second, err)
	}
}

func TestMailBlocks(t *testing.T) {
	st := mailOpenStore(t)
	alice := mailUser(t, st, "alice")
	bob := mailUser(t, st, "bob")

	if blocked, err := st.MailBlocked(alice.ID, bob.ID); err != nil || blocked {
		t.Fatalf("initial block = %v, %v", blocked, err)
	}
	if err := st.BlockMail(alice.ID, bob.ID, true); err != nil {
		t.Fatal(err)
	}
	// Idempotent re-block.
	if err := st.BlockMail(alice.ID, bob.ID, true); err != nil {
		t.Fatalf("re-block: %v", err)
	}
	if blocked, _ := st.MailBlocked(alice.ID, bob.ID); !blocked {
		t.Fatal("expected bob to be blocked")
	}
	if blocked, _ := st.MailBlocked(bob.ID, alice.ID); blocked {
		t.Fatal("block must be one-directional")
	}
	handles, err := st.BlockedHandles(alice.ID)
	if err != nil || len(handles) != 1 || handles[0] != "bob" {
		t.Fatalf("blocked handles = %v, %v", handles, err)
	}
	if err := st.BlockMail(alice.ID, bob.ID, false); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := st.MailBlocked(alice.ID, bob.ID); blocked {
		t.Fatal("unblock did not clear the row")
	}
	if handles, _ := st.BlockedHandles(alice.ID); len(handles) != 0 {
		t.Fatalf("blocked handles after unblock = %v", handles)
	}
}
