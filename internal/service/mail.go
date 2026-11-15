package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/render"
	"github.com/hacktobeer/hexline/internal/store"
)

// Mail implements private mail between handles: inbox/sent, read flags,
// threading, quotas and a simple blocklist. Mail is private: no audit rows are
// written and message bodies are never logged.
type Mail struct {
	st  *store.Store
	cfg *config.Config
}

// NewMail wires the mail service.
func NewMail(st *store.Store, cfg *config.Config) *Mail {
	return &Mail{st: st, cfg: cfg}
}

// UnreadCount counts unread mail for a user (the main menu badge).
func (m *Mail) UnreadCount(ctx context.Context, userID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	return m.st.UnreadMailCount(userID)
}

// Inbox lists received mail, newest first.
func (m *Mail) Inbox(ctx context.Context, u *domain.User, limit, offset int) ([]domain.Mail, error) {
	if err := mailParticipant(u); err != nil {
		return nil, err
	}
	return m.st.MailInbox(u.ID, limit, offset)
}

// Sent lists mail the user sent, newest first.
func (m *Mail) Sent(ctx context.Context, u *domain.User, limit, offset int) ([]domain.Mail, error) {
	if err := mailParticipant(u); err != nil {
		return nil, err
	}
	return m.st.MailSent(u.ID, limit, offset)
}

// Message returns one message, marking it read for the recipient. Only the
// sender and recipient may read it; everyone else sees ErrNotFound so message
// IDs stay unguessable.
func (m *Mail) Message(ctx context.Context, u *domain.User, id string) (*domain.Mail, error) {
	if err := mailParticipant(u); err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("%w: message id is required", domain.ErrInvalid)
	}
	msg, err := m.st.MailByIDForUser(id, u.ID)
	if err != nil {
		return nil, err
	}
	if msg.ToID == u.ID && msg.ReadAt.IsZero() {
		now := time.Now().UTC()
		if err := m.st.MarkMailRead(msg.ID, u.ID, now); err != nil {
			return nil, err
		}
		msg.ReadAt = now
	}
	return msg, nil
}

// SenderSignature returns the signature of the message's sender so the reader
// can show it. The caller must be able to read the message.
func (m *Mail) SenderSignature(ctx context.Context, u *domain.User, msg *domain.Mail) (string, error) {
	if err := mailParticipant(u); err != nil {
		return "", err
	}
	if msg == nil {
		return "", domain.ErrNotFound
	}
	if u.ID != msg.FromID && u.ID != msg.ToID {
		return "", domain.ErrNotFound
	}
	sender, err := m.st.UserByID(msg.FromID)
	if err != nil {
		return "", err
	}
	return sender.Signature, nil
}

// Send composes a new message to toHandle. Subject and body are sanitized and
// validated, the recipient's blocklist is honoured, and the mailbox quota is
// enforced before anything is stored.
func (m *Mail) Send(ctx context.Context, from *domain.User, toHandle, subject, body string) (*domain.Mail, error) {
	if err := mailSender(from); err != nil {
		return nil, err
	}
	to, err := m.recipient(from, toHandle)
	if err != nil {
		return nil, err
	}
	return m.send(from, to, subject, body, "")
}

// Reply sends a message in the parent's thread, addressed to the other party.
// The parent is marked read (the caller just read it) and the reply inherits
// the parent's thread key.
func (m *Mail) Reply(ctx context.Context, u *domain.User, mailID, body string) (*domain.Mail, error) {
	if err := mailSender(u); err != nil {
		return nil, err
	}
	parent, err := m.Message(ctx, u, mailID)
	if err != nil {
		return nil, err
	}
	handle := parent.From
	if parent.FromID == u.ID {
		handle = parent.To
	}
	to, err := m.recipient(u, handle)
	if err != nil {
		return nil, err
	}
	threadKey := parent.ThreadKey
	if threadKey == "" {
		threadKey = parent.ID
	}
	return m.send(u, to, domain.SubjectReply(parent.Subject), body, threadKey)
}

// Delete removes a message from the caller's mailbox only; the other party's
// copy is untouched.
func (m *Mail) Delete(ctx context.Context, u *domain.User, id string) error {
	if err := mailParticipant(u); err != nil {
		return err
	}
	if _, err := m.st.MailByIDForUser(id, u.ID); err != nil {
		return err
	}
	return m.st.DeleteMailForUser(id, u.ID)
}

// Block adds or removes handle from the caller's mail blocklist.
func (m *Mail) Block(ctx context.Context, u *domain.User, handle string, block bool) error {
	if err := mailParticipant(u); err != nil {
		return err
	}
	h := strings.TrimSpace(handle)
	if h == "" {
		return fmt.Errorf("%w: handle is required", domain.ErrInvalid)
	}
	target, err := m.st.UserByHandle(h)
	if err != nil {
		return fmt.Errorf("%w: no caller named %q", domain.ErrNotFound, h)
	}
	if target.ID == u.ID {
		return fmt.Errorf("%w: you cannot block yourself", domain.ErrInvalid)
	}
	return m.st.BlockMail(u.ID, target.ID, block)
}

// Blocked lists the handles the caller refuses mail from.
func (m *Mail) Blocked(ctx context.Context, u *domain.User) ([]string, error) {
	if err := mailParticipant(u); err != nil {
		return nil, err
	}
	return m.st.BlockedHandles(u.ID)
}

// Quota reports mailbox usage against cfg.Limits.MailQuota. A max of 0 means
// unlimited.
func (m *Mail) Quota(ctx context.Context, u *domain.User) (used, max int, err error) {
	if err := mailParticipant(u); err != nil {
		return 0, 0, err
	}
	used, err = m.st.MailQuotaUsed(u.ID)
	if err != nil {
		return 0, 0, err
	}
	return used, m.cfg.Limits.MailQuota, nil
}

// send validates and stores one message. An empty threadKey starts a new
// thread; InsertMail replaces it with the new message ID.
func (m *Mail) send(from, to *domain.User, subject, body, threadKey string) (*domain.Mail, error) {
	subject = render.SanitizeLine(subject)
	body = render.Sanitize(body)
	if err := domain.ValidateSubject(subject); err != nil {
		return nil, err
	}
	if err := domain.ValidateBody(body, m.cfg.Limits.PostMaxBytes, m.cfg.Limits.MaxBodyLines); err != nil {
		return nil, err
	}
	used, err := m.st.MailQuotaUsed(from.ID)
	if err != nil {
		return nil, err
	}
	if q := m.cfg.Limits.MailQuota; q > 0 && used >= q {
		return nil, fmt.Errorf("%w: mailbox holds %d messages, limit is %d", domain.ErrQuota, used, q)
	}
	msg := &domain.Mail{
		FromID:    from.ID,
		From:      from.Handle,
		ToID:      to.ID,
		To:        to.Handle,
		Subject:   subject,
		Body:      body,
		ThreadKey: threadKey,
		CreatedAt: time.Now().UTC(),
	}
	if err := m.st.InsertMail(msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// recipient resolves a handle and applies the delivery rules: the account must
// exist, must be able to log in, and must not have blocked the sender.
func (m *Mail) recipient(from *domain.User, handle string) (*domain.User, error) {
	h := strings.TrimSpace(handle)
	if h == "" {
		return nil, fmt.Errorf("%w: recipient handle is required", domain.ErrInvalid)
	}
	to, err := m.st.UserByHandle(h)
	if err != nil {
		return nil, fmt.Errorf("%w: no caller named %q", domain.ErrNotFound, h)
	}
	if !to.CanLogin() {
		return nil, fmt.Errorf("%w: %s is not accepting mail", domain.ErrPermission, to.Handle)
	}
	if to.ID != from.ID {
		blocked, err := m.st.MailBlocked(to.ID, from.ID)
		if err != nil {
			return nil, err
		}
		if blocked {
			return nil, fmt.Errorf("%w: recipient does not accept mail from you", domain.ErrPermission)
		}
	}
	return to, nil
}

// mailParticipant checks that u may use the mailbox at all.
func mailParticipant(u *domain.User) error {
	if u == nil {
		return fmt.Errorf("%w: sign in to use mail", domain.ErrPermission)
	}
	if !u.CanLogin() {
		return fmt.Errorf("%w: this account cannot use mail", domain.ErrPermission)
	}
	return nil
}

// mailSender checks that u may send mail. Guests are read-only.
func mailSender(u *domain.User) error {
	if err := mailParticipant(u); err != nil {
		return err
	}
	if u.IsGuest {
		return fmt.Errorf("%w: guests cannot send mail", domain.ErrPermission)
	}
	return nil
}
