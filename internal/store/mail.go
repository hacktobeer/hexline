package store

import (
	"fmt"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

// mailCols is the projection used by every mail read path. Handles are joined
// so callers never need a second lookup to render a mailbox.
const mailCols = `m.id, m.from_id, uf.handle, m.to_id, ut.handle, m.subject, m.body,
	m.created_at, m.read_at, m.thread_key`

const mailFrom = `FROM mail m
	JOIN users uf ON uf.id = m.from_id
	JOIN users ut ON ut.id = m.to_id`

func scanMail(sc interface{ Scan(...any) error }) (*domain.Mail, error) {
	var m domain.Mail
	var createdAt, readAt int64
	err := sc.Scan(&m.ID, &m.FromID, &m.From, &m.ToID, &m.To, &m.Subject, &m.Body,
		&createdAt, &readAt, &m.ThreadKey)
	if err != nil {
		return nil, notFound(err)
	}
	m.CreatedAt = fromTS(createdAt)
	m.ReadAt = fromTS(readAt)
	return &m, nil
}

func (s *Store) listMail(query string, args ...any) ([]domain.Mail, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list mail: %w", err)
	}
	defer rows.Close()
	var out []domain.Mail
	for rows.Next() {
		m, err := scanMail(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// InsertMail stores a private message. When m.ID is empty a ULID is generated;
// when m.ThreadKey is empty the message starts its own thread. CreatedAt
// defaults to now.
func (s *Store) InsertMail(m *domain.Mail) error {
	if m.ID == "" {
		m.ID = newID()
	}
	if m.ThreadKey == "" {
		m.ThreadKey = m.ID
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(`INSERT INTO mail(id, from_id, to_id, subject, body, created_at,
		read_at, is_deleted_by_from, is_deleted_by_to, thread_key)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)`,
		m.ID, m.FromID, m.ToID, m.Subject, m.Body, ts(m.CreatedAt), ts(m.ReadAt), m.ThreadKey)
	if err != nil {
		return fmt.Errorf("store: insert mail: %w", err)
	}
	return nil
}

// MailInbox lists a user's received mail, newest first, hiding messages the
// recipient deleted.
func (s *Store) MailInbox(userID string, limit, offset int) ([]domain.Mail, error) {
	limit, offset = pageArgs(limit, offset)
	return s.listMail(`SELECT `+mailCols+` `+mailFrom+`
		WHERE m.to_id = ? AND m.is_deleted_by_to = 0
		ORDER BY m.created_at DESC, m.id DESC LIMIT ? OFFSET ?`,
		userID, limit, offset)
}

// MailSent lists a user's sent mail, newest first, hiding messages the sender
// deleted.
func (s *Store) MailSent(userID string, limit, offset int) ([]domain.Mail, error) {
	limit, offset = pageArgs(limit, offset)
	return s.listMail(`SELECT `+mailCols+` `+mailFrom+`
		WHERE m.from_id = ? AND m.is_deleted_by_from = 0
		ORDER BY m.created_at DESC, m.id DESC LIMIT ? OFFSET ?`,
		userID, limit, offset)
}

// MailByID loads a message regardless of ownership. Services must authorize
// the caller before returning it.
func (s *Store) MailByID(id string) (*domain.Mail, error) {
	return scanMail(s.db.QueryRow(`SELECT `+mailCols+` `+mailFrom+` WHERE m.id = ?`, id))
}

// MailByIDForUser loads a message that is still visible to userID, which must
// be the sender or the recipient. Messages the caller deleted on their side
// are treated as absent.
func (s *Store) MailByIDForUser(id, userID string) (*domain.Mail, error) {
	return scanMail(s.db.QueryRow(`SELECT `+mailCols+` `+mailFrom+`
		WHERE m.id = ? AND (
			(m.to_id = ? AND m.is_deleted_by_to = 0) OR
			(m.from_id = ? AND m.is_deleted_by_from = 0))`,
		id, userID, userID))
}

// MarkMailRead stamps read_at on a message the user received. Already-read
// messages keep their original timestamp.
func (s *Store) MarkMailRead(id, userID string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE mail SET read_at = ?
		WHERE id = ? AND to_id = ? AND read_at = 0`, ts(at), id, userID)
	if err != nil {
		return fmt.Errorf("store: mark mail read: %w", err)
	}
	return nil
}

// DeleteMailForUser soft-deletes a message on the caller's side only: the
// other party keeps their copy. A message hidden from the caller is reported
// as not found.
func (s *Store) DeleteMailForUser(id, userID string) error {
	res, err := s.db.Exec(`UPDATE mail SET
		is_deleted_by_from = CASE WHEN from_id = ? THEN 1 ELSE is_deleted_by_from END,
		is_deleted_by_to = CASE WHEN to_id = ? THEN 1 ELSE is_deleted_by_to END
		WHERE id = ? AND (from_id = ? OR to_id = ?)`,
		userID, userID, id, userID, userID)
	if err != nil {
		return fmt.Errorf("store: delete mail: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// UnreadMailCount counts messages the user received, has not read, and has not
// deleted.
func (s *Store) UnreadMailCount(userID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM mail
		WHERE to_id = ? AND read_at = 0 AND is_deleted_by_to = 0`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: unread mail: %w", err)
	}
	return n, nil
}

// MailQuotaUsed counts the messages that occupy a user's mailbox: undeleted
// inbox plus undeleted sent mail.
func (s *Store) MailQuotaUsed(userID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM mail
		WHERE (from_id = ? AND is_deleted_by_from = 0)
		   OR (to_id = ? AND is_deleted_by_to = 0)`, userID, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: mail quota: %w", err)
	}
	return n, nil
}

// BlockMail adds or removes a mail block owned by ownerID.
func (s *Store) BlockMail(ownerID, blockedID string, block bool) error {
	var err error
	if block {
		_, err = s.db.Exec(`INSERT INTO mail_blocks(owner_id, blocked_id) VALUES (?, ?)
			ON CONFLICT(owner_id, blocked_id) DO NOTHING`, ownerID, blockedID)
	} else {
		_, err = s.db.Exec(`DELETE FROM mail_blocks WHERE owner_id = ? AND blocked_id = ?`,
			ownerID, blockedID)
	}
	if err != nil {
		return fmt.Errorf("store: update mail block: %w", err)
	}
	return nil
}

// BlockedHandles lists the handles a user refuses mail from, sorted by handle.
func (s *Store) BlockedHandles(ownerID string) ([]string, error) {
	rows, err := s.db.Query(`SELECT u.handle FROM mail_blocks b
		JOIN users u ON u.id = b.blocked_id
		WHERE b.owner_id = ? ORDER BY u.handle COLLATE NOCASE`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("store: list mail blocks: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// MailBlocked reports whether ownerID refuses mail from senderID.
func (s *Store) MailBlocked(ownerID, senderID string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM mail_blocks
		WHERE owner_id = ? AND blocked_id = ?`, ownerID, senderID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: check mail block: %w", err)
	}
	return n > 0, nil
}

func pageArgs(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
