package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

// --- one-liners ---

// CreateOneliner inserts a one-liner, assigning its ID and creation time when
// empty. Callers sanitize and rate-limit before calling; the store keeps the
// bytes it is given.
func (s *Store) CreateOneliner(o *domain.Oneliner) error {
	if o == nil {
		return fmt.Errorf("store: nil oneliner")
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now().UTC()
	}
	res, err := s.db.Exec(`INSERT INTO oneliners(author_id, body, created_at, is_hidden, hidden_by)
		VALUES (?, ?, ?, ?, NULL)`,
		o.AuthorID, o.Body, ts(o.CreatedAt), boolInt(o.Hidden))
	if err != nil {
		return fmt.Errorf("store: create oneliner: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("store: create oneliner id: %w", err)
	}
	o.ID = id
	return nil
}

// ListOneliners returns the newest one-liners first, including hidden ones.
// Display policy (whether hidden entries are shown) belongs to the caller.
func (s *Store) ListOneliners(limit int) ([]domain.Oneliner, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT o.id, o.author_id, COALESCE(u.handle, ''), o.body,
		o.created_at, o.is_hidden
		FROM oneliners o
		LEFT JOIN users u ON u.id = o.author_id
		ORDER BY o.created_at DESC, o.id DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list oneliners: %w", err)
	}
	defer rows.Close()

	var out []domain.Oneliner
	for rows.Next() {
		var o domain.Oneliner
		var createdAt int64
		var hidden int
		if err := rows.Scan(&o.ID, &o.AuthorID, &o.Author, &o.Body, &createdAt, &hidden); err != nil {
			return nil, fmt.Errorf("store: scan oneliner: %w", err)
		}
		o.CreatedAt = fromTS(createdAt)
		o.Hidden = hidden == 1
		out = append(out, o)
	}
	return out, rows.Err()
}

// SetOnelinerHidden hides or restores a one-liner. by is recorded as the
// moderator who hid it and ignored when hiding is undone.
func (s *Store) SetOnelinerHidden(id int64, hide bool, by string) error {
	var (
		res sql.Result
		err error
	)
	if hide {
		res, err = s.db.Exec(`UPDATE oneliners SET is_hidden = 1, hidden_by = ? WHERE id = ?`,
			nullString(by), id)
	} else {
		res, err = s.db.Exec(`UPDATE oneliners SET is_hidden = 0, hidden_by = NULL WHERE id = ?`, id)
	}
	if err != nil {
		return fmt.Errorf("store: hide oneliner: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: hide oneliner: %w", err)
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// --- polls ---

// CreatePoll inserts a poll and its options in one transaction. labels are
// stored in order; the resulting option IDs are filled into p.Options.
func (s *Store) CreatePoll(p *domain.Poll, labels []string) error {
	if p == nil {
		return fmt.Errorf("store: nil poll")
	}
	if p.ID == "" {
		p.ID = newID()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin poll: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`INSERT INTO polls(id, question, created_by, created_at, closes_at, is_hidden)
		VALUES (?, ?, ?, ?, ?, ?)`,
		p.ID, p.Question, p.CreatedBy, ts(p.CreatedAt), ts(p.ClosesAt), boolInt(p.Hidden)); err != nil {
		return fmt.Errorf("store: create poll: %w", err)
	}

	opts := make([]domain.PollOption, 0, len(labels))
	for i, label := range labels {
		res, err := tx.Exec(`INSERT INTO poll_options(poll_id, label, sort) VALUES (?, ?, ?)`,
			p.ID, label, i)
		if err != nil {
			return fmt.Errorf("store: create poll option: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("store: create poll option id: %w", err)
		}
		opts = append(opts, domain.PollOption{ID: id, PollID: p.ID, Label: label, Sort: i})
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit poll: %w", err)
	}
	p.Options = opts
	return nil
}

// ListPolls returns every poll newest first, with option counts and the
// given user's vote (0 when userID is empty or the user has not voted).
func (s *Store) ListPolls(userID string) ([]domain.Poll, error) {
	rows, err := s.db.Query(`SELECT id, question, created_by, created_at, closes_at, is_hidden
		FROM polls ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list polls: %w", err)
	}
	var out []domain.Poll
	for rows.Next() {
		var p domain.Poll
		var created, closes int64
		var hidden int
		if err := rows.Scan(&p.ID, &p.Question, &p.CreatedBy, &created, &closes, &hidden); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scan poll: %w", err)
		}
		p.CreatedAt = fromTS(created)
		p.ClosesAt = fromTS(closes)
		p.Hidden = hidden == 1
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	for i := range out {
		if err := s.hydratePoll(&out[i], userID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// PollByID loads a poll with option counts and userID's vote.
func (s *Store) PollByID(id, userID string) (*domain.Poll, error) {
	var p domain.Poll
	var created, closes int64
	var hidden int
	err := s.db.QueryRow(`SELECT id, question, created_by, created_at, closes_at, is_hidden
		FROM polls WHERE id = ?`, id).
		Scan(&p.ID, &p.Question, &p.CreatedBy, &created, &closes, &hidden)
	if err != nil {
		return nil, notFound(err)
	}
	p.CreatedAt = fromTS(created)
	p.ClosesAt = fromTS(closes)
	p.Hidden = hidden == 1
	if err := s.hydratePoll(&p, userID); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) hydratePoll(p *domain.Poll, userID string) error {
	rows, err := s.db.Query(`SELECT o.id, o.poll_id, o.label, o.sort,
		(SELECT COUNT(*) FROM poll_votes v WHERE v.option_id = o.id)
		FROM poll_options o WHERE o.poll_id = ?
		ORDER BY o.sort, o.id`, p.ID)
	if err != nil {
		return fmt.Errorf("store: poll options: %w", err)
	}
	var opts []domain.PollOption
	total := 0
	for rows.Next() {
		var o domain.PollOption
		if err := rows.Scan(&o.ID, &o.PollID, &o.Label, &o.Sort, &o.Votes); err != nil {
			rows.Close()
			return fmt.Errorf("store: scan poll option: %w", err)
		}
		total += o.Votes
		opts = append(opts, o)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	p.Options = opts
	p.TotalVotes = total
	p.MyVote = 0
	if userID != "" {
		err := s.db.QueryRow(`SELECT option_id FROM poll_votes WHERE poll_id = ? AND user_id = ?`,
			p.ID, userID).Scan(&p.MyVote)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: my vote: %w", err)
		}
	}
	return nil
}

// Vote records one vote. The option must belong to the poll and each user may
// vote once per poll (enforced by the primary key, surfaced as ErrConflict).
func (s *Store) Vote(pollID string, optionID int64, userID string, at time.Time) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM poll_options WHERE id = ? AND poll_id = ?`,
		optionID, pollID).Scan(&n); err != nil {
		return fmt.Errorf("store: check poll option: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: option %d does not belong to this poll", domain.ErrInvalid, optionID)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if _, err := s.db.Exec(`INSERT INTO poll_votes(poll_id, option_id, user_id, at)
		VALUES (?, ?, ?, ?)`, pollID, optionID, userID, ts(at)); err != nil {
		if isUniqueErr(err) {
			return fmt.Errorf("%w: you have already voted in this poll", domain.ErrConflict)
		}
		return fmt.Errorf("store: vote: %w", err)
	}
	return nil
}

// --- bulletins ---

// ListBulletins returns bulletins ordered by sort then ID. activeOnly hides
// inactive entries.
func (s *Store) ListBulletins(activeOnly bool) ([]domain.Bulletin, error) {
	query := `SELECT id, title, body, sort, is_active, created_at, updated_at FROM bulletins`
	if activeOnly {
		query += ` WHERE is_active = 1`
	}
	query += ` ORDER BY sort, id`
	return s.queryBulletins(query)
}

// ActiveBulletinsFor returns active bulletins the user has not dismissed.
func (s *Store) ActiveBulletinsFor(userID string) ([]domain.Bulletin, error) {
	if userID == "" {
		return s.ListBulletins(true)
	}
	return s.queryBulletins(`SELECT b.id, b.title, b.body, b.sort, b.is_active, b.created_at, b.updated_at
		FROM bulletins b
		WHERE b.is_active = 1 AND NOT EXISTS (
			SELECT 1 FROM bulletin_dismissals d
			WHERE d.bulletin_id = b.id AND d.user_id = ?
		)
		ORDER BY b.sort, b.id`, userID)
}

func (s *Store) queryBulletins(query string, args ...any) ([]domain.Bulletin, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list bulletins: %w", err)
	}
	defer rows.Close()
	var out []domain.Bulletin
	for rows.Next() {
		var b domain.Bulletin
		var active int
		var created, updated int64
		if err := rows.Scan(&b.ID, &b.Title, &b.Body, &b.Sort, &active, &created, &updated); err != nil {
			return nil, fmt.Errorf("store: scan bulletin: %w", err)
		}
		b.Active = active == 1
		b.CreatedAt = fromTS(created)
		b.UpdatedAt = fromTS(updated)
		out = append(out, b)
	}
	return out, rows.Err()
}

// CreateBulletin inserts a bulletin, assigning an ID and timestamps.
func (s *Store) CreateBulletin(b *domain.Bulletin) error {
	if b == nil {
		return fmt.Errorf("store: nil bulletin")
	}
	if b.ID == "" {
		b.ID = newID()
	}
	now := time.Now().UTC()
	if b.CreatedAt.IsZero() {
		b.CreatedAt = now
	}
	if b.UpdatedAt.IsZero() {
		b.UpdatedAt = b.CreatedAt
	}
	_, err := s.db.Exec(`INSERT INTO bulletins(id, title, body, sort, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.Title, b.Body, b.Sort, boolInt(b.Active), ts(b.CreatedAt), ts(b.UpdatedAt))
	if err != nil {
		return fmt.Errorf("store: create bulletin: %w", err)
	}
	return nil
}

// UpdateBulletin replaces the editable fields of a bulletin.
func (s *Store) UpdateBulletin(id, title, body string, active bool, at time.Time) error {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	res, err := s.db.Exec(`UPDATE bulletins SET title = ?, body = ?, is_active = ?, updated_at = ?
		WHERE id = ?`, title, body, boolInt(active), ts(at), id)
	if err != nil {
		return fmt.Errorf("store: update bulletin: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update bulletin: %w", err)
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// DeleteBulletin removes a bulletin; dismissals cascade.
func (s *Store) DeleteBulletin(id string) error {
	res, err := s.db.Exec(`DELETE FROM bulletins WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete bulletin: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete bulletin: %w", err)
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// DismissBulletin records a per-user dismissal. It is idempotent.
func (s *Store) DismissBulletin(userID, bulletinID string) error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM bulletins WHERE id = ?`, bulletinID).Scan(&n); err != nil {
		return fmt.Errorf("store: check bulletin: %w", err)
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	if _, err := s.db.Exec(`INSERT INTO bulletin_dismissals(user_id, bulletin_id)
		VALUES (?, ?) ON CONFLICT DO NOTHING`, userID, bulletinID); err != nil {
		return fmt.Errorf("store: dismiss bulletin: %w", err)
	}
	return nil
}
