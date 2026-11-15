package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/hacktobeer/hexline/internal/domain"
)

// This file owns message areas, threads, posts, per-user read tracking and
// full-text search. Human-facing formatting lives in the service layer.

const boardAreaCols = `id, tag, name, description, sort_order, acl_read, acl_post,
	acl_moderate, retention_days, rate_limit_per_hour, is_public, created_at`

const boardThreadCols = `t.id, t.area_id, t.subject, t.author_id, t.created_at,
	t.last_post_at, t.post_count, t.is_sticky, t.is_locked, t.is_deleted,
	a.tag, u.handle,
	COALESCE((SELECT COUNT(*) FROM posts p
		WHERE p.thread_id = t.id AND p.is_deleted = 0
		  AND p.id > COALESCE(tr.last_read_post_id, 0)), 0)`

const boardThreadFrom = ` FROM threads t
	JOIN areas a ON a.id = t.area_id
	JOIN users u ON u.id = t.author_id
	LEFT JOIN thread_reads tr ON tr.thread_id = t.id AND tr.user_id = ?`

const boardPostCols = `p.id, p.thread_id, p.author_id, u.handle, p.body, p.created_at,
	p.edited_at, p.is_deleted, COALESCE(p.deleted_by, ''), COALESCE(p.delete_reason, ''),
	p.reply_to_post_id`

const boardPostFrom = ` FROM posts p JOIN users u ON u.id = p.author_id`

func scanBoardArea(sc interface{ Scan(...any) error }) (*domain.Area, error) {
	var a domain.Area
	var read, post, moderate string
	var public int
	var createdAt int64
	if err := sc.Scan(&a.ID, &a.Tag, &a.Name, &a.Description, &a.SortOrder,
		&read, &post, &moderate, &a.RetentionDays, &a.RateLimitPerHour, &public,
		&createdAt); err != nil {
		return nil, notFound(err)
	}
	var err error
	if a.ACL.Read, err = domain.ParseACL(read); err != nil {
		return nil, fmt.Errorf("store: area %s read acl: %w", a.ID, err)
	}
	if a.ACL.Post, err = domain.ParseACL(post); err != nil {
		return nil, fmt.Errorf("store: area %s post acl: %w", a.ID, err)
	}
	if a.ACL.Moderate, err = domain.ParseACL(moderate); err != nil {
		return nil, fmt.Errorf("store: area %s moderate acl: %w", a.ID, err)
	}
	a.IsPublic = public == 1
	a.CreatedAt = fromTS(createdAt)
	return &a, nil
}

func scanBoardThread(sc interface{ Scan(...any) error }, userID string) (*domain.Thread, error) {
	var t domain.Thread
	var createdAt, lastPostAt int64
	var sticky, locked, deleted int
	if err := sc.Scan(&t.ID, &t.AreaID, &t.Subject, &t.AuthorID, &createdAt,
		&lastPostAt, &t.PostCount, &sticky, &locked, &deleted, &t.AreaTag,
		&t.Author, &t.Unread); err != nil {
		return nil, notFound(err)
	}
	t.CreatedAt = fromTS(createdAt)
	t.LastPostAt = fromTS(lastPostAt)
	t.Sticky = sticky == 1
	t.Locked = locked == 1
	t.Deleted = deleted == 1
	if userID == "" {
		// Guests have no read state; showing "everything unread" is noise.
		t.Unread = 0
	}
	return &t, nil
}

func scanBoardPost(sc interface{ Scan(...any) error }) (*domain.Post, error) {
	var p domain.Post
	var createdAt, editedAt int64
	var deleted int
	var replyTo sql.NullInt64
	if err := sc.Scan(&p.ID, &p.ThreadID, &p.AuthorID, &p.Author, &p.Body,
		&createdAt, &editedAt, &deleted, &p.DeletedBy, &p.DeleteWhy,
		&replyTo); err != nil {
		return nil, notFound(err)
	}
	p.CreatedAt = fromTS(createdAt)
	p.EditedAt = fromTS(editedAt)
	p.Deleted = deleted == 1
	if replyTo.Valid {
		v := replyTo.Int64
		p.ReplyTo = &v
	}
	return &p, nil
}

// boardFTSQuery turns free text into a safe FTS5 expression. Every token is
// quoted, so operators and bare punctuation can never change the query shape.
func boardFTSQuery(query string) string {
	fields := strings.Fields(query)
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		hasText := false
		for _, r := range f {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				hasText = true
				break
			}
		}
		if !hasText {
			continue
		}
		f = strings.ReplaceAll(f, `"`, `""`)
		parts = append(parts, `"`+f+`"`)
		if len(parts) >= 16 {
			break
		}
	}
	return strings.Join(parts, " AND ")
}

// BoardListAreas returns every area ordered for display.
func (s *Store) BoardListAreas() ([]domain.Area, error) {
	rows, err := s.db.Query(`SELECT ` + boardAreaCols + ` FROM areas ORDER BY sort_order, tag`)
	if err != nil {
		return nil, fmt.Errorf("store: list areas: %w", err)
	}
	defer rows.Close()
	var out []domain.Area
	for rows.Next() {
		a, err := scanBoardArea(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// BoardAreaByID looks an area up by its ULID.
func (s *Store) BoardAreaByID(id string) (*domain.Area, error) {
	return scanBoardArea(s.db.QueryRow(`SELECT `+boardAreaCols+` FROM areas WHERE id = ?`, id))
}

// BoardAreaByTag looks an area up case-insensitively.
func (s *Store) BoardAreaByTag(tag string) (*domain.Area, error) {
	return scanBoardArea(s.db.QueryRow(`SELECT `+boardAreaCols+` FROM areas WHERE tag = ? COLLATE NOCASE`, tag))
}

// ListThreads returns a page of live threads with per-user unread counts.
// The unread count is non-deleted posts with id > last_read_post_id.
func (s *Store) ListThreads(areaID, userID string, limit, offset int) ([]domain.Thread, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT `+boardThreadCols+boardThreadFrom+`
		WHERE t.area_id = ? AND t.is_deleted = 0
		ORDER BY t.is_sticky DESC, t.last_post_at DESC, t.id DESC
		LIMIT ? OFFSET ?`, userID, areaID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("store: list threads: %w", err)
	}
	defer rows.Close()
	var out []domain.Thread
	for rows.Next() {
		t, err := scanBoardThread(rows, userID)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// ThreadByID loads one thread (including soft-deleted threads; callers decide
// whether to hide it) with the user's unread count.
func (s *Store) ThreadByID(threadID, userID string) (*domain.Thread, error) {
	return scanBoardThread(s.db.QueryRow(`SELECT `+boardThreadCols+boardThreadFrom+
		` WHERE t.id = ?`, userID, threadID), userID)
}

// CreateThread inserts a thread and its first post atomically.
func (s *Store) CreateThread(areaID, authorID, subject, body string, now time.Time) (*domain.Thread, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	id := newID()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: create thread: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`INSERT INTO threads(id, area_id, subject, author_id,
		created_at, last_post_at, post_count) VALUES (?, ?, ?, ?, ?, ?, 1)`,
		id, areaID, subject, authorID, ts(now), ts(now)); err != nil {
		return nil, fmt.Errorf("store: create thread: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO posts(thread_id, author_id, body, created_at)
		VALUES (?, ?, ?, ?)`, id, authorID, body, ts(now)); err != nil {
		return nil, fmt.Errorf("store: create first post: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit thread: %w", err)
	}
	return s.ThreadByID(id, "")
}

// CreatePost appends a reply and updates the thread counters in one tx.
func (s *Store) CreatePost(threadID, authorID, body string, now time.Time) (*domain.Post, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: create post: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`INSERT INTO posts(thread_id, author_id, body, created_at)
		VALUES (?, ?, ?, ?)`, threadID, authorID, body, ts(now))
	if err != nil {
		return nil, fmt.Errorf("store: create post: %w", err)
	}
	postID, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: post id: %w", err)
	}
	if _, err := tx.Exec(`UPDATE threads SET post_count = post_count + 1,
		last_post_at = ? WHERE id = ?`, ts(now), threadID); err != nil {
		return nil, fmt.Errorf("store: update thread counters: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit post: %w", err)
	}
	return s.PostByID(postID)
}

// PostByID loads a single post with its author handle.
func (s *Store) PostByID(postID int64) (*domain.Post, error) {
	return scanBoardPost(s.db.QueryRow(`SELECT `+boardPostCols+boardPostFrom+` WHERE p.id = ?`, postID))
}

// PostsByThread returns posts oldest first. Soft-deleted posts are included
// only when includeDeleted is true (moderator views).
func (s *Store) PostsByThread(threadID string, includeDeleted bool) ([]domain.Post, error) {
	query := `SELECT ` + boardPostCols + boardPostFrom + ` WHERE p.thread_id = ?`
	if !includeDeleted {
		query += ` AND p.is_deleted = 0`
	}
	query += ` ORDER BY p.id`
	rows, err := s.db.Query(query, threadID)
	if err != nil {
		return nil, fmt.Errorf("store: list posts: %w", err)
	}
	defer rows.Close()
	var out []domain.Post
	for rows.Next() {
		p, err := scanBoardPost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UpdatePost replaces a live post body and records the edit time.
func (s *Store) UpdatePost(postID int64, body string, editedAt time.Time) error {
	res, err := s.db.Exec(`UPDATE posts SET body = ?, edited_at = ?
		WHERE id = ? AND is_deleted = 0`, body, ts(editedAt), postID)
	if err != nil {
		return fmt.Errorf("store: update post: %w", err)
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

// SoftDeletePost hides a post and decrements its thread's reply counter.
func (s *Store) SoftDeletePost(postID int64, deletedBy, reason string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: delete post: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`UPDATE posts SET is_deleted = 1, deleted_by = ?,
		delete_reason = ? WHERE id = ? AND is_deleted = 0`, deletedBy, reason, postID)
	if err != nil {
		return fmt.Errorf("store: delete post: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: post is already deleted", domain.ErrConflict)
	}
	if _, err := tx.Exec(`UPDATE threads SET post_count =
		CASE WHEN post_count > 0 THEN post_count - 1 ELSE 0 END
		WHERE id = (SELECT thread_id FROM posts WHERE id = ?)`, postID); err != nil {
		return fmt.Errorf("store: update thread counter: %w", err)
	}
	return tx.Commit()
}

// SetThreadFlags updates the sticky and locked flags.
func (s *Store) SetThreadFlags(threadID string, sticky, locked bool) error {
	res, err := s.db.Exec(`UPDATE threads SET is_sticky = ?, is_locked = ? WHERE id = ?`,
		boolInt(sticky), boolInt(locked), threadID)
	if err != nil {
		return fmt.Errorf("store: set thread flags: %w", err)
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

// MoveThread rehomes a thread, preserving its posts and remembering the
// previous area for moderation history.
func (s *Store) MoveThread(threadID, toAreaID string) error {
	res, err := s.db.Exec(`UPDATE threads SET area_id = ?,
		moved_from_area_id = CASE WHEN area_id = ? THEN moved_from_area_id ELSE area_id END
		WHERE id = ?`, toAreaID, toAreaID, threadID)
	if err != nil {
		return fmt.Errorf("store: move thread: %w", err)
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

// ThreadRead returns the user's last-read pointer for a thread (0 when never
// read). It is exported for service and test use.
func (s *Store) ThreadRead(userID, threadID string) (int64, error) {
	var last int64
	err := s.db.QueryRow(`SELECT last_read_post_id FROM thread_reads
		WHERE user_id = ? AND thread_id = ?`, userID, threadID).Scan(&last)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("store: thread read: %w", err)
	}
	return last, nil
}

// MaxPostID is the highest live post id in a thread (0 when empty).
func (s *Store) MaxPostID(threadID string) (int64, error) {
	var maxID int64
	err := s.db.QueryRow(`SELECT COALESCE(MAX(id), 0) FROM posts
		WHERE thread_id = ? AND is_deleted = 0`, threadID).Scan(&maxID)
	if err != nil {
		return 0, fmt.Errorf("store: max post id: %w", err)
	}
	return maxID, nil
}

// MarkThreadRead records a per-user read pointer. It never moves backwards.
func (s *Store) MarkThreadRead(userID, threadID string, postID int64, at time.Time) error {
	_, err := s.db.Exec(`INSERT INTO thread_reads(user_id, thread_id, last_read_post_id, read_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id, thread_id) DO UPDATE SET
			last_read_post_id = CASE
				WHEN excluded.last_read_post_id > thread_reads.last_read_post_id
				THEN excluded.last_read_post_id ELSE thread_reads.last_read_post_id END,
			read_at = excluded.read_at`,
		userID, threadID, postID, ts(at))
	if err != nil {
		return fmt.Errorf("store: mark thread read: %w", err)
	}
	return nil
}

// MarkAreaRead advances every thread pointer in an area to its latest live
// post, creating read rows where needed.
func (s *Store) MarkAreaRead(userID, areaID string, at time.Time) error {
	_, err := s.db.Exec(`INSERT INTO thread_reads(user_id, thread_id, last_read_post_id, read_at)
		SELECT ?, t.id,
			COALESCE((SELECT MAX(p.id) FROM posts p
				WHERE p.thread_id = t.id AND p.is_deleted = 0), 0), ?
		FROM threads t WHERE t.area_id = ? AND t.is_deleted = 0
		ON CONFLICT(user_id, thread_id) DO UPDATE SET
			last_read_post_id = CASE
				WHEN excluded.last_read_post_id > thread_reads.last_read_post_id
				THEN excluded.last_read_post_id ELSE thread_reads.last_read_post_id END,
			read_at = excluded.read_at`,
		userID, ts(at), areaID)
	if err != nil {
		return fmt.Errorf("store: mark area read: %w", err)
	}
	return nil
}

// UnreadCountsByArea returns per-area unread counts (non-deleted posts after
// each thread's read pointer) for the supplied areas.
func (s *Store) UnreadCountsByArea(userID string, areaIDs []string) (map[string]int, error) {
	out := make(map[string]int, len(areaIDs))
	for _, id := range areaIDs {
		out[id] = 0
	}
	if userID == "" || len(areaIDs) == 0 {
		return out, nil
	}
	query := `SELECT t.area_id, COUNT(*) FROM posts p
		JOIN threads t ON t.id = p.thread_id
		LEFT JOIN thread_reads tr ON tr.thread_id = t.id AND tr.user_id = ?
		WHERE p.is_deleted = 0 AND t.is_deleted = 0
		  AND p.id > COALESCE(tr.last_read_post_id, 0)
		  AND t.area_id IN (` + placeholders(len(areaIDs)) + `)
		GROUP BY t.area_id`
	args := make([]any, 0, len(areaIDs)+1)
	args = append(args, userID)
	for _, id := range areaIDs {
		args = append(args, id)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: unread by area: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var areaID string
		var n int
		if err := rows.Scan(&areaID, &n); err != nil {
			return nil, err
		}
		out[areaID] = n
	}
	return out, rows.Err()
}

// UnreadTotalForAreas counts unread posts across the supplied areas.
func (s *Store) UnreadTotalForAreas(userID string, areaIDs []string) (int, error) {
	if userID == "" || len(areaIDs) == 0 {
		return 0, nil
	}
	query := `SELECT COUNT(*) FROM posts p
		JOIN threads t ON t.id = p.thread_id
		LEFT JOIN thread_reads tr ON tr.thread_id = t.id AND tr.user_id = ?
		WHERE p.is_deleted = 0 AND t.is_deleted = 0
		  AND p.id > COALESCE(tr.last_read_post_id, 0)
		  AND t.area_id IN (` + placeholders(len(areaIDs)) + `)`
	args := make([]any, 0, len(areaIDs)+1)
	args = append(args, userID)
	for _, id := range areaIDs {
		args = append(args, id)
	}
	var n int
	if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: unread total: %w", err)
	}
	return n, nil
}

// CountPostsByUserSince counts posts created at or after since, including
// deleted ones so rate limits cannot be dodged by deleting.
func (s *Store) CountPostsByUserSince(userID string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM posts WHERE author_id = ? AND created_at >= ?`,
		userID, ts(since)).Scan(&n)
	return n, err
}

// SearchPosts runs an FTS5 MATCH over subjects and bodies, best match first.
// Soft-deleted posts and threads are excluded.
func (s *Store) SearchPosts(query string, areaIDs []string, limit int) ([]domain.Post, error) {
	fts := boardFTSQuery(query)
	if fts == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	sqlText := `SELECT ` + boardPostCols + `
		FROM posts_fts
		JOIN posts p ON p.id = posts_fts.rowid
		JOIN threads t ON t.id = p.thread_id
		JOIN users u ON u.id = p.author_id
		WHERE posts_fts MATCH ? AND p.is_deleted = 0 AND t.is_deleted = 0`
	args := []any{fts}
	if len(areaIDs) > 0 {
		sqlText += ` AND t.area_id IN (` + placeholders(len(areaIDs)) + `)`
		for _, id := range areaIDs {
			args = append(args, id)
		}
	}
	sqlText += ` ORDER BY bm25(posts_fts) ASC, p.id ASC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, fmt.Errorf("store: search posts: %w", err)
	}
	defer rows.Close()
	var out []domain.Post
	for rows.Next() {
		p, err := scanBoardPost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}
