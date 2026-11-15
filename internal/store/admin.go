package store

import (
	"errors"
	"fmt"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

// AdminCounts is the snapshot backing the sysop stats screen and `bbs admin stats`.
type AdminCounts struct {
	Users       int
	Active      int
	Probation   int
	Suspended   int
	Areas       int
	Threads     int
	Posts       int
	FileAreas   int
	Files       int
	Mail        int
	Oneliners   int
	Sessions24h int
	DBBytes     int64
}

// AdminCounts gathers board-wide counters in one place.
func (s *Store) AdminCounts() (AdminCounts, error) {
	var c AdminCounts
	scalar := func(dst *int, query string, args ...any) error {
		return s.db.QueryRow(query, args...).Scan(dst)
	}
	if err := scalar(&c.Users, `SELECT COUNT(*) FROM users`); err != nil {
		return c, fmt.Errorf("store: count users: %w", err)
	}
	if err := scalar(&c.Active, `SELECT COUNT(*) FROM users WHERE status = ?`, domain.StatusActive); err != nil {
		return c, fmt.Errorf("store: count active users: %w", err)
	}
	if err := scalar(&c.Probation, `SELECT COUNT(*) FROM users WHERE status = ?`, domain.StatusProbation); err != nil {
		return c, fmt.Errorf("store: count probation users: %w", err)
	}
	if err := scalar(&c.Suspended, `SELECT COUNT(*) FROM users WHERE status = ?`, domain.StatusSuspended); err != nil {
		return c, fmt.Errorf("store: count suspended users: %w", err)
	}
	if err := scalar(&c.Areas, `SELECT COUNT(*) FROM areas`); err != nil {
		return c, fmt.Errorf("store: count areas: %w", err)
	}
	if err := scalar(&c.Threads, `SELECT COUNT(*) FROM threads`); err != nil {
		return c, fmt.Errorf("store: count threads: %w", err)
	}
	if err := scalar(&c.Posts, `SELECT COUNT(*) FROM posts`); err != nil {
		return c, fmt.Errorf("store: count posts: %w", err)
	}
	if err := scalar(&c.FileAreas, `SELECT COUNT(*) FROM file_areas`); err != nil {
		return c, fmt.Errorf("store: count file areas: %w", err)
	}
	if err := scalar(&c.Files, `SELECT COUNT(*) FROM files WHERE is_deleted = 0`); err != nil {
		return c, fmt.Errorf("store: count files: %w", err)
	}
	if err := scalar(&c.Mail, `SELECT COUNT(*) FROM mail`); err != nil {
		return c, fmt.Errorf("store: count mail: %w", err)
	}
	if err := scalar(&c.Oneliners, `SELECT COUNT(*) FROM oneliners`); err != nil {
		return c, fmt.Errorf("store: count oneliners: %w", err)
	}
	if err := scalar(&c.Sessions24h, `SELECT COUNT(*) FROM sessions WHERE started_at >= ?`,
		time.Now().UTC().Add(-24*time.Hour).Unix()); err != nil {
		return c, fmt.Errorf("store: count sessions: %w", err)
	}
	if err := s.db.QueryRow(`SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()`).
		Scan(&c.DBBytes); err != nil {
		return c, fmt.Errorf("store: database size: %w", err)
	}
	return c, nil
}

// CountUsersByStatus counts accounts in one lifecycle state.
func (s *Store) CountUsersByStatus(status domain.Status) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE status = ?`, status).Scan(&n)
	return n, err
}

// CountSessionsSince counts sessions that started at or after t.
func (s *Store) CountSessionsSince(t time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE started_at >= ?`, t.UTC().Unix()).Scan(&n)
	return n, err
}

// CountAreaThreads counts threads in an area (including soft-deleted ones).
func (s *Store) CountAreaThreads(areaID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM threads WHERE area_id = ?`, areaID).Scan(&n)
	return n, err
}

// --- message areas ---

const adminAreaCols = `id, tag, name, description, sort_order, acl_read, acl_post,
	acl_moderate, retention_days, rate_limit_per_hour, is_public, created_at`

func adminScanArea(sc interface{ Scan(...any) error }) (*domain.Area, error) {
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

// AdminListAreas returns every message area in display order.
func (s *Store) AdminListAreas() ([]domain.Area, error) {
	rows, err := s.db.Query(`SELECT ` + adminAreaCols + ` FROM areas ORDER BY sort_order, tag`)
	if err != nil {
		return nil, fmt.Errorf("store: list areas: %w", err)
	}
	defer rows.Close()
	var out []domain.Area
	for rows.Next() {
		a, err := adminScanArea(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// AdminAreaByID loads one message area.
func (s *Store) AdminAreaByID(id string) (*domain.Area, error) {
	return adminScanArea(s.db.QueryRow(`SELECT `+adminAreaCols+` FROM areas WHERE id = ?`, id))
}

// AdminAreaByTag loads a message area case-insensitively.
func (s *Store) AdminAreaByTag(tag string) (*domain.Area, error) {
	return adminScanArea(s.db.QueryRow(`SELECT `+adminAreaCols+` FROM areas WHERE tag = ? COLLATE NOCASE`, tag))
}

// CreateArea inserts a message area, generating ID and CreatedAt when unset.
func (s *Store) CreateArea(a *domain.Area) error {
	if a.ID == "" {
		a.ID = newID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if len(a.ACL.Read) == 0 && len(a.ACL.Post) == 0 && len(a.ACL.Moderate) == 0 {
		a.ACL = domain.DefaultACL()
	}
	_, err := s.db.Exec(`INSERT INTO areas(id, tag, name, description, sort_order,
		acl_read, acl_post, acl_moderate, retention_days, rate_limit_per_hour,
		is_public, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Tag, a.Name, a.Description, a.SortOrder,
		domain.FormatACL(a.ACL.Read), domain.FormatACL(a.ACL.Post), domain.FormatACL(a.ACL.Moderate),
		a.RetentionDays, a.RateLimitPerHour, boolInt(a.IsPublic), ts(a.CreatedAt))
	if err != nil {
		if isUniqueErr(err) {
			return fmt.Errorf("%w: area tag %q already exists", domain.ErrConflict, a.Tag)
		}
		return fmt.Errorf("store: create area: %w", err)
	}
	return nil
}

// UpdateArea persists the editable fields of an area.
func (s *Store) UpdateArea(a *domain.Area) error {
	res, err := s.db.Exec(`UPDATE areas SET name = ?, description = ?, sort_order = ?,
		acl_read = ?, acl_post = ?, acl_moderate = ?, retention_days = ?,
		rate_limit_per_hour = ?, is_public = ? WHERE id = ?`,
		a.Name, a.Description, a.SortOrder,
		domain.FormatACL(a.ACL.Read), domain.FormatACL(a.ACL.Post), domain.FormatACL(a.ACL.Moderate),
		a.RetentionDays, a.RateLimitPerHour, boolInt(a.IsPublic), a.ID)
	if err != nil {
		return fmt.Errorf("store: update area: %w", err)
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

// DeleteArea removes an area. Unless force is true it refuses while threads
// remain, so a typo cannot silently destroy a conference.
func (s *Store) DeleteArea(id string, force bool) error {
	if !force {
		n, err := s.CountAreaThreads(id)
		if err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: area still has %d thread(s); use --force", domain.ErrConflict, n)
		}
	}
	res, err := s.db.Exec(`DELETE FROM areas WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete area: %w", err)
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

// --- file areas ---

const fileAreaCols = `id, tag, name, description, sort_order, acl_read, acl_upload,
	quota_bytes, created_at`

func scanFileArea(sc interface{ Scan(...any) error }) (*domain.FileArea, error) {
	var a domain.FileArea
	var aclRead, aclUpload string
	var createdAt int64
	if err := sc.Scan(&a.ID, &a.Tag, &a.Name, &a.Description, &a.SortOrder,
		&aclRead, &aclUpload, &a.QuotaBytes, &createdAt); err != nil {
		return nil, notFound(err)
	}
	var err error
	if a.ACL.Read, err = domain.ParseACL(aclRead); err != nil {
		return nil, fmt.Errorf("store: file area %s read acl: %w", a.Tag, err)
	}
	if a.ACL.Post, err = domain.ParseACL(aclUpload); err != nil {
		return nil, fmt.Errorf("store: file area %s upload acl: %w", a.Tag, err)
	}
	a.CreatedAt = fromTS(createdAt)
	return &a, nil
}

// CreateFileArea inserts a download area.
func (s *Store) CreateFileArea(a *domain.FileArea) error {
	if a.ID == "" {
		a.ID = newID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if len(a.ACL.Read) == 0 && len(a.ACL.Post) == 0 {
		a.ACL = domain.DefaultACL()
	}
	_, err := s.db.Exec(`INSERT INTO file_areas(`+fileAreaCols+`) VALUES (?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Tag, a.Name, a.Description, a.SortOrder,
		domain.FormatACL(a.ACL.Read), domain.FormatACL(a.ACL.Post),
		a.QuotaBytes, ts(a.CreatedAt))
	if err != nil {
		if isUniqueErr(err) {
			return fmt.Errorf("%w: file area tag %q already exists", domain.ErrConflict, a.Tag)
		}
		return fmt.Errorf("store: create file area: %w", err)
	}
	return nil
}

// FileAreaByID loads a download area.
func (s *Store) FileAreaByID(id string) (*domain.FileArea, error) {
	return scanFileArea(s.db.QueryRow(`SELECT `+fileAreaCols+` FROM file_areas WHERE id = ?`, id))
}

// FileAreaByTag loads a download area case-insensitively.
func (s *Store) FileAreaByTag(tag string) (*domain.FileArea, error) {
	return scanFileArea(s.db.QueryRow(`SELECT `+fileAreaCols+` FROM file_areas WHERE tag = ? COLLATE NOCASE`, tag))
}

// ListFileAreas returns download areas in display order.
func (s *Store) ListFileAreas() ([]domain.FileArea, error) {
	rows, err := s.db.Query(`SELECT ` + fileAreaCols + ` FROM file_areas ORDER BY sort_order, name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.FileArea
	for rows.Next() {
		a, err := scanFileArea(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// UpdateFileArea persists the editable fields of a download area.
func (s *Store) UpdateFileArea(a *domain.FileArea) error {
	res, err := s.db.Exec(`UPDATE file_areas SET name = ?, description = ?, sort_order = ?,
		acl_read = ?, acl_upload = ?, quota_bytes = ? WHERE id = ?`,
		a.Name, a.Description, a.SortOrder,
		domain.FormatACL(a.ACL.Read), domain.FormatACL(a.ACL.Post), a.QuotaBytes, a.ID)
	if err != nil {
		return fmt.Errorf("store: update file area: %w", err)
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

// DeleteFileArea removes a download area (files cascade).
func (s *Store) DeleteFileArea(id string) error {
	res, err := s.db.Exec(`DELETE FROM file_areas WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete file area: %w", err)
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

// --- bans ---

const banCols = `id, scope, value, reason, created_by, created_at, expires_at`

func scanBan(sc interface{ Scan(...any) error }) (*domain.Ban, error) {
	var b domain.Ban
	var createdAt, expiresAt int64
	if err := sc.Scan(&b.ID, &b.Scope, &b.Value, &b.Reason, &b.CreatedBy,
		&createdAt, &expiresAt); err != nil {
		return nil, notFound(err)
	}
	b.CreatedAt = fromTS(createdAt)
	b.ExpiresAt = fromTS(expiresAt)
	return &b, nil
}

// CreateBan records a handle or IP-hash ban.
func (s *Store) CreateBan(b *domain.Ban) error {
	if b.ID == "" {
		b.ID = newID()
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.Exec(`INSERT INTO bans(`+banCols+`) VALUES (?,?,?,?,?,?,?)`,
		b.ID, b.Scope, b.Value, b.Reason, b.CreatedBy, ts(b.CreatedAt), ts(b.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: create ban: %w", err)
	}
	return nil
}

// ListBans returns every ban, newest first (expired entries included).
func (s *Store) ListBans() ([]domain.Ban, error) {
	rows, err := s.db.Query(`SELECT ` + banCols + ` FROM bans ORDER BY created_at DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Ban
	for rows.Next() {
		b, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// RemoveBan deletes a ban by ID.
func (s *Store) RemoveBan(id string) error {
	res, err := s.db.Exec(`DELETE FROM bans WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: remove ban: %w", err)
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

// ActiveBan finds an unexpired ban for scope/value at the given instant.
// Handle values are matched case-insensitively.
func (s *Store) ActiveBan(scope, value string, at time.Time) (*domain.Ban, error) {
	if scope == "" || value == "" {
		return nil, domain.ErrNotFound
	}
	b, err := scanBan(s.db.QueryRow(`SELECT `+banCols+` FROM bans
		WHERE scope = ? AND value = ? COLLATE NOCASE
		AND (expires_at = 0 OR expires_at > ?)
		ORDER BY created_at DESC, id DESC LIMIT 1`, scope, value, at.UTC().Unix()))
	if errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	return b, err
}

// --- retention / prune primitives ---

// CountSessionsBefore counts sessions started before cutoff.
func (s *Store) CountSessionsBefore(cutoff time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE started_at < ?`, ts(cutoff)).Scan(&n)
	return n, err
}

// PruneSessions deletes sessions started before cutoff.
func (s *Store) PruneSessions(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE started_at < ?`, ts(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: prune sessions: %w", err)
	}
	return res.RowsAffected()
}

// CountAuditBefore counts audit rows older than cutoff.
func (s *Store) CountAuditBefore(cutoff time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE at < ?`, ts(cutoff)).Scan(&n)
	return n, err
}

// CountOnelinersBefore counts oneliners older than cutoff.
func (s *Store) CountOnelinersBefore(cutoff time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM oneliners WHERE created_at < ?`, ts(cutoff)).Scan(&n)
	return n, err
}

// PruneOneliners deletes oneliners older than cutoff.
func (s *Store) PruneOneliners(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM oneliners WHERE created_at < ?`, ts(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: prune oneliners: %w", err)
	}
	return res.RowsAffected()
}

// CountDeletedPostsBefore counts soft-deleted posts older than cutoff.
func (s *Store) CountDeletedPostsBefore(cutoff time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM posts WHERE is_deleted = 1 AND created_at < ?`,
		ts(cutoff)).Scan(&n)
	return n, err
}

// PruneDeletedPosts hard-deletes soft-deleted posts older than cutoff.
func (s *Store) PruneDeletedPosts(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM posts WHERE is_deleted = 1 AND created_at < ?`, ts(cutoff))
	if err != nil {
		return 0, fmt.Errorf("store: prune deleted posts: %w", err)
	}
	return res.RowsAffected()
}

// --- settings ---

// ListSettings returns the runtime settings table.
func (s *Store) ListSettings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetSetting upserts a runtime knob.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// --- bulletins & polls (sysop-managed community content) ---

const bulletinCols = `id, title, body, sort, is_active, created_at, updated_at`

func scanBulletin(sc interface{ Scan(...any) error }) (*domain.Bulletin, error) {
	var b domain.Bulletin
	var active int
	var createdAt, updatedAt int64
	if err := sc.Scan(&b.ID, &b.Title, &b.Body, &b.Sort, &active, &createdAt, &updatedAt); err != nil {
		return nil, notFound(err)
	}
	b.Active = active == 1
	b.CreatedAt = fromTS(createdAt)
	b.UpdatedAt = fromTS(updatedAt)
	return &b, nil
}

// AdminListBulletins lists bulletins in display order.
func (s *Store) AdminListBulletins() ([]domain.Bulletin, error) {
	rows, err := s.db.Query(`SELECT ` + bulletinCols + ` FROM bulletins ORDER BY sort, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Bulletin
	for rows.Next() {
		b, err := scanBulletin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// AdminCreateBulletin inserts a bulletin, generating ID and timestamps.
func (s *Store) AdminCreateBulletin(b *domain.Bulletin) error {
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
	_, err := s.db.Exec(`INSERT INTO bulletins(`+bulletinCols+`) VALUES (?,?,?,?,?,?,?)`,
		b.ID, b.Title, b.Body, b.Sort, boolInt(b.Active), ts(b.CreatedAt), ts(b.UpdatedAt))
	if err != nil {
		return fmt.Errorf("store: create bulletin: %w", err)
	}
	return nil
}

// AdminDeleteBulletin removes a bulletin and its per-user dismissals.
func (s *Store) AdminDeleteBulletin(id string) error {
	res, err := s.db.Exec(`DELETE FROM bulletins WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete bulletin: %w", err)
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

// AdminCreatePoll inserts a poll and its options atomically.
func (s *Store) AdminCreatePoll(p *domain.Poll) error {
	if p.ID == "" {
		p.ID = newID()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO polls(id, question, created_by, created_at, closes_at, is_hidden)
		VALUES (?, ?, ?, ?, ?, ?)`,
		p.ID, p.Question, p.CreatedBy, ts(p.CreatedAt), ts(p.ClosesAt), boolInt(p.Hidden)); err != nil {
		return fmt.Errorf("store: create poll: %w", err)
	}
	for i, opt := range p.Options {
		sortOrder := opt.Sort
		if sortOrder == 0 {
			sortOrder = i + 1
		}
		if _, err := tx.Exec(`INSERT INTO poll_options(poll_id, label, sort) VALUES (?, ?, ?)`,
			p.ID, opt.Label, sortOrder); err != nil {
			return fmt.Errorf("store: create poll option: %w", err)
		}
	}
	return tx.Commit()
}
