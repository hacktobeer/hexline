package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

// NewFileID returns a fresh ULID for a file row. Storage names are derived
// from it so user input never reaches the filesystem.
func NewFileID() string { return newID() }

const fileCols = `f.id, f.area_id, a.tag, f.filename, f.stored_path, f.size_bytes, f.sha256,
	f.description, f.uploader_id, u.handle, f.uploaded_at, f.download_count, f.scan_status,
	COALESCE(r.avg_stars, 0), COALESCE(r.rating_count, 0)`

const fileJoins = `FROM files f
	JOIN file_areas a ON a.id = f.area_id
	JOIN users u ON u.id = f.uploader_id
	LEFT JOIN (
		SELECT file_id, AVG(stars) AS avg_stars, COUNT(*) AS rating_count
		FROM file_ratings GROUP BY file_id
	) r ON r.file_id = f.id`

func scanFile(sc interface{ Scan(...any) error }) (*domain.File, error) {
	var f domain.File
	var uploadedAt int64
	if err := sc.Scan(&f.ID, &f.AreaID, &f.AreaTag, &f.Filename, &f.StoredPath,
		&f.SizeBytes, &f.SHA256, &f.Description, &f.UploaderID, &f.Uploader,
		&uploadedAt, &f.DownloadCount, &f.ScanStatus, &f.Rating, &f.RatingCount); err != nil {
		return nil, notFound(err)
	}
	f.UploadedAt = fromTS(uploadedAt)
	return &f, nil
}

// FileAreaCounts returns non-deleted file counts keyed by area ID.
func (s *Store) FileAreaCounts() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT area_id, COUNT(*) FROM files
		WHERE is_deleted = 0 GROUP BY area_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// ListFiles returns non-deleted files in an area, newest first.
func (s *Store) ListFiles(areaID string, limit, offset int) ([]domain.File, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT `+fileCols+` `+fileJoins+`
		WHERE f.area_id = ? AND f.is_deleted = 0
		ORDER BY f.uploaded_at DESC, f.id DESC LIMIT ? OFFSET ?`,
		areaID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.File
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// FileByID returns one non-deleted file with uploader and rating aggregates.
func (s *Store) FileByID(id string) (*domain.File, error) {
	return scanFile(s.db.QueryRow(`SELECT `+fileCols+` `+fileJoins+`
		WHERE f.id = ? AND f.is_deleted = 0`, strings.TrimSpace(id)))
}

// FileByAreaAndName looks a file up by area and filename (case-insensitive).
func (s *Store) FileByAreaAndName(areaID, filename string) (*domain.File, error) {
	return scanFile(s.db.QueryRow(`SELECT `+fileCols+` `+fileJoins+`
		WHERE f.area_id = ? AND f.filename = ? COLLATE NOCASE AND f.is_deleted = 0
		LIMIT 1`, areaID, filename))
}

// InsertFile records a stored upload. The caller owns the on-disk file.
func (s *Store) InsertFile(f *domain.File) error {
	if f.ID == "" {
		f.ID = newID()
	}
	if f.UploadedAt.IsZero() {
		f.UploadedAt = time.Now().UTC()
	}
	if f.ScanStatus == "" {
		f.ScanStatus = "clean"
	}
	_, err := s.db.Exec(`INSERT INTO files(id, area_id, filename, stored_path, size_bytes,
		sha256, description, uploader_id, uploaded_at, download_count, is_deleted, scan_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		f.ID, f.AreaID, f.Filename, f.StoredPath, f.SizeBytes, f.SHA256, f.Description,
		f.UploaderID, ts(f.UploadedAt), f.DownloadCount, f.ScanStatus)
	if err != nil {
		return fmt.Errorf("store: insert file: %w", err)
	}
	return nil
}

// RecordDownload bumps the counter and appends a file_downloads row. The row
// is skipped for callers without a user ID (guest sessions).
func (s *Store) RecordDownload(fileID, userID string, at time.Time, bytesSent int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE files SET download_count = download_count + 1
		WHERE id = ? AND is_deleted = 0`, fileID)
	if err != nil {
		return fmt.Errorf("store: record download: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: file %s", domain.ErrNotFound, fileID)
	}
	if userID != "" {
		if _, err := tx.Exec(`INSERT INTO file_downloads(file_id, user_id, at, bytes_sent)
			VALUES (?, ?, ?, ?)`, fileID, userID, ts(at), bytesSent); err != nil {
			return fmt.Errorf("store: record download: %w", err)
		}
	}
	return tx.Commit()
}

// UpsertRating stores one rating per user per file.
func (s *Store) UpsertRating(fileID, userID string, stars int, at time.Time) error {
	_, err := s.db.Exec(`INSERT INTO file_ratings(file_id, user_id, stars, at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(file_id, user_id) DO UPDATE SET stars = excluded.stars, at = excluded.at`,
		fileID, userID, stars, ts(at))
	if err != nil {
		return fmt.Errorf("store: rate file: %w", err)
	}
	return nil
}

// UserUploadBytes sums the non-deleted uploads of one user.
func (s *Store) UserUploadBytes(userID string) (int64, error) {
	var total int64
	err := s.db.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM files
		WHERE uploader_id = ? AND is_deleted = 0`, userID).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("store: upload quota: %w", err)
	}
	return total, nil
}

// SoftDeleteFile hides a file from listings and downloads.
func (s *Store) SoftDeleteFile(id string) error {
	res, err := s.db.Exec(`UPDATE files SET is_deleted = 1 WHERE id = ? AND is_deleted = 0`, id)
	if err != nil {
		return fmt.Errorf("store: delete file: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: file %s", domain.ErrNotFound, id)
	}
	return nil
}

// SearchFiles matches filenames and descriptions inside the given areas.
// LIKE wildcards in query are escaped so input is literal.
func (s *Store) SearchFiles(areaIDs []string, query string, limit int) ([]domain.File, error) {
	if len(areaIDs) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	pattern := "%" + escapeLike(strings.TrimSpace(query)) + "%"
	args := make([]any, 0, len(areaIDs)+3)
	for _, id := range areaIDs {
		args = append(args, id)
	}
	args = append(args, pattern, pattern, limit)
	rows, err := s.db.Query(`SELECT `+fileCols+` `+fileJoins+`
		WHERE f.is_deleted = 0 AND f.area_id IN (`+placeholders(len(areaIDs))+`)
		AND (f.filename LIKE ? ESCAPE '\' OR f.description LIKE ? ESCAPE '\')
		ORDER BY f.uploaded_at DESC, f.id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.File
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// escapeLike neutralises LIKE wildcards so user input matches literally.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}
