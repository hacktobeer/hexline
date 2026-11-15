package store

import (
	"fmt"
	"time"
)

// RecordLoginAttempt appends a login audit row (success or failure).
func (s *Store) RecordLoginAttempt(ipHash, handle string, ok bool) error {
	v := 0
	if ok {
		v = 1
	}
	_, err := s.db.Exec(`INSERT INTO login_attempts(at, ip_hash, handle, ok) VALUES (?, ?, ?, ?)`,
		time.Now().Unix(), ipHash, handle, v)
	if err != nil {
		return fmt.Errorf("store: login attempt: %w", err)
	}
	return nil
}

// CountPostsByUser counts non-deleted posts by author.
func (s *Store) CountPostsByUser(userID string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM posts WHERE author_id = ? AND is_deleted = 0`, userID).Scan(&n)
	return n, err
}

// PruneLoginAttempts deletes rows older than cutoff.
func (s *Store) PruneLoginAttempts(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM login_attempts WHERE at < ?`, ts(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
