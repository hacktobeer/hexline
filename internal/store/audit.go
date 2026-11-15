package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

// RecordAudit appends an audit entry. detail is marshalled to JSON; nil is
// stored as {}.
func (s *Store) RecordAudit(e domain.AuditEntry) error {
	detail := e.Detail
	if detail == "" {
		detail = "{}"
	} else if !json.Valid([]byte(detail)) {
		b, err := json.Marshal(map[string]string{"note": detail})
		if err != nil {
			return err
		}
		detail = string(b)
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	var actor any
	if e.ActorID != "" {
		actor = e.ActorID
	}
	_, err := s.db.Exec(`INSERT INTO audit_log(at, actor_id, actor, action, target_kind, target_id, detail_json, ip_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts(e.At), actor, e.Actor, e.Action, e.TargetKind, e.TargetID, detail, e.IPHash)
	if err != nil {
		return fmt.Errorf("store: record audit: %w", err)
	}
	return nil
}

// ListAudit returns recent entries, newest first.
func (s *Store) ListAudit(limit int) ([]domain.AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id, at, COALESCE(actor_id,''), actor, action,
		target_kind, target_id, detail_json, ip_hash FROM audit_log
		ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AuditEntry
	for rows.Next() {
		var e domain.AuditEntry
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.ActorID, &e.Actor, &e.Action,
			&e.TargetKind, &e.TargetID, &e.Detail, &e.IPHash); err != nil {
			return nil, err
		}
		e.At = fromTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneAudit deletes entries older than cutoff and returns the count removed.
func (s *Store) PruneAudit(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM audit_log WHERE at < ?`, ts(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// StartSession records a live session row.
func (s *Store) StartSession(id, userID string, node int, ipHash, client string) error {
	_, err := s.db.Exec(`INSERT INTO sessions(id, user_id, node, started_at, ip_hash, client)
		VALUES (?, ?, ?, ?, ?, ?)`, id, nullString(userID), node, time.Now().Unix(), ipHash, client)
	return err
}

// EndSession marks a session finished.
func (s *Store) EndSession(id string) error {
	_, err := s.db.Exec(`UPDATE sessions SET ended_at = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
