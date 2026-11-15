package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

const userCols = `id, handle, email, real_name, location, signature, timezone, role, status,
	created_at, last_call_at, calls, time_online_s, pass_hash, pass_params, prefs_json, promoted_at, is_guest`

func scanUser(sc interface{ Scan(...any) error }) (*domain.User, error) {
	var u domain.User
	var createdAt, lastCallAt, timeOnline, promotedAt int64
	var prefsJSON string
	var guest int
	err := sc.Scan(&u.ID, &u.Handle, &u.Email, &u.RealName, &u.Location, &u.Signature,
		&u.Timezone, &u.Role, &u.Status, &createdAt, &lastCallAt, &u.Calls, &timeOnline,
		&u.PassHash, &u.PassParams, &prefsJSON, &promotedAt, &guest)
	if err != nil {
		return nil, notFound(err)
	}
	u.CreatedAt = fromTS(createdAt)
	u.LastCallAt = fromTS(lastCallAt)
	u.TimeOnline = time.Duration(timeOnline) * time.Second
	u.PromotedAt = fromTS(promotedAt)
	u.IsGuest = guest == 1
	u.Prefs = domain.DefaultPrefs()
	if prefsJSON != "" && prefsJSON != "{}" {
		if err := json.Unmarshal([]byte(prefsJSON), &u.Prefs); err != nil {
			return nil, fmt.Errorf("store: user prefs: %w", err)
		}
	}
	u.Prefs = u.Prefs.Normalize()
	return &u, nil
}

// CreateUser inserts u, generating an ID when empty.
func (s *Store) CreateUser(u *domain.User) error {
	if u.ID == "" {
		u.ID = newID()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	if u.Role == "" {
		u.Role = domain.RoleUser
	}
	if u.Status == "" {
		u.Status = domain.StatusProbation
	}
	if u.Timezone == "" {
		u.Timezone = "UTC"
	}
	u.Prefs = u.Prefs.Normalize()
	prefs, err := json.Marshal(u.Prefs)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO users(`+userCols+`) VALUES
		(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Handle, u.Email, u.RealName, u.Location, u.Signature, u.Timezone,
		u.Role, u.Status, ts(u.CreatedAt), ts(u.LastCallAt), u.Calls,
		int64(u.TimeOnline.Seconds()), u.PassHash, u.PassParams, string(prefs), ts(u.PromotedAt),
		boolInt(u.IsGuest))
	if err != nil {
		if isUniqueErr(err) {
			return fmt.Errorf("%w: handle %q is taken", domain.ErrConflict, u.Handle)
		}
		return fmt.Errorf("store: create user: %w", err)
	}
	return nil
}

// UserByHandle looks a user up case-insensitively.
func (s *Store) UserByHandle(handle string) (*domain.User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE handle = ? COLLATE NOCASE`, handle))
}

// UserByID looks a user up by ID.
func (s *Store) UserByID(id string) (*domain.User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// HandleExists reports whether a handle is taken.
func (s *Store) HandleExists(handle string) (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE handle = ? COLLATE NOCASE`, handle).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// CountUsers returns the number of accounts (any status).
func (s *Store) CountUsers() (int, error) {
	var n int
	return n, s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
}

// ListUsers returns accounts ordered by creation time.
func (s *Store) ListUsers(limit, offset int) ([]domain.User, error) {
	rows, err := s.db.Query(`SELECT `+userCols+` FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// UpdateUserProfile persists editable profile fields.
func (s *Store) UpdateUserProfile(u *domain.User) error {
	_, err := s.db.Exec(`UPDATE users SET email = ?, real_name = ?, location = ?,
		signature = ?, timezone = ? WHERE id = ?`,
		u.Email, u.RealName, u.Location, u.Signature, u.Timezone, u.ID)
	if err != nil {
		return fmt.Errorf("store: update profile: %w", err)
	}
	return nil
}

// UpdateUserPrefs persists presentation preferences.
func (s *Store) UpdateUserPrefs(id string, p domain.Prefs) error {
	raw, err := json.Marshal(p.Normalize())
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE users SET prefs_json = ? WHERE id = ?`, string(raw), id)
	return err
}

// SetPassword replaces the stored hash and its parameter record.
func (s *Store) SetPassword(id, hash, params string) error {
	_, err := s.db.Exec(`UPDATE users SET pass_hash = ?, pass_params = ? WHERE id = ?`, hash, params, id)
	return err
}

// SetStatus changes an account's state.
func (s *Store) SetStatus(id string, status domain.Status) error {
	_, err := s.db.Exec(`UPDATE users SET status = ? WHERE id = ?`, status, id)
	return err
}

// Promote moves a probationary account to active.
func (s *Store) Promote(id string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE users SET status = ?, promoted_at = ? WHERE id = ? AND status = ?`,
		domain.StatusActive, ts(at), id, domain.StatusProbation)
	return err
}

// RecordLogin updates call statistics.
func (s *Store) RecordLogin(id string, at time.Time, online time.Duration) error {
	_, err := s.db.Exec(`UPDATE users SET last_call_at = ?, calls = calls + 1,
		time_online_s = time_online_s + ? WHERE id = ?`, ts(at), int64(online.Seconds()), id)
	return err
}

// SetRole changes an account's role.
func (s *Store) SetRole(id string, role domain.Role) error {
	_, err := s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, id)
	return err
}

// AddSSHKey records a public key fingerprint for a user.
func (s *Store) AddSSHKey(userID, fingerprint, key string) error {
	_, err := s.db.Exec(`INSERT INTO ssh_keys(fingerprint, user_id, key, created_at)
		VALUES (?, ?, ?, ?) ON CONFLICT(fingerprint) DO UPDATE SET user_id = excluded.user_id`,
		fingerprint, userID, key, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store: add ssh key: %w", err)
	}
	return nil
}

// UserIDBySSHKey resolves a key fingerprint to a user ID.
func (s *Store) UserIDBySSHKey(fingerprint string) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT user_id FROM ssh_keys WHERE fingerprint = ?`, fingerprint).Scan(&id)
	return id, notFound(err)
}

// ActiveHandlesOlderThan lists active accounts older than t (for stats).
func (s *Store) ActiveHandlesOlderThan(t time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT handle FROM users WHERE status = ? AND created_at < ?`,
		domain.StatusActive, ts(t))
	if err != nil {
		return nil, err
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

func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	// modernc.org/sqlite surfaces constraint violations in the message.
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
