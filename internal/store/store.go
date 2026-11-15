// Package store implements hexline's SQLite persistence.
package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"

	"github.com/hacktobeer/hexline/internal/domain"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store owns the database handle. Feature files add methods on *Store.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path.
// A single connection is used deliberately: SQLite has one writer, and
// serializing keeps busy errors out of the service layer.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// DB exposes the handle for store-internal files and diagnostics.
func (s *Store) DB() *sql.DB { return s.db }

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Migrate applies embedded migrations in lexical order.
func (s *Store) Migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("store: list migrations: %w", err)
	}
	sort.Strings(names)

	known := map[string]bool{}
	for _, name := range names {
		version := strings.TrimSuffix(filepath.Base(name), ".sql")
		known[version] = true
		var applied int
		err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&applied)
		if err != nil {
			return fmt.Errorf("store: migration state: %w", err)
		}
		if applied > 0 {
			continue
		}
		body, err := migrationFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("store: read %s: %w", name, err)
		}
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("store: begin %s: %w", version, err)
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: apply %s: %w", version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)`,
			version, time.Now().Unix()); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: record %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit %s: %w", version, err)
		}
	}

	// Refuse to run against a database written by a newer binary.
	var newer string
	err = s.db.QueryRow(`SELECT version FROM schema_migrations WHERE version NOT IN (`+
		placeholders(len(known))+`) ORDER BY version DESC LIMIT 1`, anyArgs(known)...).Scan(&newer)
	if err == nil {
		return fmt.Errorf("store: database schema %q is newer than this binary (known: %s); upgrade the binary",
			newer, strings.Join(keys(known), ", "))
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: schema check: %w", err)
	}
	return nil
}

func placeholders(n int) string {
	if n == 0 {
		return "''"
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func anyArgs(m map[string]bool) []any {
	out := make([]any, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Seed inserts the minimum content a fresh board needs. It is idempotent.
func (s *Store) Seed() error {
	now := time.Now().Unix()
	areas := []struct {
		tag, name, desc string
		sort            int
	}{
		{"general", "General", "Anything and everything. Say hello.", 10},
		{"tech", "Tech", "Computers, code, retro hardware and the occasional rant.", 20},
		{"sysop", "Sysop", "Board announcements and meta discussion.", 30},
	}
	for _, a := range areas {
		if _, err := s.db.Exec(`INSERT INTO areas(id, tag, name, description, sort_order, created_at)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tag) DO NOTHING`,
			newID(), a.tag, a.name, a.desc, a.sort, now); err != nil {
			return fmt.Errorf("store: seed area %s: %w", a.tag, err)
		}
	}
	fa := []struct {
		tag, name, desc string
		sort            int
	}{
		{"uploads", "Uploads", "Shared files from callers.", 10},
	}
	for _, a := range fa {
		if _, err := s.db.Exec(`INSERT INTO file_areas(id, tag, name, description, sort_order, created_at)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(tag) DO NOTHING`,
			newID(), a.tag, a.name, a.desc, a.sort, now); err != nil {
			return fmt.Errorf("store: seed file area %s: %w", a.tag, err)
		}
	}
	if _, err := s.db.Exec(`INSERT INTO bulletins(id, title, body, sort, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, ?, ?) ON CONFLICT(id) DO NOTHING`,
		"welcome", "Welcome to hexline",
		"Thanks for calling. Please read the board rules, be excellent to each other,\nand post something in General before you leave.\n\n-- the sysop",
		10, now, now); err != nil {
		return fmt.Errorf("store: seed bulletin: %w", err)
	}
	return nil
}

// Integrity runs SQLite's integrity check and returns a human-readable result.
func (s *Store) Integrity() (string, error) {
	var result string
	if err := s.db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return "", err
	}
	return result, nil
}

// Backup writes a consistent snapshot to out using VACUUM INTO.
func (s *Store) Backup(out string) error {
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("store: backup target %s already exists", out)
	}
	if _, err := s.db.Exec(`VACUUM INTO ?`, out); err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	return nil
}

// --- shared helpers for feature files ---

func newID() string {
	return ulid.Make().String()
}

func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().Unix()
}

func fromTS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
