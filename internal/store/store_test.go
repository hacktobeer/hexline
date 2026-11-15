package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestMigrateIsIdempotent(t *testing.T) {
	st := openTemp(t)
	if err := st.Migrate(); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := st.Migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := st.Seed(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.Seed(); err != nil {
		t.Fatalf("seed twice: %v", err)
	}
	var areas int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM areas`).Scan(&areas); err != nil {
		t.Fatal(err)
	}
	if areas != 3 {
		t.Fatalf("want 3 seeded areas, got %d", areas)
	}
}

func TestFTS5Available(t *testing.T) {
	st := openTemp(t)
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	var names string
	if err := st.DB().QueryRow(`SELECT group_concat(name) FROM pragma_module_list WHERE name LIKE 'fts%'`).Scan(&names); err != nil {
		t.Fatalf("module_list: %v", err)
	}
	if names != "fts5,fts5vocab" {
		t.Fatalf("unexpected fts modules: %q", names)
	}
}

func TestIntegrity(t *testing.T) {
	st := openTemp(t)
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	got, err := st.Integrity()
	if err != nil || got != "ok" {
		t.Fatalf("integrity = %q, %v", got, err)
	}
}

func TestBackupSnapshot(t *testing.T) {
	st := openTemp(t)
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := st.Seed(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "snap.db")
	if err := st.Backup(out); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := st.Backup(out); err == nil {
		t.Fatal("expected refusal to overwrite an existing backup")
	}
	copyStore, err := Open(out)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer copyStore.Close()
	var n int
	if err := copyStore.DB().QueryRow(`SELECT COUNT(*) FROM areas`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("backup areas = %d, %v", n, err)
	}
}

// A backup must not use the serving connection: every query on that one
// connection queues, so a held read transaction would block VACUUM forever.
func TestBackupDoesNotWaitForTheServingConnection(t *testing.T) {
	st := openTemp(t)
	if err := st.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := st.Seed(); err != nil {
		t.Fatal(err)
	}
	rows, err := st.DB().Query(`SELECT id FROM areas`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("no seeded areas")
	}

	out := filepath.Join(t.TempDir(), "snap.db")
	done := make(chan error, 1)
	go func() { done <- st.Backup(out) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("backup: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backup blocked while the serving connection was busy")
	}
}
