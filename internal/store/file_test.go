package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hacktobeer/hexline/internal/domain"
)

// filesTestStore opens a migrated, seeded database.
func filesTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "files.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := st.Seed(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return st
}

func filesTestUser(t *testing.T, st *Store, handle string) *domain.User {
	t.Helper()
	u := &domain.User{Handle: handle, Role: domain.RoleUser, Status: domain.StatusActive, PassHash: "x"}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", handle, err)
	}
	return u
}

// filesTestArea returns the seeded uploads area ID.
func filesTestArea(t *testing.T, st *Store) (id, tag string) {
	t.Helper()
	row := st.DB().QueryRow(`SELECT id, tag FROM file_areas WHERE tag = 'uploads'`)
	if err := row.Scan(&id, &tag); err != nil {
		t.Fatalf("uploads area: %v", err)
	}
	return id, tag
}

func filesTestFile(t *testing.T, st *Store, areaID, areaTag string, uploader *domain.User, name string, size int64) *domain.File {
	t.Helper()
	f := &domain.File{
		ID:         NewFileID(),
		AreaID:     areaID,
		AreaTag:    areaTag,
		Filename:   name,
		StoredPath: filepath.Join(areaTag, NewFileID()),
		SizeBytes:  size,
		SHA256:     strings.Repeat("ab", 32),
		UploaderID: uploader.ID,
		UploadedAt: time.Now().UTC(),
	}
	if err := st.InsertFile(f); err != nil {
		t.Fatalf("insert file: %v", err)
	}
	return f
}

func TestFileInsertListDetail(t *testing.T) {
	st := filesTestStore(t)
	areaID, areaTag := filesTestArea(t, st)
	ada := filesTestUser(t, st, "ada")

	older := filesTestFile(t, st, areaID, areaTag, ada, "older.txt", 100)
	newer := filesTestFile(t, st, areaID, areaTag, ada, "newer.txt", 2048)

	list, err := st.ListFiles(areaID, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 files, got %d", len(list))
	}
	// Newest first.
	if list[0].Filename != "newer.txt" || list[1].Filename != "older.txt" {
		t.Fatalf("unexpected order: %s, %s", list[0].Filename, list[1].Filename)
	}
	if list[0].Uploader != "ada" || list[0].AreaTag != "uploads" {
		t.Fatalf("joins missing: %+v", list[0])
	}

	got, err := st.FileByID(newer.ID)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if got.Filename != "newer.txt" || got.SizeBytes != 2048 || got.SHA256 != strings.Repeat("ab", 32) {
		t.Fatalf("detail mismatch: %+v", got)
	}
	if got.RatingCount != 0 || got.Rating != 0 {
		t.Fatalf("fresh file should be unrated: %+v", got)
	}

	// Paging.
	page, err := st.ListFiles(areaID, 1, 1)
	if err != nil || len(page) != 1 || page[0].Filename != "older.txt" {
		t.Fatalf("page = %+v, %v", page, err)
	}

	// Case-insensitive name lookup.
	byName, err := st.FileByAreaAndName(areaID, "NEWER.TXT")
	if err != nil || byName.ID != newer.ID {
		t.Fatalf("lookup by name = %+v, %v", byName, err)
	}
	if _, err := st.FileByID(older.ID); err != nil {
		t.Fatalf("older lookup: %v", err)
	}
}

func TestFileAreaCountsAndQuota(t *testing.T) {
	st := filesTestStore(t)
	areaID, areaTag := filesTestArea(t, st)
	ada := filesTestUser(t, st, "ada")
	bob := filesTestUser(t, st, "bob")

	keep := filesTestFile(t, st, areaID, areaTag, ada, "keep.bin", 700)
	filesTestFile(t, st, areaID, areaTag, ada, "gone.bin", 500)
	filesTestFile(t, st, areaID, areaTag, bob, "bob.bin", 50)

	counts, err := st.FileAreaCounts()
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts[areaID] != 3 {
		t.Fatalf("counts = %v", counts)
	}
	used, err := st.UserUploadBytes(ada.ID)
	if err != nil || used != 1200 {
		t.Fatalf("quota sum = %d, %v", used, err)
	}
	if err := st.SoftDeleteFile(keep.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	used, err = st.UserUploadBytes(ada.ID)
	if err != nil || used != 500 {
		t.Fatalf("quota sum after delete = %d, %v", used, err)
	}
	counts, err = st.FileAreaCounts()
	if err != nil || counts[areaID] != 2 {
		t.Fatalf("counts after delete = %v, %v", counts, err)
	}
	if _, err := st.FileByID(keep.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted file should be gone, got %v", err)
	}
	if err := st.SoftDeleteFile(keep.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestFileRatingUpsert(t *testing.T) {
	st := filesTestStore(t)
	areaID, areaTag := filesTestArea(t, st)
	ada := filesTestUser(t, st, "ada")
	bob := filesTestUser(t, st, "bob")
	f := filesTestFile(t, st, areaID, areaTag, ada, "rate.zip", 10)

	now := time.Now().UTC()
	if err := st.UpsertRating(f.ID, bob.ID, 2, now); err != nil {
		t.Fatalf("rate: %v", err)
	}
	if err := st.UpsertRating(f.ID, bob.ID, 5, now); err != nil {
		t.Fatalf("rerate: %v", err)
	}
	if err := st.UpsertRating(f.ID, ada.ID, 4, now); err != nil {
		t.Fatalf("rate 2: %v", err)
	}
	var rows int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM file_ratings WHERE file_id = ?`, f.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("want 2 rating rows (upsert), got %d", rows)
	}
	got, err := st.FileByID(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RatingCount != 2 || got.Rating != 4.5 {
		t.Fatalf("rating aggregate = %v (%d)", got.Rating, got.RatingCount)
	}
}

func TestFileDownloadCounter(t *testing.T) {
	st := filesTestStore(t)
	areaID, areaTag := filesTestArea(t, st)
	ada := filesTestUser(t, st, "ada")
	bob := filesTestUser(t, st, "bob")
	f := filesTestFile(t, st, areaID, areaTag, ada, "download.bin", 42)

	now := time.Now().UTC()
	if err := st.RecordDownload(f.ID, bob.ID, now, f.SizeBytes); err != nil {
		t.Fatalf("record download: %v", err)
	}
	// Guests have no user row: the counter still moves, the log row is skipped.
	if err := st.RecordDownload(f.ID, "", now, f.SizeBytes); err != nil {
		t.Fatalf("record guest download: %v", err)
	}
	got, err := st.FileByID(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DownloadCount != 2 {
		t.Fatalf("download count = %d", got.DownloadCount)
	}
	var logged int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM file_downloads WHERE file_id = ?`, f.ID).Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if logged != 1 {
		t.Fatalf("download rows = %d", logged)
	}
	if err := st.RecordDownload("missing", bob.ID, now, 0); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("download of missing file = %v", err)
	}
}

func TestFileSearchEscapesWildcards(t *testing.T) {
	st := filesTestStore(t)
	areaID, areaTag := filesTestArea(t, st)
	ada := filesTestUser(t, st, "ada")

	percent := filesTestFile(t, st, areaID, areaTag, ada, "100% done.txt", 1)
	filesTestFile(t, st, areaID, areaTag, ada, "plain.txt", 1)
	underscore := filesTestFile(t, st, areaID, areaTag, ada, "a_b.txt", 1)
	filesTestFile(t, st, areaID, areaTag, ada, "axb.txt", 1)

	// "%" and "_" must match literally, not as LIKE wildcards.
	hits, err := st.SearchFiles([]string{areaID}, "%", 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 || hits[0].ID != percent.ID {
		t.Fatalf("percent search = %+v", hits)
	}
	hits, err = st.SearchFiles([]string{areaID}, "a_b", 10)
	if err != nil || len(hits) != 1 || hits[0].ID != underscore.ID {
		t.Fatalf("underscore search = %+v, %v", hits, err)
	}
	// Descriptions are searched too.
	if _, err := st.DB().Exec(`UPDATE files SET description = 'retro terminal art' WHERE id = ?`, underscore.ID); err != nil {
		t.Fatal(err)
	}
	hits, err = st.SearchFiles([]string{areaID}, "terminal", 10)
	if err != nil || len(hits) != 1 || hits[0].ID != underscore.ID {
		t.Fatalf("description search = %+v, %v", hits, err)
	}
	if hits, err := st.SearchFiles(nil, "plain", 10); err != nil || len(hits) != 0 {
		t.Fatalf("empty area set = %+v, %v", hits, err)
	}
}
