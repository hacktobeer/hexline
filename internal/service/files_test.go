package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/store"
)

// filesTestConfig builds a config whose upload root is a temp directory.
func filesTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default()
	dataDir := t.TempDir()
	cfg.Server.DataDir = dataDir
	cfg.Storage.FilesDir = filepath.Join(dataDir, "files")
	cfg.Storage.MaxUploadBytes = 64 << 10
	cfg.Limits.UploadQuotaBytes = 1 << 20
	return cfg
}

func filesTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "files.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
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

func filesTestUser(t *testing.T, st *store.Store, handle string, role domain.Role, status domain.Status, guest bool) *domain.User {
	t.Helper()
	u := &domain.User{Handle: handle, Role: role, Status: status, PassHash: "x", IsGuest: guest}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("create user %s: %v", handle, err)
	}
	return u
}

type filesFixture struct {
	files *Files
	st    *store.Store
	cfg   *config.Config
	user  *domain.User
	root  string
}

func filesTestFixture(t *testing.T) *filesFixture {
	t.Helper()
	cfg := filesTestConfig(t)
	st := filesTestStore(t)
	return &filesFixture{
		files: NewFiles(st, cfg),
		st:    st,
		cfg:   cfg,
		user:  filesTestUser(t, st, "ada", domain.RoleUser, domain.StatusActive, false),
		root:  cfg.FilesPath(),
	}
}

// filesDiskFiles lists regular files under root (empty when root is absent).
func filesDiskFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.Mode().IsRegular() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func filesTestUpload(t *testing.T, fx *filesFixture, area, name, desc string, content []byte) *domain.File {
	t.Helper()
	f, err := fx.files.Upload(context.Background(), fx.user, area, name, desc, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("upload %q: %v", name, err)
	}
	return f
}

func TestUploadStoresServerNameChecksumAndPermissions(t *testing.T) {
	fx := filesTestFixture(t)
	content := []byte("hello hexline\n")
	f := filesTestUpload(t, fx, "uploads", "hello.txt", "a greeting", content)

	if f.Filename != "hello.txt" || f.AreaTag != "uploads" || f.Uploader != "ada" {
		t.Fatalf("unexpected metadata: %+v", f)
	}
	want := sha256.Sum256(content)
	if f.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 = %q", f.SHA256)
	}
	if f.SizeBytes != int64(len(content)) {
		t.Fatalf("size = %d", f.SizeBytes)
	}
	// The stored path is server-generated and never contains the user name.
	disk := filepath.Join(fx.root, f.StoredPath)
	if !strings.HasPrefix(disk, fx.root+string(os.PathSeparator)) {
		t.Fatalf("stored path %q escapes %q", disk, fx.root)
	}
	if strings.Contains(f.StoredPath, "hello") {
		t.Fatalf("stored path %q leaks the user filename", f.StoredPath)
	}
	data, err := os.ReadFile(disk)
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Fatalf("stored content = %q", data)
	}
	info, err := os.Stat(disk)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("file mode = %o, want 640", got)
	}
	dirInfo, err := os.Stat(filepath.Join(fx.root, "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o750 {
		t.Fatalf("area dir mode = %o, want 750", got)
	}

	detail, err := fx.files.File(context.Background(), fx.user, f.ID)
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	if detail.Description != "a greeting" || detail.SHA256 != f.SHA256 {
		t.Fatalf("detail mismatch: %+v", detail)
	}
	if detail.DownloadCount != 0 || detail.RatingCount != 0 {
		t.Fatalf("fresh file counters: %+v", detail)
	}
}

func TestUploadRejectsTraversal(t *testing.T) {
	fx := filesTestFixture(t)
	ctx := context.Background()
	names := []string{
		"../../etc/passwd",
		"../../../tmp/escape.bin",
		"a/b",
		"/etc/passwd",
		"..",
		".",
		"",
		"..\\x",
		`C:\windows\system32\evil.dll`,
		"....//x",
		"nested/../../x",
		strings.Repeat("a", filesMaxNameRunes+1),
	}
	for _, name := range names {
		_, err := fx.files.Upload(ctx, fx.user, "uploads", name, "", bytes.NewReader([]byte("x")), 1)
		if err == nil {
			t.Fatalf("upload %q was accepted", name)
		}
		if !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("upload %q error = %v, want ErrInvalid", name, err)
		}
	}
	if got := filesDiskFiles(t, fx.root); len(got) != 0 {
		t.Fatalf("failed uploads left files behind: %v", got)
	}
	parent := filepath.Dir(fx.root)
	if _, err := os.Stat(filepath.Join(parent, "passwd")); err == nil {
		t.Fatal("traversal attempt created a file outside the files root")
	}

	// Downloads take the same name check: no spec may address a path.
	if _, _, err := fx.files.OpenDownload(ctx, fx.user, "uploads", "../../etc/passwd"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("download traversal error = %v, want ErrInvalid", err)
	}
}

func TestUploadRejectsSymlinkedAreaDir(t *testing.T) {
	fx := filesTestFixture(t)
	outside := t.TempDir()
	if err := os.MkdirAll(fx.root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(fx.root, "uploads")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := fx.files.Upload(context.Background(), fx.user, "uploads", "escape.txt", "",
		bytes.NewReader([]byte("x")), 1)
	if !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("symlinked area dir error = %v, want ErrPermission", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("upload escaped through a symlink: %v", entries)
	}
}

func TestUploadEnforcesSizeCap(t *testing.T) {
	fx := filesTestFixture(t)
	ctx := context.Background()
	for _, size := range []int64{0, -1, fx.cfg.Storage.MaxUploadBytes + 1} {
		_, err := fx.files.Upload(ctx, fx.user, "uploads", "big.bin", "", bytes.NewReader([]byte("x")), size)
		if !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("size %d error = %v, want ErrInvalid", size, err)
		}
	}
	// A stream longer than the declared size is rejected mid-upload.
	_, err := fx.files.Upload(ctx, fx.user, "uploads", "liar.bin", "",
		bytes.NewReader(bytes.Repeat([]byte("x"), 100)), 10)
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("oversized stream error = %v, want ErrInvalid", err)
	}
	if got := filesDiskFiles(t, fx.root); len(got) != 0 {
		t.Fatalf("aborted upload left files behind: %v", got)
	}
}

func TestUploadEnforcesQuota(t *testing.T) {
	fx := filesTestFixture(t)
	fx.cfg.Limits.UploadQuotaBytes = 100
	ctx := context.Background()

	filesTestUpload(t, fx, "uploads", "one.bin", "", bytes.Repeat([]byte("a"), 60))
	used, quota, err := fx.files.Usage(ctx, fx.user)
	if err != nil || used != 60 || quota != 100 {
		t.Fatalf("usage = %d/%d, %v", used, quota, err)
	}
	_, err = fx.files.Upload(ctx, fx.user, "uploads", "two.bin", "",
		bytes.NewReader(bytes.Repeat([]byte("b"), 50)), 50)
	if !errors.Is(err, domain.ErrQuota) {
		t.Fatalf("quota error = %v, want ErrQuota", err)
	}
	// Exactly filling the quota is allowed.
	filesTestUpload(t, fx, "uploads", "three.bin", "", bytes.Repeat([]byte("c"), 40))
	used, _, err = fx.files.Usage(ctx, fx.user)
	if err != nil || used != 100 {
		t.Fatalf("usage after fill = %d, %v", used, err)
	}
}

func TestUploadPermissionGates(t *testing.T) {
	fx := filesTestFixture(t)
	ctx := context.Background()
	probation := filesTestUser(t, fx.st, "newbie", domain.RoleUser, domain.StatusProbation, false)
	suspended := filesTestUser(t, fx.st, "banned", domain.RoleUser, domain.StatusSuspended, false)
	guest := &domain.User{Handle: "guest", IsGuest: true, Status: domain.StatusActive, Role: domain.RoleUser}

	cases := []struct {
		user *domain.User
		want error
	}{
		{probation, domain.ErrProbation},
		{guest, domain.ErrPermission},
		{suspended, domain.ErrPermission},
		{nil, domain.ErrPermission},
	}
	for _, tc := range cases {
		_, err := fx.files.Upload(ctx, tc.user, "uploads", "x.txt", "", bytes.NewReader([]byte("x")), 1)
		if !errors.Is(err, tc.want) {
			t.Fatalf("upload as %+v error = %v, want %v", tc.user, err, tc.want)
		}
	}

	// Area ACL: an area whose upload ACL is sysop-only refuses regular users.
	if _, err := fx.st.DB().Exec(`INSERT INTO file_areas(id, tag, name, description, sort_order,
		acl_read, acl_upload, quota_bytes, created_at)
		VALUES ('sysarea', 'sysonly', 'Sysop files', '', 50, 'sysop', 'sysop', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.files.Upload(ctx, fx.user, "sysonly", "x.txt", "", bytes.NewReader([]byte("x")), 1); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("sysop-only upload error = %v, want ErrPermission", err)
	}
	sysop := filesTestUser(t, fx.st, "root", domain.RoleSysop, domain.StatusActive, false)
	if _, err := fx.files.Upload(ctx, sysop, "sysonly", "x.txt", "", bytes.NewReader([]byte("x")), 1); err != nil {
		t.Fatalf("sysop upload: %v", err)
	}
	// The sysop-only area is invisible to regular callers.
	areas, err := fx.files.Areas(ctx, fx.user)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range areas {
		if a.Tag == "sysonly" {
			t.Fatal("sysop-only area leaked into a regular caller's area list")
		}
	}
	if _, err := fx.files.Files(ctx, fx.user, "sysonly", 10, 0); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("listing sysop-only area error = %v, want ErrPermission", err)
	}
}

func TestOpenDownloadCountsAndFindsMissingFiles(t *testing.T) {
	fx := filesTestFixture(t)
	ctx := context.Background()
	content := []byte("payload bytes")
	f := filesTestUpload(t, fx, "uploads", "payload.bin", "", content)

	rc, got, err := fx.files.OpenDownload(ctx, fx.user, "uploads", "payload.bin")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	data, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(data, content) {
		t.Fatalf("download content = %q, %v", data, err)
	}
	if got.ID != f.ID || got.DownloadCount != 1 {
		t.Fatalf("download metadata: %+v", got)
	}
	// Case-insensitive spec, like the store lookup.
	rc, _, err = fx.files.OpenDownload(ctx, fx.user, "UPLOADS", "PAYLOAD.BIN")
	if err != nil {
		t.Fatalf("case-insensitive download: %v", err)
	}
	rc.Close()

	var count int
	if err := fx.st.DB().QueryRow(`SELECT download_count FROM files WHERE id = ?`, f.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("download_count = %d, want 2", count)
	}
	var rows int
	if err := fx.st.DB().QueryRow(`SELECT COUNT(*) FROM file_downloads WHERE file_id = ?`, f.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("file_downloads rows = %d, want 2", rows)
	}

	// Soft delete hides the file from downloads.
	if err := fx.st.SoftDeleteFile(f.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fx.files.OpenDownload(ctx, fx.user, "uploads", "payload.bin"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted download error = %v, want ErrNotFound", err)
	}

	// A row whose content vanished reports a clear not-found.
	f2 := filesTestUpload(t, fx, "uploads", "lost.bin", "", []byte("gone"))
	if err := os.Remove(filepath.Join(fx.root, f2.StoredPath)); err != nil {
		t.Fatal(err)
	}
	_, _, err = fx.files.OpenDownload(ctx, fx.user, "uploads", "lost.bin")
	if !errors.Is(err, domain.ErrNotFound) || !strings.Contains(err.Error(), "missing on disk") {
		t.Fatalf("missing content error = %v", err)
	}
}

func TestRateUpsertsAndValidates(t *testing.T) {
	fx := filesTestFixture(t)
	ctx := context.Background()
	f := filesTestUpload(t, fx, "uploads", "rated.zip", "", []byte("zip"))

	if err := fx.files.Rate(ctx, fx.user, f.ID, 0); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("rating 0 error = %v", err)
	}
	if err := fx.files.Rate(ctx, fx.user, f.ID, 6); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("rating 6 error = %v", err)
	}
	if err := fx.files.Rate(ctx, fx.user, f.ID, 5); err != nil {
		t.Fatalf("rate: %v", err)
	}
	if err := fx.files.Rate(ctx, fx.user, f.ID, 3); err != nil {
		t.Fatalf("rerate: %v", err)
	}
	got, err := fx.files.File(ctx, fx.user, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rating != 3 || got.RatingCount != 1 {
		t.Fatalf("rating aggregate = %v (%d)", got.Rating, got.RatingCount)
	}
	guest := &domain.User{Handle: "guest", IsGuest: true, Status: domain.StatusActive, Role: domain.RoleUser}
	if err := fx.files.Rate(ctx, guest, f.ID, 4); !errors.Is(err, domain.ErrPermission) {
		t.Fatalf("guest rating error = %v", err)
	}
}

func TestFileSearchMatchesNamesAndDescriptions(t *testing.T) {
	fx := filesTestFixture(t)
	ctx := context.Background()
	filesTestUpload(t, fx, "uploads", "hello.txt", "greeting", []byte("a"))
	percent := filesTestUpload(t, fx, "uploads", "100% done.txt", "", []byte("b"))
	filesTestUpload(t, fx, "uploads", "notes.txt", "retro terminal art", []byte("c"))

	hits, err := fx.files.Search(ctx, fx.user, "hello", 10)
	if err != nil || len(hits) != 1 || hits[0].Filename != "hello.txt" {
		t.Fatalf("name search = %+v, %v", hits, err)
	}
	hits, err = fx.files.Search(ctx, fx.user, "terminal", 10)
	if err != nil || len(hits) != 1 || hits[0].Filename != "notes.txt" {
		t.Fatalf("description search = %+v, %v", hits, err)
	}
	// LIKE wildcards are literal.
	hits, err = fx.files.Search(ctx, fx.user, "%", 10)
	if err != nil || len(hits) != 1 || hits[0].ID != percent.ID {
		t.Fatalf("percent search = %+v, %v", hits, err)
	}
	if _, err := fx.files.Search(ctx, fx.user, "   ", 10); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("empty search error = %v", err)
	}
}

func TestUploadSanitizesText(t *testing.T) {
	fx := filesTestFixture(t)
	f := filesTestUpload(t, fx, "uploads", "bad\x1b[31m.txt", "desc\x1b[0m here", []byte("x"))
	if strings.ContainsRune(f.Filename, 0x1b) || strings.ContainsRune(f.Description, 0x1b) {
		t.Fatalf("control characters survived sanitising: %+v", f)
	}
	if f.Filename != "bad[31m.txt" {
		t.Fatalf("filename = %q", f.Filename)
	}
	long := strings.Repeat("d", filesMaxDescRunes+1)
	if _, err := fx.files.Upload(context.Background(), fx.user, "uploads", "ok.txt", long,
		bytes.NewReader([]byte("x")), 1); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("long description error = %v", err)
	}
}

func TestUploadExtensionPolicy(t *testing.T) {
	fx := filesTestFixture(t)
	ctx := context.Background()
	fx.cfg.Storage.AllowedExt = []string{".txt"}
	_, err := fx.files.Upload(ctx, fx.user, "uploads", "tool.zip", "", bytes.NewReader([]byte("z")), 1)
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("disallowed extension error = %v, want ErrInvalid", err)
	}
	// The configured list is case-insensitive and may omit the leading dot.
	fx.cfg.Storage.AllowedExt = []string{"txt"}
	if _, err := fx.files.Upload(ctx, fx.user, "uploads", "notes.TXT", "", bytes.NewReader([]byte("n")), 1); err != nil {
		t.Fatalf("allowed extension rejected: %v", err)
	}
}
