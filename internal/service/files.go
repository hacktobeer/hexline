package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/render"
	"github.com/hacktobeer/hexline/internal/store"
)

// Limits for the file slice. They are deliberately code constants: upload
// policy knobs live in config (size and quota), field caps do not.
const (
	filesMaxNameRunes   = 100
	filesMaxDescRunes   = 500
	filesDefaultPage    = 20
	filesMaxPage        = 100
	filesDefaultSearch  = 50
	filesUploadTempMask = ".upload-*"
)

// Files implements file areas, uploads, downloads and ratings.
type Files struct {
	st  *store.Store
	cfg *config.Config
}

// NewFiles wires the file service.
func NewFiles(st *store.Store, cfg *config.Config) *Files {
	return &Files{st: st, cfg: cfg}
}

// Areas lists file areas the caller may read, in display order.
func (f *Files) Areas(ctx context.Context, u *domain.User) ([]domain.FileArea, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	all, err := f.st.ListFileAreas()
	if err != nil {
		return nil, err
	}
	role := filesRole(u)
	out := make([]domain.FileArea, 0, len(all))
	for _, a := range all {
		if a.ACL.CanRead(role) {
			out = append(out, a)
		}
	}
	return out, nil
}

// AreaCounts returns non-deleted file counts for the areas the caller may read.
func (f *Files) AreaCounts(ctx context.Context, u *domain.User) (map[string]int, error) {
	areas, err := f.Areas(ctx, u)
	if err != nil {
		return nil, err
	}
	all, err := f.st.FileAreaCounts()
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(areas))
	for _, a := range areas {
		out[a.ID] = all[a.ID]
	}
	return out, nil
}

// Files lists one page of an area's non-deleted files.
func (f *Files) Files(ctx context.Context, u *domain.User, areaID string, limit, offset int) ([]domain.File, error) {
	area, err := f.area(ctx, u, areaID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = filesDefaultPage
	}
	if limit > filesMaxPage {
		limit = filesMaxPage
	}
	if offset < 0 {
		offset = 0
	}
	return f.st.ListFiles(area.ID, limit, offset)
}

// File returns one file's full metadata if the caller may read its area.
func (f *Files) File(ctx context.Context, u *domain.User, id string) (*domain.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := f.st.FileByID(strings.TrimSpace(id))
	if err != nil {
		return nil, err
	}
	if _, err := f.area(ctx, u, file.AreaID); err != nil {
		return nil, err
	}
	return file, nil
}

// filesUploadLocks serialize the quota check + rename + insert per user.
// Striped so two different callers can still upload at the same time.
var filesUploadLocks [64]sync.Mutex

func filesUploadLock(userID string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(userID))
	return &filesUploadLocks[h.Sum32()%uint32(len(filesUploadLocks))]
}

// Upload stores a file of a known size under <root>/<area tag>/<ulid>.
func (f *Files) Upload(ctx context.Context, u *domain.User, areaTag, filename, description string,
	r io.Reader, size int64) (*domain.File, error) {
	if size <= 0 {
		return nil, fmt.Errorf("%w: upload size must be greater than zero", domain.ErrInvalid)
	}
	if max := f.cfg.Storage.MaxUploadBytes; max > 0 && size > max {
		return nil, fmt.Errorf("%w: upload is %d bytes, limit is %d", domain.ErrInvalid, size, max)
	}
	// One byte past the declared size catches a lying caller.
	return f.receive(ctx, u, areaTag, filename, description, io.LimitReader(r, size+1), size)
}

// UploadStream stores a file whose size is not known up front (the `ssh put`
// pipe). It stops reading at the configured maximum and uses the bytes it saw.
func (f *Files) UploadStream(ctx context.Context, u *domain.User, areaTag, filename, description string,
	r io.Reader, maxBytes int64) (*domain.File, error) {
	if maxBytes <= 0 {
		maxBytes = f.cfg.Storage.MaxUploadBytes
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("%w: no upload size limit configured", domain.ErrUnavailable)
	}
	return f.receive(ctx, u, areaTag, filename, description, io.LimitReader(r, maxBytes+1), -1)
}

// receive owns the single write of an upload: validate, stream to a temp file
// while hashing, enforce the quota under a per-user lock, rename, insert.
func (f *Files) receive(ctx context.Context, u *domain.User, areaTag, filename, description string,
	r io.Reader, expected int64) (*domain.File, error) {
	if err := filesUploader(u); err != nil {
		return nil, err
	}
	area, err := f.areaByTag(ctx, areaTag)
	if err != nil {
		return nil, err
	}
	if !area.ACL.CanPost(filesRole(u)) {
		return nil, fmt.Errorf("%w: you may not upload to this area", domain.ErrPermission)
	}
	name, err := filesFilename(filename)
	if err != nil {
		return nil, err
	}
	if err := filesExtensionAllowed(f.cfg, name); err != nil {
		return nil, err
	}
	desc, err := filesDescription(description)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("%w: no content provided", domain.ErrInvalid)
	}
	max := f.cfg.Storage.MaxUploadBytes
	quota := f.cfg.Limits.UploadQuotaBytes
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	root, err := filesRoot(f.cfg)
	if err != nil {
		return nil, err
	}
	dir, err := filesAreaDir(root, area.Tag)
	if err != nil {
		return nil, err
	}
	id := store.NewFileID()
	final := filepath.Join(dir, id)
	if !filesInside(root, final) {
		return nil, fmt.Errorf("%w: upload path escapes the files root", domain.ErrPermission)
	}
	tmp, err := os.CreateTemp(dir, filesUploadTempMask)
	if err != nil {
		return nil, fmt.Errorf("files: create upload: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o640); err != nil {
		cleanup()
		return nil, fmt.Errorf("files: set upload permissions: %w", err)
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hasher), r)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("files: write upload: %w", err)
	}
	if expected >= 0 && written != expected {
		cleanup()
		return nil, fmt.Errorf("%w: expected %d bytes, received %d", domain.ErrInvalid, expected, written)
	}
	if written == 0 {
		cleanup()
		return nil, fmt.Errorf("%w: upload is empty", domain.ErrInvalid)
	}
	if max > 0 && written > max {
		cleanup()
		return nil, fmt.Errorf("%w: upload exceeds the %d byte limit", domain.ErrInvalid, max)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return nil, fmt.Errorf("files: sync upload: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("files: close upload: %w", err)
	}

	// The quota check happens under the user's lock, after the bytes are
	// known, so concurrent uploads cannot both pass an outdated total.
	lock := filesUploadLock(u.ID)
	lock.Lock()
	defer lock.Unlock()
	used, err := f.st.UserUploadBytes(u.ID)
	if err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	if quota > 0 && used+written > quota {
		os.Remove(tmpName)
		return nil, fmt.Errorf("%w: %d of %d bytes used; this upload needs %d",
			domain.ErrQuota, used, quota, written)
	}
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return nil, fmt.Errorf("files: store upload: %w", err)
	}

	file := &domain.File{
		ID:            id,
		AreaID:        area.ID,
		AreaTag:       area.Tag,
		Filename:      name,
		StoredPath:    filepath.Join(area.Tag, id),
		SizeBytes:     written,
		SHA256:        hex.EncodeToString(hasher.Sum(nil)),
		Description:   desc,
		UploaderID:    u.ID,
		Uploader:      u.Handle,
		UploadedAt:    time.Now().UTC(),
		ScanStatus:    "clean",
		DownloadCount: 0,
	}
	if err := f.st.InsertFile(file); err != nil {
		os.Remove(final)
		return nil, err
	}
	return file, nil
}

// OpenDownload resolves "AREA/FILE" for the non-interactive `bbs get` pipe.
// The download is counted before the caller reads a single byte.
func (f *Files) OpenDownload(ctx context.Context, u *domain.User, areaTag, filename string) (io.ReadCloser, *domain.File, error) {
	if u == nil {
		return nil, nil, fmt.Errorf("%w: log in to download files", domain.ErrPermission)
	}
	area, err := f.areaByTag(ctx, areaTag)
	if err != nil {
		return nil, nil, err
	}
	if !area.ACL.CanRead(filesRole(u)) {
		return nil, nil, fmt.Errorf("%w: you may not read this area", domain.ErrPermission)
	}
	name, err := filesFilename(filename)
	if err != nil {
		return nil, nil, err
	}
	file, err := f.st.FileByAreaAndName(area.ID, name)
	if err != nil {
		return nil, nil, err
	}
	root, err := filesRoot(f.cfg)
	if err != nil {
		return nil, nil, err
	}
	path, err := filesResolve(root, file.StoredPath)
	if err != nil {
		return nil, nil, err
	}
	rc, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("%w: %q is missing on disk", domain.ErrNotFound, file.Filename)
		}
		return nil, nil, fmt.Errorf("files: open download: %w", err)
	}
	if err := f.st.RecordDownload(file.ID, u.ID, time.Now().UTC(), file.SizeBytes); err != nil {
		rc.Close()
		return nil, nil, err
	}
	file.DownloadCount++
	return rc, file, nil
}

// Rate stores a 1..5 star rating, replacing the caller's previous one.
func (f *Files) Rate(ctx context.Context, u *domain.User, fileID string, stars int) error {
	if u == nil || u.IsGuest {
		return fmt.Errorf("%w: log in to rate files", domain.ErrPermission)
	}
	if !u.CanWrite() {
		return fmt.Errorf("%w: this account may not rate files", domain.ErrPermission)
	}
	if stars < 1 || stars > 5 {
		return fmt.Errorf("%w: rating must be between 1 and 5", domain.ErrInvalid)
	}
	file, err := f.File(ctx, u, fileID)
	if err != nil {
		return err
	}
	return f.st.UpsertRating(file.ID, u.ID, stars, time.Now().UTC())
}

// Search matches filenames and descriptions across readable areas.
func (f *Files) Search(ctx context.Context, u *domain.User, query string, limit int) ([]domain.File, error) {
	q := strings.TrimSpace(render.SanitizeLine(query))
	if q == "" {
		return nil, fmt.Errorf("%w: a search term is required", domain.ErrInvalid)
	}
	if limit <= 0 {
		limit = filesDefaultSearch
	}
	if limit > filesMaxPage {
		limit = filesMaxPage
	}
	areas, err := f.Areas(ctx, u)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(areas))
	for _, a := range areas {
		ids = append(ids, a.ID)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return f.st.SearchFiles(ids, q, limit)
}

// Usage reports the caller's non-deleted upload bytes and the configured
// per-user quota (0 means unlimited).
func (f *Files) Usage(ctx context.Context, u *domain.User) (used, quota int64, err error) {
	quota = f.cfg.Limits.UploadQuotaBytes
	if u == nil || u.ID == "" {
		return 0, quota, ctx.Err()
	}
	used, err = f.st.UserUploadBytes(u.ID)
	return used, quota, err
}

// --- internals ---

func filesRole(u *domain.User) domain.Role {
	if u == nil || !u.Role.Valid() {
		return domain.RoleUser
	}
	return u.Role
}

// filesUploader enforces D3: probation accounts and guests may not upload.
func filesUploader(u *domain.User) error {
	if u == nil {
		return fmt.Errorf("%w: log in to upload files", domain.ErrPermission)
	}
	if u.IsGuest {
		return fmt.Errorf("%w: guests may not upload files", domain.ErrPermission)
	}
	if u.IsProbation() {
		return fmt.Errorf("%w: uploads unlock after probation", domain.ErrProbation)
	}
	if !u.CanWrite() {
		return fmt.Errorf("%w: this account may not upload files", domain.ErrPermission)
	}
	return nil
}

// filesFilename normalises a user-supplied name and rejects anything that
// could be read as a path.
func filesFilename(name string) (string, error) {
	name = render.SanitizeLine(name)
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("%w: a filename is required", domain.ErrInvalid)
	}
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("%w: filename must not contain path separators", domain.ErrInvalid)
	}
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("%w: filename must not contain %q", domain.ErrInvalid, "..")
	}
	if base := filepath.Base(name); base != name {
		return "", fmt.Errorf("%w: filename must be a plain name", domain.ErrInvalid)
	}
	if utf8.RuneCountInString(name) > filesMaxNameRunes {
		return "", fmt.Errorf("%w: filename is longer than %d characters", domain.ErrInvalid, filesMaxNameRunes)
	}
	return name, nil
}

// filesExtensionAllowed applies storage.allowed_ext when the operator sets it.
// An empty list means every extension is accepted.
func filesExtensionAllowed(cfg *config.Config, name string) error {
	allowed := cfg.Storage.AllowedExt
	if len(allowed) == 0 {
		return nil
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	for _, want := range allowed {
		if strings.ToLower(strings.TrimSpace(strings.TrimPrefix(want, "."))) == ext {
			return nil
		}
	}
	return fmt.Errorf("%w: files of type .%s are not accepted here", domain.ErrInvalid, ext)
}

// filesDescription sanitises and caps the free-text description.
func filesDescription(desc string) (string, error) {
	desc = strings.TrimSpace(render.Sanitize(desc))
	if utf8.RuneCountInString(desc) > filesMaxDescRunes {
		return "", fmt.Errorf("%w: description is longer than %d characters", domain.ErrInvalid, filesMaxDescRunes)
	}
	return desc, nil
}

// filesRoot returns the absolute, symlink-resolved upload root, creating it.
func filesRoot(cfg *config.Config) (string, error) {
	root := cfg.FilesPath()
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", fmt.Errorf("files: create upload root: %w", err)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("files: resolve upload root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("files: resolve upload root: %w", err)
	}
	return resolved, nil
}

// filesInside reports whether path is root itself or a descendant.
func filesInside(root, path string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(os.PathSeparator))
}

// filesAreaDir creates and resolves <root>/<tag>, refusing tags or symlinks
// that resolve outside the root.
func filesAreaDir(root, tag string) (string, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" || tag == "." || tag == ".." ||
		strings.ContainsAny(tag, `/\`) || strings.Contains(tag, "..") {
		return "", fmt.Errorf("%w: invalid file area tag", domain.ErrInvalid)
	}
	dir := filepath.Join(root, tag)
	if !filesInside(root, dir) {
		return "", fmt.Errorf("%w: file area path escapes the files root", domain.ErrPermission)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("files: create area dir: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("files: resolve area dir: %w", err)
	}
	if !filesInside(root, resolved) {
		return "", fmt.Errorf("%w: file area path escapes the files root", domain.ErrPermission)
	}
	return resolved, nil
}

// filesResolve turns a stored relative path into an absolute path inside the
// root, or reports ErrNotFound when it is missing or unsafe.
func filesResolve(root, stored string) (string, error) {
	if stored == "" || filepath.IsAbs(stored) {
		return "", fmt.Errorf("%w: invalid stored path", domain.ErrNotFound)
	}
	clean := filepath.Clean(stored)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: invalid stored path", domain.ErrNotFound)
	}
	path := filepath.Join(root, clean)
	if !filesInside(root, path) {
		return "", fmt.Errorf("%w: stored path escapes the files root", domain.ErrNotFound)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: the stored copy of this file is missing on disk", domain.ErrNotFound)
		}
		return "", fmt.Errorf("files: resolve stored path: %w", err)
	}
	if !filesInside(root, resolved) {
		return "", fmt.Errorf("%w: stored path escapes the files root", domain.ErrNotFound)
	}
	return resolved, nil
}

// areaByTag resolves an area without an ACL decision (used where the caller
// checks a specific capability, such as upload).
func (f *Files) areaByTag(ctx context.Context, tag string) (*domain.FileArea, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, fmt.Errorf("%w: a file area is required", domain.ErrInvalid)
	}
	return f.st.FileAreaByTag(tag)
}

// area resolves an area by ID or tag and enforces read access.
func (f *Files) area(ctx context.Context, u *domain.User, idOrTag string) (*domain.FileArea, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	idOrTag = strings.TrimSpace(idOrTag)
	if idOrTag == "" {
		return nil, fmt.Errorf("%w: a file area is required", domain.ErrInvalid)
	}
	area, err := f.st.FileAreaByID(idOrTag)
	if errors.Is(err, domain.ErrNotFound) {
		area, err = f.st.FileAreaByTag(idOrTag)
	}
	if err != nil {
		return nil, err
	}
	if !area.ACL.CanRead(filesRole(u)) {
		return nil, fmt.Errorf("%w: you may not read this area", domain.ErrPermission)
	}
	return area, nil
}
