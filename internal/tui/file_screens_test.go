package tui

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/config"
	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/service"
	"github.com/hacktobeer/hexline/internal/store"
)

// filesTestApp builds an App wired to a real temp store and file service.
func filesTestApp(t *testing.T) (*App, *service.Files, *domain.User) {
	t.Helper()
	cfg := config.Default()
	dataDir := t.TempDir()
	cfg.Server.DataDir = dataDir
	cfg.Storage.FilesDir = filepath.Join(dataDir, "files")
	cfg.Storage.MaxUploadBytes = 64 << 10
	cfg.Limits.UploadQuotaBytes = 1 << 20

	st, err := store.Open(filepath.Join(t.TempDir(), "tui.db"))
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
	user := &domain.User{Handle: "ada", Role: domain.RoleUser, Status: domain.StatusActive, PassHash: "x"}
	if err := st.CreateUser(user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	files := service.NewFiles(st, cfg)
	a := &App{
		Cfg: cfg, Store: st, Files: files,
		Sess: &Session{User: user, Node: 1},
		W:    80, H: 24,
	}
	return a, files, user
}

func filesTestUpload(t *testing.T, a *App, files *service.Files, user *domain.User, name, desc string, content []byte) *domain.File {
	t.Helper()
	f, err := files.Upload(context.Background(), user, "uploads", name, desc,
		strings.NewReader(string(content)), int64(len(content)))
	if err != nil {
		t.Fatalf("upload %q: %v", name, err)
	}
	return f
}

func filesTestArea(t *testing.T, files *service.Files, user *domain.User) domain.FileArea {
	t.Helper()
	areas, err := files.Areas(context.Background(), user)
	if err != nil {
		t.Fatalf("areas: %v", err)
	}
	for _, area := range areas {
		if area.Tag == "uploads" {
			return area
		}
	}
	t.Fatal("seeded uploads area missing")
	return domain.FileArea{}
}

func filesTestRun(t *testing.T, cmd tea.Cmd) tea.Msg {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected a tea.Cmd")
	}
	return cmd()
}

func TestFileAreaListViewAndNavigation(t *testing.T) {
	a, files, user := filesTestApp(t)
	filesTestUpload(t, a, files, user, "hello.txt", "", []byte("hello hexline"))

	s := newFileAreaList(a, nil)
	s.Update(a, filesTestRun(t, s.Init(a)))
	view := s.View(a)
	for _, want := range []string{"File areas", "uploads", "Uploads", "1 file"} {
		if !strings.Contains(view, want) {
			t.Fatalf("area list view missing %q:\n%s", want, view)
		}
	}

	// Enter on the only area navigates to its file list.
	msg := s.Update(a, tea.KeyMsg{Type: tea.KeyEnter})
	if msg == nil {
		t.Fatal("enter produced no command")
	}
	nav, ok := filesTestRun(t, msg).(NavigateMsg)
	if !ok || nav.Route != RouteFileList {
		t.Fatalf("enter navigation = %#v", nav)
	}
	arg, ok := nav.Arg.(filesArg)
	if !ok || arg.Tag != "uploads" || arg.ID == "" {
		t.Fatalf("navigation arg = %#v", nav.Arg)
	}
}

func TestFileListViewShowsMetadata(t *testing.T) {
	a, files, user := filesTestApp(t)
	filesTestUpload(t, a, files, user, "hello.txt", "a greeting", []byte("hello hexline"))
	area := filesTestArea(t, files, user)

	s := newFileList(a, filesArg{ID: area.ID, Tag: area.Tag, Name: area.Name})
	s.Update(a, filesTestRun(t, s.Init(a)))
	view := s.View(a)
	for _, want := range []string{"hello.txt", "ada", "dl", "unrated"} {
		if !strings.Contains(view, want) {
			t.Fatalf("file list view missing %q:\n%s", want, view)
		}
	}

	// Enter opens the detail screen for the selected file.
	msg := s.Update(a, tea.KeyMsg{Type: tea.KeyEnter})
	nav, ok := filesTestRun(t, msg).(NavigateMsg)
	if !ok || nav.Route != RouteFileDetail {
		t.Fatalf("detail navigation = %#v", nav)
	}
	if arg, ok := nav.Arg.(filesDetailArg); !ok || arg.ID == "" {
		t.Fatalf("detail arg = %#v", nav.Arg)
	}
}

func TestFileDetailViewShowsChecksumAndPipeCommand(t *testing.T) {
	a, files, user := filesTestApp(t)
	f := filesTestUpload(t, a, files, user, "hello.txt", "a greeting for callers", []byte("hello hexline"))

	s := newFileDetail(a, filesDetailArg{ID: f.ID})
	s.Update(a, filesTestRun(t, s.Init(a)))
	view := s.View(a)
	for _, want := range []string{
		"hello.txt",
		f.SHA256,
		"a greeting for callers",
		"Uploaded",
		"ada",
		"ssh bbs get uploads/hello.txt > hello.txt",
		"13 B",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("detail view missing %q:\n%s", want, view)
		}
	}

	// Rate from the detail screen: r, 5, enter refreshes the metadata.
	if cmd := s.Update(a, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")}); cmd != nil {
		t.Fatalf("r should only open the rating prompt")
	}
	s.Update(a, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("5")})
	cmd := s.Update(a, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("rating produced no command")
	}
	s.Update(a, filesTestRun(t, cmd))
	if view := s.View(a); !strings.Contains(view, "5.0 (1)") {
		t.Fatalf("rating not reflected:\n%s", view)
	}
}

func TestUploadScreenExplainsPipeAndQuota(t *testing.T) {
	a, files, user := filesTestApp(t)
	filesTestUpload(t, a, files, user, "hello.txt", "", []byte("0123456789"))
	area := filesTestArea(t, files, user)

	s := newUploadScreen(a, filesArg{ID: area.ID, Tag: area.Tag, Name: area.Name})
	s.Update(a, filesTestRun(t, s.Init(a)))
	view := s.View(a)
	for _, want := range []string{
		"ssh bbs put uploads/FILE < local-file",
		"max size",
		"your quota",
		"10 B of 1.0 MiB",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("upload view missing %q:\n%s", want, view)
		}
	}
}
