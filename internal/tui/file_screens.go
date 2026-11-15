package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/render"
)

// File screens: areas, listing, detail, upload. Transfers themselves happen
// over the SSH pipe (`ssh bbs get|put`); these screens only navigate, rate and
// explain (D2: no in-session binary protocols).

// filesArg carries a file area between screens.
type filesArg struct {
	ID    string
	Tag   string
	Name  string
	Count int
}

// ref returns the identifier the service resolves against (ID, else tag).
func (a filesArg) ref() string {
	if a.ID != "" {
		return a.ID
	}
	return a.Tag
}

// filesDetailArg carries one file between screens.
type filesDetailArg struct{ ID string }

func (a filesArg) displayName() string {
	switch {
	case a.Name != "" && a.Tag != "":
		return a.Name + " (" + a.Tag + ")"
	case a.Name != "":
		return a.Name
	default:
		return a.Tag
	}
}

// --- area list ---

type fileAreaListScreen struct {
	BaseScreen
	areas  []domain.FileArea
	counts map[string]int
	cursor int
	loaded bool
	err    error
}

type filesAreasMsg struct {
	areas  []domain.FileArea
	counts map[string]int
	err    error
}

func newFileAreaList(_ *App, _ any) Screen {
	return &fileAreaListScreen{BaseScreen: BaseScreen{
		Route: RouteFiles, TitleText: "File areas", Hints: "enter list files  esc back",
	}}
}

func (s *fileAreaListScreen) Init(a *App) tea.Cmd {
	return func() tea.Msg {
		if a.Files == nil {
			return filesAreasMsg{err: domain.ErrUnavailable}
		}
		ctx := context.Background()
		u := a.User()
		areas, err := a.Files.Areas(ctx, u)
		if err != nil {
			return filesAreasMsg{err: err}
		}
		counts, err := a.Files.AreaCounts(ctx, u)
		return filesAreasMsg{areas: areas, counts: counts, err: err}
	}
}

func (s *fileAreaListScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case filesAreasMsg:
		s.loaded = true
		s.err = m.err
		s.areas = m.areas
		s.counts = m.counts
		if s.cursor >= len(s.areas) {
			s.cursor = max(0, len(s.areas)-1)
		}
		return nil
	case tea.KeyMsg:
		switch m.String() {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down", "j":
			if s.cursor < len(s.areas)-1 {
				s.cursor++
			}
		case "enter":
			if s.cursor >= 0 && s.cursor < len(s.areas) {
				area := s.areas[s.cursor]
				arg := filesArg{ID: area.ID, Tag: area.Tag, Name: area.Name, Count: s.counts[area.ID]}
				return func() tea.Msg { return NavigateMsg{Route: RouteFileList, Arg: arg} }
			}
		}
	}
	return nil
}

func (s *fileAreaListScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, "File areas") + "\n")
	switch {
	case s.err != nil:
		b.WriteString(styleWarn.Render(render.Clip(friendlyError(s.err), w)) + "\n")
		return b.String()
	case !s.loaded:
		b.WriteString(styleDim.Render("loading…") + "\n")
		return b.String()
	case len(s.areas) == 0:
		b.WriteString(styleDim.Render("No file areas are available to you.") + "\n")
		return b.String()
	}
	height := max(1, a.BodyHeight()-3)
	start, end := filesWindow(s.cursor, len(s.areas), height)
	for i := start; i < end; i++ {
		area := s.areas[i]
		left := area.Tag + "  " + area.Name
		if area.Description != "" {
			left += " — " + area.Description
		}
		b.WriteString(ListRow(w, left, filesCount(s.counts[area.ID], "file"), i == s.cursor) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- file list ---

type fileListScreen struct {
	BaseScreen
	arg       filesArg
	files     []domain.File
	cursor    int
	offset    int
	limit     int
	query     string
	searching bool
	input     textinput.Model
	loaded    bool
	err       error
}

type filesListMsg struct {
	files  []domain.File
	offset int
	query  string
	err    error
}

func newFileList(_ *App, arg any) Screen {
	s := &fileListScreen{
		BaseScreen: BaseScreen{Route: RouteFileList, TitleText: "Files",
			Hints: "enter detail  u upload  / search  n/p page  esc back"},
		limit: 20,
	}
	if v, ok := arg.(filesArg); ok {
		s.arg = v
	}
	return s
}

func (s *fileListScreen) Init(a *App) tea.Cmd { return s.load(a) }

func (s *fileListScreen) load(a *App) tea.Cmd {
	areaID := s.arg.ref()
	offset, limit, query := s.offset, s.limit, s.query
	return func() tea.Msg {
		if a.Files == nil {
			return filesListMsg{offset: offset, query: query, err: domain.ErrUnavailable}
		}
		ctx := context.Background()
		u := a.User()
		var (
			files []domain.File
			err   error
		)
		if query != "" {
			files, err = a.Files.Search(ctx, u, query, limit)
		} else {
			files, err = a.Files.Files(ctx, u, areaID, limit, offset)
		}
		return filesListMsg{files: files, offset: offset, query: query, err: err}
	}
}

func (s *fileListScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case filesListMsg:
		if m.query != s.query {
			return nil // stale response from a superseded search
		}
		s.loaded = true
		s.err = m.err
		s.files = m.files
		s.offset = m.offset
		if s.cursor >= len(s.files) {
			s.cursor = max(0, len(s.files)-1)
		}
		return nil
	case tea.KeyMsg:
		key := m.String()
		if s.searching {
			switch key {
			case "enter":
				s.searching = false
				s.query = strings.TrimSpace(s.input.Value())
				s.offset = 0
				s.cursor = 0
				s.loaded = false
				return s.load(a)
			}
			var cmd tea.Cmd
			s.input, cmd = s.input.Update(msg)
			return cmd
		}
		switch key {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down", "j":
			if s.cursor < len(s.files)-1 {
				s.cursor++
			}
		case "n":
			if s.query == "" && len(s.files) == s.limit {
				s.offset += s.limit
				s.loaded = false
				return s.load(a)
			}
		case "p":
			if s.query == "" && s.offset > 0 {
				s.offset = max(0, s.offset-s.limit)
				s.loaded = false
				s.cursor = 0
				return s.load(a)
			}
		case "enter":
			if s.cursor >= 0 && s.cursor < len(s.files) {
				id := s.files[s.cursor].ID
				return func() tea.Msg {
					return NavigateMsg{Route: RouteFileDetail, Arg: filesDetailArg{ID: id}}
				}
			}
		case "u":
			tag := s.arg.Tag
			if tag == "" && s.cursor >= 0 && s.cursor < len(s.files) {
				tag = s.files[s.cursor].AreaTag
			}
			if tag != "" {
				arg := filesArg{ID: s.arg.ID, Tag: tag, Name: s.arg.Name}
				return func() tea.Msg { return NavigateMsg{Route: RouteUpload, Arg: arg} }
			}
		case "/":
			s.searching = true
			s.input = NewInput("filename or description", max(10, a.W-4))
			s.input.Focus()
			return nil
		}
	}
	return nil
}

func (s *fileListScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	header := "Files"
	if s.arg.displayName() != "" {
		header = "Files · " + s.arg.displayName()
	}
	b.WriteString(Section(w, header) + "\n")
	if s.query != "" {
		b.WriteString(styleDim.Render(render.Clip("search: "+s.query+"  (/ to change)", w)) + "\n")
	}
	if s.searching {
		b.WriteString(LabeledInput("search", s.input) + "\n")
	}
	switch {
	case s.err != nil:
		b.WriteString(styleWarn.Render(render.Clip(friendlyError(s.err), w)) + "\n")
		return b.String()
	case !s.loaded:
		b.WriteString(styleDim.Render("loading…") + "\n")
		return b.String()
	case len(s.files) == 0:
		b.WriteString(styleDim.Render("No files here yet. Press u to see how to upload.") + "\n")
		return b.String()
	}
	height := max(1, a.BodyHeight()-3)
	start, end := filesWindow(s.cursor, len(s.files), height)
	for i := start; i < end; i++ {
		f := s.files[i]
		left := f.Filename
		right := fmt.Sprintf("%s  %s  %s  %ddl  %s",
			filesSize(f.SizeBytes), f.Uploader, filesDate(f), f.DownloadCount, filesRating(f))
		b.WriteString(ListRow(w, left, right, i == s.cursor) + "\n")
	}
	if s.query == "" && (s.offset > 0 || len(s.files) == s.limit) {
		page := s.offset/s.limit + 1
		b.WriteString(styleDim.Render(fmt.Sprintf("page %d", page)) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- detail ---

type fileDetailScreen struct {
	BaseScreen
	arg     filesDetailArg
	file    *domain.File
	loaded  bool
	err     error
	rating  bool
	input   textinput.Model
	rateErr string
	desc    pager
}

type filesDetailMsg struct {
	file *domain.File
	err  error
}

// filesRateMsg reports a rating failure without discarding the detail view.
type filesRateMsg struct{ err error }

func newFileDetail(_ *App, arg any) Screen {
	s := &fileDetailScreen{BaseScreen: BaseScreen{
		Route: RouteFileDetail, TitleText: "File", Hints: "r rate  j/k scroll  esc back",
	}}
	if v, ok := arg.(filesDetailArg); ok {
		s.arg = v
	}
	return s
}

func (s *fileDetailScreen) Init(a *App) tea.Cmd { return s.load(a) }

func (s *fileDetailScreen) load(a *App) tea.Cmd {
	id := s.arg.ID
	return func() tea.Msg {
		if a.Files == nil {
			return filesDetailMsg{err: domain.ErrUnavailable}
		}
		f, err := a.Files.File(context.Background(), a.User(), id)
		return filesDetailMsg{file: f, err: err}
	}
}

func (s *fileDetailScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case filesDetailMsg:
		s.loaded = true
		s.file = m.file
		s.err = m.err
		s.rating = false
		s.rateErr = ""
		if m.file != nil && m.file.Description != "" {
			s.desc.SetText(m.file.Description, max(20, a.W-2), a.ANSI())
		}
		return nil
	case filesRateMsg:
		s.rateErr = friendlyError(m.err)
		return nil
	case tea.KeyMsg:
		key := m.String()
		if s.rating {
			switch key {
			case "enter":
				stars, err := strconv.Atoi(strings.TrimSpace(s.input.Value()))
				if err != nil || stars < 1 || stars > 5 {
					s.rateErr = "enter a whole number from 1 to 5"
					return nil
				}
				id := s.arg.ID
				return func() tea.Msg {
					if a.Files == nil {
						return filesRateMsg{err: domain.ErrUnavailable}
					}
					ctx := context.Background()
					u := a.User()
					if err := a.Files.Rate(ctx, u, id, stars); err != nil {
						return filesRateMsg{err: err}
					}
					f, err := a.Files.File(ctx, u, id)
					return filesDetailMsg{file: f, err: err}
				}
			}
			var cmd tea.Cmd
			s.input, cmd = s.input.Update(msg)
			return cmd
		}
		switch key {
		case "r":
			if s.file != nil {
				s.rating = true
				s.rateErr = ""
				s.input = NewInput("1-5", 8)
				s.input.Focus()
			}
		case "up", "k":
			s.desc.Move(-1, max(1, a.BodyHeight()-18))
		case "down", "j":
			s.desc.Move(1, max(1, a.BodyHeight()-18))
		}
	}
	return nil
}

func (s *fileDetailScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	switch {
	case s.err != nil:
		b.WriteString(Section(w, "File") + "\n")
		b.WriteString(styleWarn.Render(render.Clip(friendlyError(s.err), w)) + "\n")
		return b.String()
	case !s.loaded || s.file == nil:
		b.WriteString(Section(w, "File") + "\n")
		b.WriteString(styleDim.Render("loading…") + "\n")
		return b.String()
	}
	f := s.file
	b.WriteString(Section(w, render.Clip(f.Filename, w)) + "\n")
	line := func(label, value string) {
		b.WriteString(styleDim.Render(render.PadRight(label, 12)) + render.Clip(value, max(1, w-12)) + "\n")
	}
	line("Area", f.AreaTag)
	line("Size", filesSize(f.SizeBytes)+fmt.Sprintf(" (%d bytes)", f.SizeBytes))
	line("Uploaded", filesDate(*f)+" by "+f.Uploader)
	line("Downloads", strconv.Itoa(f.DownloadCount))
	line("Rating", filesRating(*f))
	line("SHA-256", f.SHA256)
	b.WriteString("\n")
	if f.Description != "" {
		b.WriteString(Section(w, "Description") + "\n")
		b.WriteString(s.desc.View(max(20, w-2), max(1, a.BodyHeight()-18)) + "\n\n")
	}
	b.WriteString(Section(w, "Download") + "\n")
	b.WriteString(styleDim.Render("Run this on your own machine (no in-session transfer, D2):") + "\n")
	b.WriteString("  " + filesDownloadCommand(a, f.AreaTag, f.Filename) + "\n")
	if s.rating {
		b.WriteString("\n" + LabeledInput("rating (1-5)", s.input) + "\n")
		if s.rateErr != "" {
			b.WriteString(styleWarn.Render(s.rateErr) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- upload help ---

type uploadScreen struct {
	BaseScreen
	arg    filesArg
	area   *domain.FileArea
	used   int64
	quota  int64
	loaded bool
	err    error
}

type filesUploadMsg struct {
	area  *domain.FileArea
	used  int64
	quota int64
	err   error
}

func newUploadScreen(_ *App, arg any) Screen {
	s := &uploadScreen{BaseScreen: BaseScreen{
		Route: RouteUpload, TitleText: "Upload", Hints: "esc back",
	}}
	if v, ok := arg.(filesArg); ok {
		s.arg = v
	}
	return s
}

func (s *uploadScreen) Init(a *App) tea.Cmd {
	ref := s.arg.ref()
	return func() tea.Msg {
		if a.Files == nil {
			return filesUploadMsg{err: domain.ErrUnavailable}
		}
		ctx := context.Background()
		u := a.User()
		used, quota, err := a.Files.Usage(ctx, u)
		if err != nil {
			return filesUploadMsg{err: err}
		}
		areas, err := a.Files.Areas(ctx, u)
		if err != nil {
			return filesUploadMsg{err: err}
		}
		var found *domain.FileArea
		for i := range areas {
			if areas[i].ID == ref || strings.EqualFold(areas[i].Tag, s.arg.Tag) {
				found = &areas[i]
				break
			}
		}
		return filesUploadMsg{area: found, used: used, quota: quota}
	}
}

func (s *uploadScreen) Update(_ *App, msg tea.Msg) tea.Cmd {
	if m, ok := msg.(filesUploadMsg); ok {
		s.loaded = true
		s.err = m.err
		s.area = m.area
		s.used = m.used
		s.quota = m.quota
	}
	return nil
}

func (s *uploadScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	title := "Upload"
	if s.arg.displayName() != "" {
		title = "Upload · " + s.arg.displayName()
	}
	b.WriteString(Section(w, title) + "\n")
	if s.err != nil {
		b.WriteString(styleWarn.Render(render.Clip(friendlyError(s.err), w)) + "\n")
		return b.String()
	}
	tag := s.arg.Tag
	if s.area != nil {
		tag = s.area.Tag
	}
	if tag == "" {
		tag = "uploads"
	}
	b.WriteString("There is no file picker in this session (D2: no in-session transfer).\n")
	b.WriteString("Pipe the file in from your own machine:\n\n")
	b.WriteString("  " + filesUploadCommand(a, tag) + "\n\n")
	b.WriteString(Section(w, "Limits") + "\n")
	line := func(label, value string) {
		b.WriteString(styleDim.Render(render.PadRight(label, 18)) + render.Clip(value, max(1, w-18)) + "\n")
	}
	line("max size", filesQuota(a.Cfg.Storage.MaxUploadBytes))
	if s.area != nil && s.area.QuotaBytes > 0 {
		line("area quota", filesQuota(s.area.QuotaBytes))
	}
	exts := "any"
	if len(a.Cfg.Storage.AllowedExt) > 0 {
		exts = strings.Join(a.Cfg.Storage.AllowedExt, ", ")
	}
	line("extensions", exts)
	line("your quota", filesUsage(s.used, s.quota))
	b.WriteString("\n")
	if a.User() == nil || a.User().IsGuest {
		b.WriteString(styleWarn.Render("Guests may not upload.") + "\n")
	} else if a.User().IsProbation() {
		b.WriteString(styleWarn.Render("Uploads stay off during probation (D3).") + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- helpers (package-level, files prefix) ---

// filesWindow returns the visible slice bounds for a cursor in a list.
func filesWindow(cursor, total, height int) (int, int) {
	if height < 1 {
		height = 1
	}
	if total <= height {
		return 0, max(0, total)
	}
	start := cursor - height/2
	if start < 0 {
		start = 0
	}
	if start+height > total {
		start = total - height
	}
	return start, start + height
}

// filesSize renders a byte count in IEC units.
func filesSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	value := float64(n) / 1024
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

// filesQuota renders a quota, where 0 means unlimited.
func filesQuota(n int64) string {
	if n <= 0 {
		return "unlimited"
	}
	return filesSize(n)
}

// filesUsage renders "used of quota".
func filesUsage(used, quota int64) string {
	if quota <= 0 {
		return filesSize(used) + " used (unlimited)"
	}
	return filesSize(used) + " of " + filesSize(quota)
}

func filesCount(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

func filesDate(f domain.File) string {
	if f.UploadedAt.IsZero() {
		return "-"
	}
	return f.UploadedAt.Format("2006-01-02")
}

func filesRating(f domain.File) string {
	if f.RatingCount == 0 {
		return "unrated"
	}
	return fmt.Sprintf("★%.1f (%d)", f.Rating, f.RatingCount)
}

// filesBoard is the host part of the pipe command. An address that only names
// a port (":2222"), a wildcard or loopback falls back to the placeholder "bbs".
func filesBoard(a *App) string {
	if a == nil || a.Cfg == nil {
		return "bbs"
	}
	host := strings.TrimSpace(a.Cfg.Transport.SSH.Address)
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "", "0.0.0.0", "::", "localhost", "127.0.0.1":
		return "bbs"
	}
	return host
}

// filesShellWord quotes one shell word when it contains anything special.
func filesShellWord(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t'\"$`\\!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// filesDownloadCommand is the exact pipe a caller runs to fetch a file.
func filesDownloadCommand(a *App, areaTag, filename string) string {
	spec := filesShellWord(areaTag + "/" + filename)
	return fmt.Sprintf("ssh %s get %s > %s", filesBoard(a), spec, filesShellWord(filename))
}

// filesUploadCommand is the exact pipe a caller runs to upload a file.
func filesUploadCommand(a *App, areaTag string) string {
	spec := filesShellWord(areaTag + "/FILE")
	return fmt.Sprintf("ssh %s put %s < local-file", filesBoard(a), spec)
}
