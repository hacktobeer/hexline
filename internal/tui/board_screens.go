package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/render"
)

// Board screens: area list, thread list, post reader, composer, search.

const boardPageSize = 20

// boardAreaArg carries an area ID between screens.
type boardAreaArg struct {
	AreaID string
	Tag    string
	Name   string
}

// boardThreadArg carries a thread (and optionally a post to jump to).
type boardThreadArg struct {
	ThreadID string
	AreaID   string
	AreaTag  string
	Subject  string
	PostID   int64
}

// boardComposeArg configures the composer for a new thread, reply or edit.
type boardComposeArg struct {
	Mode     string // "thread", "reply" or "edit"
	AreaID   string
	AreaTag  string
	ThreadID string
	Subject  string
	Body     string
	PostID   int64
}

// boardSearchArg narrows search to one area when set.
type boardSearchArg struct {
	AreaID  string
	AreaTag string
}

func boardAreaArgOf(arg any) boardAreaArg {
	switch v := arg.(type) {
	case boardAreaArg:
		return v
	case *boardAreaArg:
		if v != nil {
			return *v
		}
	case string:
		return boardAreaArg{AreaID: v}
	}
	return boardAreaArg{}
}

func boardThreadArgOf(arg any) boardThreadArg {
	switch v := arg.(type) {
	case boardThreadArg:
		return v
	case *boardThreadArg:
		if v != nil {
			return *v
		}
	case string:
		return boardThreadArg{ThreadID: v}
	}
	return boardThreadArg{}
}

func boardComposeArgOf(arg any) boardComposeArg {
	switch v := arg.(type) {
	case boardComposeArg:
		return v
	case *boardComposeArg:
		if v != nil {
			return *v
		}
	}
	return boardComposeArg{Mode: "thread"}
}

func boardSearchArgOf(arg any) boardSearchArg {
	switch v := arg.(type) {
	case boardSearchArg:
		return v
	case *boardSearchArg:
		if v != nil {
			return *v
		}
	case boardAreaArg:
		return boardSearchArg{AreaID: v.AreaID, AreaTag: v.Tag}
	}
	return boardSearchArg{}
}

func boardShortTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("01-02 15:04")
}

func boardDateTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func boardSnippet(body, query string, width int) string {
	flat := strings.Join(strings.Fields(body), " ")
	target := ""
	for _, f := range strings.Fields(strings.ToLower(query)) {
		if f != "" {
			target = f
			break
		}
	}
	if target != "" {
		if idx := strings.Index(strings.ToLower(flat), target); idx > 0 {
			flat = "…" + flat[idx:]
		}
	}
	return render.Clip(flat, width)
}

func boardUnreadLabel(n int) string {
	if n <= 0 {
		return "all read"
	}
	return itoa(n) + " unread"
}

func boardThreadMarker(t domain.Thread) string {
	switch {
	case t.Sticky && t.Locked:
		return "SL "
	case t.Sticky:
		return "S  "
	case t.Locked:
		return "L  "
	}
	return "   "
}

func boardPagerHeight(a *App) int {
	h := a.BodyHeight() - 5
	if h < 4 {
		h = 4
	}
	return h
}

// --- area list -------------------------------------------------------------

type boardAreasMsg struct {
	areas  []domain.Area
	unread map[string]int
	err    error
}

type boardListScreen struct {
	BaseScreen
	areas  []domain.Area
	unread map[string]int
	cursor int
	loaded bool
	err    string
}

func newBoardList(a *App, _ any) Screen {
	s := &boardListScreen{BaseScreen: BaseScreen{
		Route:     RouteBoards,
		TitleText: "Message boards",
		Hints:     "enter open  / search  m mark area read  r refresh  esc back",
	}}
	return s
}

func boardLoadAreas(a *App) tea.Cmd {
	return func() tea.Msg {
		if a.Boards == nil {
			return boardAreasMsg{err: fmt.Errorf("boards are unavailable")}
		}
		ctx := context.Background()
		areas, err := a.Boards.Areas(ctx, a.User())
		if err != nil {
			return boardAreasMsg{err: err}
		}
		unread, err := a.Boards.UnreadByArea(ctx, a.User())
		if err != nil {
			return boardAreasMsg{err: err}
		}
		return boardAreasMsg{areas: areas, unread: unread}
	}
}

func (s *boardListScreen) Init(a *App) tea.Cmd {
	s.loaded = false
	return boardLoadAreas(a)
}

func (s *boardListScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case boardAreasMsg:
		s.loaded = true
		if msg.err != nil {
			s.err = friendlyError(msg.err)
			return nil
		}
		s.err = ""
		s.areas = msg.areas
		s.unread = msg.unread
		if s.cursor >= len(s.areas) {
			s.cursor = len(s.areas) - 1
		}
		if s.cursor < 0 {
			s.cursor = 0
		}
		return nil
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down", "j":
			if s.cursor < len(s.areas)-1 {
				s.cursor++
			}
		case "home", "g":
			s.cursor = 0
		case "end", "G":
			if len(s.areas) > 0 {
				s.cursor = len(s.areas) - 1
			}
		case "enter":
			if s.cursor < len(s.areas) {
				area := s.areas[s.cursor]
				return func() tea.Msg {
					return NavigateMsg{Route: RouteThreads, Arg: boardAreaArg{
						AreaID: area.ID, Tag: area.Tag, Name: area.Name,
					}}
				}
			}
		case "/":
			return func() tea.Msg {
				return NavigateMsg{Route: RouteSearch, Arg: boardSearchArg{}}
			}
		case "m":
			if s.cursor < len(s.areas) {
				area := s.areas[s.cursor]
				if err := a.Boards.MarkAllRead(context.Background(), a.User(), area.ID); err != nil {
					return a.Errorf(err, "mark %s read", area.Tag)
				}
				a.Flash("%s marked read", area.Tag)
				return boardLoadAreas(a)
			}
		case "r":
			return boardLoadAreas(a)
		}
	}
	return nil
}

func (s *boardListScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, "Message boards") + "\n")
	b.WriteString(styleDim.Render(render.Clip("Conferences you can read. Unread counts update as you read.", w)) + "\n\n")
	if s.err != "" {
		b.WriteString(styleWarn.Render(render.Clip("! "+s.err, w)) + "\n")
	}
	if !s.loaded {
		b.WriteString(styleDim.Render("loading boards…"))
		return b.String()
	}
	if len(s.areas) == 0 {
		b.WriteString(styleDim.Render("No boards are available to this account."))
		return b.String()
	}
	for i, area := range s.areas {
		left := "[" + area.Tag + "] " + area.Name
		right := boardUnreadLabel(s.unread[area.ID])
		b.WriteString(ListRow(w, left, right, i == s.cursor) + "\n")
		if area.Description != "" {
			b.WriteString("    " + styleDim.Render(render.Clip(area.Description, w-4)) + "\n")
		}
	}
	return b.String()
}

// --- thread list -----------------------------------------------------------

type boardThreadsMsg struct {
	threads []domain.Thread
	offset  int
	err     error
}

type threadListScreen struct {
	BaseScreen
	areaID   string
	areaTag  string
	areaName string
	threads  []domain.Thread
	offset   int
	cursor   int
	loaded   bool
	err      string
}

func newThreadList(a *App, arg any) Screen {
	spec := boardAreaArgOf(arg)
	return &threadListScreen{
		BaseScreen: BaseScreen{
			Route:     RouteThreads,
			TitleText: "Threads",
			Hints:     "enter read  n/p page  c compose  / search  m mark area read  esc back",
		},
		areaID:   spec.AreaID,
		areaTag:  spec.Tag,
		areaName: spec.Name,
	}
}

func boardLoadThreads(a *App, areaID string, offset int) tea.Cmd {
	return func() tea.Msg {
		if a.Boards == nil {
			return boardThreadsMsg{offset: offset, err: fmt.Errorf("boards are unavailable")}
		}
		threads, err := a.Boards.Threads(context.Background(), a.User(), areaID, boardPageSize, offset)
		return boardThreadsMsg{threads: threads, offset: offset, err: err}
	}
}

func (s *threadListScreen) Init(a *App) tea.Cmd {
	s.loaded = false
	if s.areaID == "" {
		s.loaded = true
		return nil
	}
	return boardLoadThreads(a, s.areaID, s.offset)
}

func (s *threadListScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case boardThreadsMsg:
		s.loaded = true
		if msg.err != nil {
			s.err = friendlyError(msg.err)
			return nil
		}
		s.err = ""
		s.offset = msg.offset
		s.threads = msg.threads
		if len(s.threads) == 0 && s.offset > 0 {
			s.offset -= boardPageSize
			if s.offset < 0 {
				s.offset = 0
			}
			return boardLoadThreads(a, s.areaID, s.offset)
		}
		if s.cursor >= len(s.threads) {
			s.cursor = len(s.threads) - 1
		}
		if s.cursor < 0 {
			s.cursor = 0
		}
		return nil
	case tea.KeyMsg:
		key := msg.String()
		switch key {
		case "up", "k":
			if s.cursor > 0 {
				s.cursor--
			}
		case "down", "j":
			if s.cursor < len(s.threads)-1 {
				s.cursor++
			}
		case "home", "g":
			s.cursor = 0
		case "end", "G":
			if len(s.threads) > 0 {
				s.cursor = len(s.threads) - 1
			}
		case "enter":
			if s.cursor < len(s.threads) {
				t := s.threads[s.cursor]
				return func() tea.Msg {
					return NavigateMsg{Route: RoutePosts, Arg: boardThreadArg{
						ThreadID: t.ID, AreaID: t.AreaID, AreaTag: t.AreaTag, Subject: t.Subject,
					}}
				}
			}
		case "n":
			s.offset += boardPageSize
			return boardLoadThreads(a, s.areaID, s.offset)
		case "p":
			s.offset -= boardPageSize
			if s.offset < 0 {
				s.offset = 0
			}
			return boardLoadThreads(a, s.areaID, s.offset)
		case "r":
			return boardLoadThreads(a, s.areaID, s.offset)
		case "c":
			if !a.CanWrite() {
				a.Flash("this session is read-only")
				return nil
			}
			return func() tea.Msg {
				return NavigateMsg{Route: RouteCompose, Arg: boardComposeArg{
					Mode: "thread", AreaID: s.areaID, AreaTag: s.areaTag,
				}}
			}
		case "/":
			return func() tea.Msg {
				return NavigateMsg{Route: RouteSearch, Arg: boardSearchArg{
					AreaID: s.areaID, AreaTag: s.areaTag,
				}}
			}
		case "m":
			if err := a.Boards.MarkAllRead(context.Background(), a.User(), s.areaID); err != nil {
				return a.Errorf(err, "mark %s read", s.areaTag)
			}
			a.Flash("%s marked read", s.areaTag)
			return boardLoadThreads(a, s.areaID, s.offset)
		}
	}
	return nil
}

func (s *threadListScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	title := s.areaTag
	if s.areaName != "" {
		title = "[" + s.areaTag + "] " + s.areaName
	}
	b.WriteString(Section(w, title) + "\n")
	page := s.offset/boardPageSize + 1
	sub := fmt.Sprintf("S sticky · L locked · page %s · %d threads", itoa(page), len(s.threads))
	b.WriteString(styleDim.Render(render.Clip(sub, w)) + "\n\n")
	if s.err != "" {
		b.WriteString(styleWarn.Render(render.Clip("! "+s.err, w)) + "\n")
	}
	if !s.loaded {
		b.WriteString(styleDim.Render("loading threads…"))
		return b.String()
	}
	if len(s.threads) == 0 {
		if s.offset > 0 {
			b.WriteString(styleDim.Render("No more threads on this page."))
		} else {
			b.WriteString(styleDim.Render("No threads yet. Press c to start one."))
		}
		return b.String()
	}
	for i, t := range s.threads {
		left := boardThreadMarker(t) + t.Subject
		replies := t.PostCount - 1
		if replies < 0 {
			replies = 0
		}
		right := fmt.Sprintf("%s · %d replies", t.Author, replies)
		if t.Unread > 0 {
			right += fmt.Sprintf(" · %d new", t.Unread)
		}
		right += " · " + boardShortTime(t.LastPostAt)
		b.WriteString(ListRow(w, left, right, i == s.cursor) + "\n")
	}
	return b.String()
}

// --- post reader -----------------------------------------------------------

type boardThreadMsg struct {
	thread *domain.Thread
	posts  []domain.Post
	sigs   map[string]string
	areas  []domain.Area
	err    error
}

type postViewScreen struct {
	BaseScreen
	threadID   string
	jumpPostID int64
	thread     *domain.Thread
	posts      []domain.Post
	sigs       map[string]string
	targets    []domain.Area
	idx        int
	pg         pager
	prepared   bool
	loaded     bool
	err        string
	confirmDel bool
	moving     bool
	moveCursor int
}

func newPostView(a *App, arg any) Screen {
	spec := boardThreadArgOf(arg)
	hints := "j/k scroll  space page  n/p post  r reply  e edit  esc back"
	if a.IsModerator() {
		hints = "j/k scroll  n/p post  r reply  e edit  d delete  l lock  s sticky  m move  esc back"
	}
	return &postViewScreen{
		BaseScreen: BaseScreen{Route: RoutePosts, TitleText: "Thread", Hints: hints},
		threadID:   spec.ThreadID,
		jumpPostID: spec.PostID,
	}
}

func boardLoadThread(a *App, threadID string) tea.Cmd {
	return func() tea.Msg {
		if a.Boards == nil {
			return boardThreadMsg{err: fmt.Errorf("boards are unavailable")}
		}
		ctx := context.Background()
		thread, posts, err := a.Boards.Thread(ctx, a.User(), threadID)
		if err != nil {
			return boardThreadMsg{err: err}
		}
		sigs := make(map[string]string)
		for _, p := range posts {
			if _, ok := sigs[p.AuthorID]; ok {
				continue
			}
			if au, err := a.Store.UserByID(p.AuthorID); err == nil {
				sigs[p.AuthorID] = au.Signature
			}
		}
		var areas []domain.Area
		if a.IsModerator() {
			areas, _ = a.Boards.Areas(ctx, a.User())
		}
		// Opening a thread marks it read; a failure here must not hide the
		// thread, so it is intentionally best effort.
		_ = a.Boards.MarkRead(ctx, a.User(), thread.ID)
		return boardThreadMsg{thread: thread, posts: posts, sigs: sigs, areas: areas}
	}
}

func (s *postViewScreen) Init(a *App) tea.Cmd {
	s.loaded = false
	if s.threadID == "" {
		s.loaded = true
		s.err = "no thread selected"
		return nil
	}
	return boardLoadThread(a, s.threadID)
}

func (s *postViewScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case boardThreadMsg:
		s.loaded = true
		if msg.err != nil {
			s.err = friendlyError(msg.err)
			return nil
		}
		s.err = ""
		s.thread = msg.thread
		s.posts = msg.posts
		s.sigs = msg.sigs
		s.targets = s.targets[:0]
		for _, area := range msg.areas {
			if msg.thread != nil && area.ID == msg.thread.AreaID {
				continue
			}
			s.targets = append(s.targets, area)
		}
		if len(s.posts) == 0 {
			s.idx = 0
		} else {
			if s.jumpPostID != 0 {
				found := false
				for i, p := range s.posts {
					if p.ID == s.jumpPostID {
						s.idx = i
						found = true
						break
					}
				}
				if !found {
					s.idx = 0
				}
			}
			if s.idx >= len(s.posts) {
				s.idx = len(s.posts) - 1
			}
			if s.idx < 0 {
				s.idx = 0
			}
		}
		s.jumpPostID = 0
		s.prepared = false
		return nil
	case tea.KeyMsg:
		return s.updateKey(a, msg)
	}
	return nil
}

func (s *postViewScreen) updateKey(a *App, key tea.KeyMsg) tea.Cmd {
	k := key.String()
	if s.moving {
		switch k {
		case "up", "k":
			if s.moveCursor > 0 {
				s.moveCursor--
			}
		case "down", "j":
			if s.moveCursor < len(s.targets)-1 {
				s.moveCursor++
			}
		case "enter":
			if s.moveCursor < len(s.targets) {
				target := s.targets[s.moveCursor]
				if s.thread == nil {
					return nil
				}
				if err := a.Boards.MoveThread(context.Background(), a.User(), s.thread.ID, target.ID); err != nil {
					s.moving = false
					return a.Errorf(err, "move thread")
				}
				s.moving = false
				a.Flash("thread moved to %s", target.Tag)
				return boardLoadThread(a, s.thread.ID)
			}
		case "m", "q":
			s.moving = false
		}
		return nil
	}
	if s.confirmDel {
		switch k {
		case "y":
			s.confirmDel = false
			p := s.currentPost()
			if p == nil {
				return nil
			}
			if err := a.Boards.DeletePost(context.Background(), a.User(), p.ID, "removed by moderator"); err != nil {
				return a.Errorf(err, "delete post")
			}
			a.Flash("post deleted")
			return boardLoadThread(a, s.threadID)
		case "n", "esc":
			s.confirmDel = false
		}
		return nil
	}

	height := boardPagerHeight(a)
	switch k {
	case "up", "k":
		s.pg.Move(-1, height)
	case "down", "j", " ":
		s.pg.Move(1, height)
	case "pgup":
		s.pg.Move(-height, height)
	case "pgdown":
		s.pg.Move(height, height)
	case "n":
		if s.idx < len(s.posts)-1 {
			s.idx++
			s.prepared = false
		}
	case "p":
		if s.idx > 0 {
			s.idx--
			s.prepared = false
		}
	case "r":
		if s.thread == nil {
			return nil
		}
		if s.thread.Locked {
			a.Flash("this thread is locked")
			return nil
		}
		if !a.CanWrite() {
			a.Flash("this session is read-only")
			return nil
		}
		arg := boardComposeArg{Mode: "reply", AreaID: s.thread.AreaID, AreaTag: s.thread.AreaTag,
			ThreadID: s.thread.ID, Subject: domain.SubjectReply(s.thread.Subject)}
		if p := s.currentPost(); p != nil {
			arg.Body = domain.Quote(p.Author, p.Body)
		}
		return func() tea.Msg { return NavigateMsg{Route: RouteCompose, Arg: arg} }
	case "e":
		p := s.currentPost()
		if p == nil || s.thread == nil {
			return nil
		}
		u := a.User()
		if u == nil || p.AuthorID != u.ID {
			if !a.IsModerator() {
				a.Flash("you can only edit your own posts")
				return nil
			}
		}
		arg := boardComposeArg{Mode: "edit", AreaID: s.thread.AreaID, AreaTag: s.thread.AreaTag,
			ThreadID: s.thread.ID, Subject: s.thread.Subject, Body: p.Body, PostID: p.ID}
		return func() tea.Msg { return NavigateMsg{Route: RouteCompose, Arg: arg} }
	case "d":
		if !a.IsModerator() {
			a.Flash("permission denied")
			return nil
		}
		if p := s.currentPost(); p != nil && !p.Deleted {
			s.confirmDel = true
		}
	case "l":
		if s.thread == nil {
			return nil
		}
		locked := !s.thread.Locked
		if err := a.Boards.SetThreadFlags(context.Background(), a.User(), s.thread.ID, s.thread.Sticky, locked); err != nil {
			return a.Errorf(err, "lock thread")
		}
		if locked {
			a.Flash("thread locked")
		} else {
			a.Flash("thread unlocked")
		}
		return boardLoadThread(a, s.thread.ID)
	case "s":
		if s.thread == nil {
			return nil
		}
		sticky := !s.thread.Sticky
		if err := a.Boards.SetThreadFlags(context.Background(), a.User(), s.thread.ID, sticky, s.thread.Locked); err != nil {
			return a.Errorf(err, "sticky thread")
		}
		if sticky {
			a.Flash("thread pinned")
		} else {
			a.Flash("thread unpinned")
		}
		return boardLoadThread(a, s.thread.ID)
	case "m":
		if !a.IsModerator() {
			a.Flash("permission denied")
			return nil
		}
		if len(s.targets) == 0 {
			a.Flash("no other boards to move to")
			return nil
		}
		s.moving = true
		s.moveCursor = 0
	}
	return nil
}

func (s *postViewScreen) currentPost() *domain.Post {
	if s.idx < 0 || s.idx >= len(s.posts) {
		return nil
	}
	return &s.posts[s.idx]
}

func (s *postViewScreen) preparePost(a *App) {
	s.prepared = true
	p := s.currentPost()
	if p == nil {
		s.pg.SetText("", a.W-2)
		return
	}
	body := p.Body
	if p.Deleted {
		body = "[deleted]\n\n" + body
	}
	if sig := s.sigs[p.AuthorID]; sig != "" && !p.Deleted {
		body = strings.TrimRight(body, "\n") + "\n\n-- \n" + sig
	}
	s.pg.SetText(body, a.W-2)
}

func (s *postViewScreen) keyHints() string {
	if s.moving {
		return "j/k choose  enter move  m cancel"
	}
	if s.confirmDel {
		return "y delete  n cancel"
	}
	return s.Hints
}

func (s *postViewScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	if s.err != "" {
		b.WriteString(styleWarn.Render(render.Clip("! "+s.err, w)) + "\n")
	}
	if !s.loaded {
		b.WriteString(styleDim.Render("loading thread…"))
		return b.String()
	}
	if s.thread == nil {
		b.WriteString(styleDim.Render("No thread loaded."))
		return b.String()
	}
	title := s.thread.Subject
	markers := ""
	if s.thread.Sticky {
		markers += "S"
	}
	if s.thread.Locked {
		markers += "L"
	}
	if markers != "" {
		title = "[" + markers + "] " + title
	}
	b.WriteString(Section(w, title) + "\n")

	if s.moving {
		b.WriteString(styleDim.Render("Move thread to:") + "\n")
		for i, area := range s.targets {
			left := "[" + area.Tag + "] " + area.Name
			b.WriteString(ListRow(w, left, "", i == s.moveCursor) + "\n")
		}
		return b.String()
	}

	if len(s.posts) == 0 {
		b.WriteString(styleDim.Render("No live posts in this thread."))
		return b.String()
	}
	p := s.posts[s.idx]
	header := fmt.Sprintf("post %d/%d · %s · %s",
		s.idx+1, len(s.posts), p.Author, boardDateTime(p.CreatedAt))
	if !p.EditedAt.IsZero() {
		header += " · edited " + boardDateTime(p.EditedAt)
	}
	if p.Deleted {
		header += " · deleted"
	}
	b.WriteString(styleDim.Render(render.Clip(header, w)) + "\n")
	if p.Deleted {
		reason := p.DeleteWhy
		if reason == "" {
			reason = "no reason given"
		}
		b.WriteString(styleWarn.Render(render.Clip(
			fmt.Sprintf("deleted by %s (%s)", p.DeletedBy, reason), w)) + "\n")
	}
	if !s.prepared {
		s.preparePost(a)
	}
	b.WriteString(s.pg.View(w, boardPagerHeight(a)))
	if s.confirmDel {
		b.WriteString("\n" + styleWarn.Render("Delete this post? (y/n)"))
	}
	return b.String()
}

// --- composer --------------------------------------------------------------

type composeScreen struct {
	BaseScreen
	mode    string
	areaID  string
	areaTag string
	thread  string
	postID  int64
	subject textinput.Model
	body    textarea.Model
	focus   int
	preview bool
	err     string
	busy    bool
}

func newComposeScreen(a *App, arg any) Screen {
	spec := boardComposeArgOf(arg)
	mode := spec.Mode
	if mode == "" {
		mode = "thread"
	}
	title := "New thread"
	switch mode {
	case "reply":
		title = "Reply"
	case "edit":
		title = "Edit post"
	}
	c := &composeScreen{
		BaseScreen: BaseScreen{
			Route:     RouteCompose,
			TitleText: title,
			Hints:     "ctrl+s save  ctrl+p preview  tab next  esc cancel",
		},
		mode:    mode,
		areaID:  spec.AreaID,
		areaTag: spec.AreaTag,
		thread:  spec.ThreadID,
		postID:  spec.PostID,
	}
	c.subject = NewInput("subject", max(20, a.W-10))
	c.subject.CharLimit = 120
	c.subject.SetValue(spec.Subject)

	ta := textarea.New()
	ta.Placeholder = "Write your message. Plain text; *bold*, _italic_ and > quotes are supported."
	ta.SetWidth(max(20, a.W-4))
	ta.SetHeight(boardPagerHeight(a))
	if a.Cfg != nil && a.Cfg.Limits.PostMaxBytes > 0 {
		ta.CharLimit = a.Cfg.Limits.PostMaxBytes
	}
	ta.SetValue(spec.Body)
	c.body = ta

	if mode == "thread" {
		c.subject.Focus()
		c.focus = 0
	} else {
		c.body.Focus()
		c.focus = 1
	}
	return c
}

func (c *composeScreen) Init(a *App) tea.Cmd { return textinput.Blink }

func (c *composeScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		if c.focus == 0 {
			c.subject, cmd = c.subject.Update(msg)
		} else {
			c.body, cmd = c.body.Update(msg)
		}
		return cmd
	}
	switch key.String() {
	case "tab":
		if c.mode != "thread" {
			return nil
		}
		if c.focus == 0 {
			c.subject.Blur()
			c.body.Focus()
			c.focus = 1
		} else {
			c.body.Blur()
			c.subject.Focus()
			c.focus = 0
		}
		return nil
	case "ctrl+p":
		c.preview = !c.preview
		return nil
	case "ctrl+s":
		return c.submit(a)
	}
	var cmd tea.Cmd
	if c.focus == 0 {
		c.subject, cmd = c.subject.Update(msg)
	} else {
		c.body, cmd = c.body.Update(msg)
	}
	return cmd
}

func (c *composeScreen) submit(a *App) tea.Cmd {
	if c.busy {
		return nil
	}
	u := a.User()
	if u == nil {
		c.err = "not logged in"
		return nil
	}
	if a.Boards == nil {
		c.err = "boards are unavailable"
		return nil
	}
	c.busy = true
	ctx := context.Background()
	body := c.body.Value()

	promoted := false
	switch c.mode {
	case "thread":
		if _, err := a.Boards.CreateThread(ctx, u, c.areaID, c.subject.Value(), body); err != nil {
			c.busy = false
			c.err = friendlyError(err)
			return nil
		}
		promoted = c.maybePromote(a, u)
		a.Flash("thread posted")
	case "reply":
		if _, err := a.Boards.Reply(ctx, u, c.thread, body); err != nil {
			c.busy = false
			c.err = friendlyError(err)
			return nil
		}
		promoted = c.maybePromote(a, u)
		a.Flash("reply posted")
	case "edit":
		if err := a.Boards.EditPost(ctx, u, c.postID, body); err != nil {
			c.busy = false
			c.err = friendlyError(err)
			return nil
		}
		a.Flash("post updated")
	default:
		c.busy = false
		c.err = "unknown compose mode"
		return nil
	}
	if promoted {
		a.Flash("welcome off probation — your posts count now")
	}
	return func() tea.Msg { return PopMsg{} }
}

// maybePromote applies the D9 auto-promotion rule. Failures are deliberately
// ignored: posting succeeded and promotion is best effort.
func (c *composeScreen) maybePromote(a *App, u *domain.User) bool {
	if a.Auth == nil {
		return false
	}
	ctx := context.Background()
	count, err := a.Auth.PostCount(ctx, u.ID)
	if err != nil {
		return false
	}
	promoted, err := a.Auth.MaybePromote(ctx, u, count)
	return err == nil && promoted
}

func (c *composeScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, c.Title()) + "\n")
	if c.mode != "thread" {
		b.WriteString(styleDim.Render(render.Clip("in ["+c.areaTag+"] "+c.subject.Value(), w)) + "\n")
	}
	b.WriteString("\n")
	if c.preview {
		b.WriteString(styleDim.Render("preview") + "\n")
		preview := render.Render(c.body.Value(), render.Options{Width: w - 4, ANSI: true})
		if strings.TrimSpace(preview) == "" {
			preview = styleDim.Render("(empty message)")
		}
		b.WriteString(preview)
		b.WriteString("\n" + styleDim.Render("ctrl+p to go back to editing") + "\n")
	} else {
		if c.mode == "thread" {
			b.WriteString(LabeledInput("Subject", c.subject) + "\n")
		}
		b.WriteString(styleDim.Render("Message") + "\n")
		b.WriteString(c.body.View() + "\n")
	}
	if c.busy {
		b.WriteString(styleDim.Render("saving…") + "\n")
	}
	if c.err != "" {
		b.WriteString(styleWarn.Render(render.Clip("! "+c.err, w)) + "\n")
	}
	return b.String()
}

// --- search ----------------------------------------------------------------

type boardSearchRow struct {
	post    domain.Post
	areaTag string
	subject string
}

type boardSearchMsg struct {
	rows  []boardSearchRow
	query string
	err   error
}

type searchScreen struct {
	BaseScreen
	input     textinput.Model
	areaID    string
	areaTag   string
	rows      []boardSearchRow
	cursor    int
	focus     int // 0 query, 1 results
	searched  bool
	searching bool
	err       string
}

func newSearchScreen(a *App, arg any) Screen {
	spec := boardSearchArgOf(arg)
	s := &searchScreen{
		BaseScreen: BaseScreen{
			Route:     RouteSearch,
			TitleText: "Search",
			Hints:     "enter search  esc back",
		},
		areaID:  spec.AreaID,
		areaTag: spec.AreaTag,
	}
	s.input = NewInput("search subjects and bodies", max(20, a.W-10))
	s.input.Focus()
	return s
}

func boardSearch(a *App, query, areaID string) tea.Cmd {
	return func() tea.Msg {
		if a.Boards == nil {
			return boardSearchMsg{query: query, err: fmt.Errorf("boards are unavailable")}
		}
		posts, err := a.Boards.Search(context.Background(), a.User(), query, areaID, 25)
		if err != nil {
			return boardSearchMsg{query: query, err: err}
		}
		rows := make([]boardSearchRow, 0, len(posts))
		cache := make(map[string]*domain.Thread)
		for _, p := range posts {
			thread, ok := cache[p.ThreadID]
			if !ok {
				thread, _ = a.Store.ThreadByID(p.ThreadID, "")
				cache[p.ThreadID] = thread
			}
			row := boardSearchRow{post: p}
			if thread != nil {
				row.areaTag = thread.AreaTag
				row.subject = thread.Subject
			}
			rows = append(rows, row)
		}
		return boardSearchMsg{rows: rows, query: query}
	}
}

func (s *searchScreen) Init(a *App) tea.Cmd { return textinput.Blink }

func (s *searchScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case boardSearchMsg:
		s.searching = false
		s.searched = true
		if msg.err != nil {
			s.err = friendlyError(msg.err)
			s.focus = 0
			s.input.Focus()
			return nil
		}
		s.err = ""
		s.rows = msg.rows
		s.cursor = 0
		if len(s.rows) > 0 {
			s.focus = 1
			s.input.Blur()
		}
		return nil
	case tea.KeyMsg:
		key := msg.String()
		switch key {
		case "enter":
			if s.focus == 1 && len(s.rows) > 0 {
				row := s.rows[s.cursor]
				return func() tea.Msg {
					return NavigateMsg{Route: RoutePosts, Arg: boardThreadArg{
						ThreadID: row.post.ThreadID, AreaTag: row.areaTag,
						Subject: row.subject, PostID: row.post.ID,
					}}
				}
			}
			query := strings.TrimSpace(s.input.Value())
			if query == "" {
				s.err = "type something to search for"
				return nil
			}
			s.err = ""
			s.searching = true
			return boardSearch(a, query, s.areaID)
		case "tab":
			if s.focus == 0 && s.searched {
				s.focus = 1
				s.input.Blur()
			} else {
				s.focus = 0
				s.input.Focus()
			}
			return nil
		case "/":
			s.focus = 0
			s.input.Focus()
			return nil
		case "up", "k":
			if s.focus == 1 && s.cursor > 0 {
				s.cursor--
			}
			return nil
		case "down", "j":
			if s.focus == 1 && s.cursor < len(s.rows)-1 {
				s.cursor++
			}
			return nil
		}
	}
	if s.focus == 0 {
		var cmd tea.Cmd
		s.input, cmd = s.input.Update(msg)
		return cmd
	}
	return nil
}

func (s *searchScreen) keyHints() string {
	if s.focus == 1 {
		return "enter open  / edit query  tab query  esc back"
	}
	if s.areaTag != "" {
		return "enter search [" + s.areaTag + "]  esc back"
	}
	return "enter search  esc back"
}

func (s *searchScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, "Search posts") + "\n")
	label := "Query"
	if s.areaTag != "" {
		label += " (in [" + s.areaTag + "])"
	}
	b.WriteString(LabeledInput(label, s.input) + "\n\n")
	if s.err != "" {
		b.WriteString(styleWarn.Render(render.Clip("! "+s.err, w)) + "\n")
	}
	if s.searching {
		b.WriteString(styleDim.Render("searching…"))
		return b.String()
	}
	if !s.searched {
		b.WriteString(styleDim.Render("Search subjects and message bodies. Results open at the matching post."))
		return b.String()
	}
	if len(s.rows) == 0 {
		b.WriteString(styleDim.Render("No matches."))
		return b.String()
	}
	for i, row := range s.rows {
		left := "[" + row.areaTag + "] " + row.subject
		right := fmt.Sprintf("%s · %s", row.post.Author, boardShortTime(row.post.CreatedAt))
		selected := i == s.cursor && s.focus == 1
		b.WriteString(ListRow(w, left, right, selected) + "\n")
		b.WriteString("    " + styleDim.Render(boardSnippet(row.post.Body, s.input.Value(), w-4)) + "\n")
	}
	return b.String()
}
