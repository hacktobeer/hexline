package tui

import (
	"context"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/render"
)

// Mail screens: inbox/sent list, blocklist, reader, composer.
//
// Screens never write SQL: they call App.Mail and only format what it returns.
// Arguments may be plain IDs/handles or the typed structs below, so routes can
// push a screen without importing mail-specific details.

const mailPageSize = 20

// mailInboxArg opens the mailbox, optionally on a tab or a message.
type mailInboxArg struct {
	Tab  string // "inbox" (default) or "sent"
	Open string // message ID to open after loading
}

// mailViewArg carries the message to read plus its siblings, so n/p can page
// through the mailbox the caller came from.
type mailViewArg struct {
	IDs []string
	Pos int
}

// mailComposeArg pre-fills the composer (used by reply).
type mailComposeArg struct {
	To      string
	Subject string
	Body    string
}

// --- shared mail helpers ---

func mailDate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04")
}

// mailStamp is the short date used in list rows.
func mailStamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

// mailPrefill extracts composer pre-fill values from a screen argument.
func mailPrefill(arg any) mailComposeArg {
	switch x := arg.(type) {
	case mailComposeArg:
		return x
	case *mailComposeArg:
		if x != nil {
			return *x
		}
	case string:
		return mailComposeArg{To: x}
	}
	return mailComposeArg{}
}

// mailIDs projects the current page of messages to their IDs.
func mailIDs(items []domain.Mail) []string {
	ids := make([]string, len(items))
	for i, m := range items {
		ids[i] = m.ID
	}
	return ids
}

// mailEmptyLine is the placeholder shown for an empty mailbox.
func mailEmptyLine(tab string) string {
	if tab == "sent" {
		return "(nothing sent yet — press c to write a message)"
	}
	return "(no mail — press c to write one)"
}

// --- inbox / sent / blocklist ---

type mailInbox struct {
	BaseScreen
	tab       string
	mode      string // "list" or "blocks"
	items     []domain.Mail
	ids       []string
	cursor    int
	offset    int
	limit     int
	unread    int
	quotaUsed int
	quotaMax  int
	loaded    bool
	errText   string

	blocks      []string
	blockCursor int
	blockInput  textinput.Model
	addingBlock bool
}

// mailInboxMsg delivers a mailbox page.
type mailInboxMsg struct {
	tab    string
	items  []domain.Mail
	unread int
	used   int
	max    int
	err    error
}

// mailBlocksMsg delivers the caller's blocklist.
type mailBlocksMsg struct {
	handles []string
	err     error
}

// mailBlockDoneMsg reports a block or unblock action.
type mailBlockDoneMsg struct {
	handle  string
	blocked bool
	err     error
}

func newMailInbox(a *App, arg any) Screen {
	m := &mailInbox{
		BaseScreen: BaseScreen{Route: RouteMail, TitleText: "Mail",
			Hints: "i inbox  s sent  n/p page  enter read  c compose  b blocklist  esc back"},
		tab:   "inbox",
		mode:  "list",
		limit: mailPageSize,
	}
	switch x := arg.(type) {
	case mailInboxArg:
		if x.Tab != "" {
			m.tab = x.Tab
		}
	case *mailInboxArg:
		if x != nil && x.Tab != "" {
			m.tab = x.Tab
		}
	case string:
		if x == "sent" || x == "inbox" {
			m.tab = x
		}
	}
	m.blockInput = NewInput("handle to block", 24)
	return m
}

func (m *mailInbox) Init(a *App) tea.Cmd { return m.load(a) }

func (m *mailInbox) keyHints() string {
	if m.mode == "blocks" {
		if m.addingBlock {
			return "enter block  esc back"
		}
		return "enter unblock  a add  b back  esc back"
	}
	return m.Hints
}

// load fetches the current page, unread count and quota in one round trip.
func (m *mailInbox) load(a *App) tea.Cmd {
	u := a.User()
	tab := m.tab
	limit, offset := m.limit, m.offset
	return func() tea.Msg {
		msg := mailInboxMsg{tab: tab}
		if u == nil {
			msg.err = domain.ErrPermission
			return msg
		}
		ctx := context.Background()
		var err error
		if tab == "sent" {
			msg.items, err = a.Mail.Sent(ctx, u, limit, offset)
		} else {
			msg.items, err = a.Mail.Inbox(ctx, u, limit, offset)
		}
		if err != nil {
			msg.err = err
			return msg
		}
		msg.unread, _ = a.Mail.UnreadCount(ctx, u.ID)
		msg.used, msg.max, _ = a.Mail.Quota(ctx, u)
		return msg
	}
}

func (m *mailInbox) loadBlocks(a *App) tea.Cmd {
	u := a.User()
	return func() tea.Msg {
		if u == nil {
			return mailBlocksMsg{err: domain.ErrPermission}
		}
		handles, err := a.Mail.Blocked(context.Background(), u)
		return mailBlocksMsg{handles: handles, err: err}
	}
}

func (m *mailInbox) block(a *App, handle string, block bool) tea.Cmd {
	u := a.User()
	return func() tea.Msg {
		err := a.Mail.Block(context.Background(), u, handle, block)
		return mailBlockDoneMsg{handle: handle, blocked: block, err: err}
	}
}

func (m *mailInbox) Update(a *App, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case mailInboxMsg:
		if msg.tab != m.tab {
			return nil // stale page from the other tab
		}
		m.loaded = true
		m.items = msg.items
		m.ids = mailIDs(msg.items)
		m.unread = msg.unread
		m.quotaUsed = msg.used
		m.quotaMax = msg.max
		if msg.err != nil {
			m.errText = friendlyError(msg.err)
			m.items = nil
			m.ids = nil
		}
		if m.cursor >= len(m.items) {
			m.cursor = max(0, len(m.items)-1)
		}
		return nil
	case mailBlocksMsg:
		m.addingBlock = false
		m.blockInput.Blur()
		if msg.err != nil {
			m.errText = friendlyError(msg.err)
			return nil
		}
		m.blocks = msg.handles
		if m.blockCursor >= len(m.blocks) {
			m.blockCursor = max(0, len(m.blocks)-1)
		}
		return nil
	case mailBlockDoneMsg:
		if msg.err != nil {
			m.errText = friendlyError(msg.err)
			return nil
		}
		if msg.blocked {
			a.Flash("blocked %s", msg.handle)
		} else {
			a.Flash("unblocked %s", msg.handle)
		}
		return m.loadBlocks(a)
	case tea.KeyMsg:
		if m.mode == "blocks" {
			return m.updateBlocks(a, msg)
		}
		return m.updateList(a, msg)
	}
	return nil
}

func (m *mailInbox) updateList(a *App, key tea.KeyMsg) tea.Cmd {
	switch key.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case "n":
		if len(m.items) < m.limit {
			a.Flash("no more mail")
			return nil
		}
		m.offset += m.limit
		m.cursor = 0
		return m.load(a)
	case "p":
		if m.offset == 0 {
			a.Flash("already at the first page")
			return nil
		}
		m.offset = max(0, m.offset-m.limit)
		m.cursor = 0
		return m.load(a)
	case "i", "tab":
		if m.tab == "inbox" {
			return nil
		}
		m.tab, m.offset, m.cursor = "inbox", 0, 0
		return m.load(a)
	case "s":
		if m.tab == "sent" {
			return nil
		}
		m.tab, m.offset, m.cursor = "sent", 0, 0
		return m.load(a)
	case "enter":
		if len(m.ids) == 0 {
			return nil
		}
		arg := mailViewArg{IDs: m.ids, Pos: m.cursor}
		return func() tea.Msg { return NavigateMsg{Route: RouteMailView, Arg: arg} }
	case "c":
		return func() tea.Msg { return NavigateMsg{Route: RouteMailCompose} }
	case "b":
		m.mode = "blocks"
		m.addingBlock = false
		return m.loadBlocks(a)
	}
	return nil
}

func (m *mailInbox) updateBlocks(a *App, key tea.KeyMsg) tea.Cmd {
	if m.addingBlock {
		switch key.String() {
		case "enter":
			handle := strings.TrimSpace(m.blockInput.Value())
			if handle == "" {
				m.errText = "enter a handle to block"
				return nil
			}
			return m.block(a, handle, true)
		case "ctrl+g":
			m.addingBlock = false
			m.blockInput.Blur()
			return nil
		}
		var cmd tea.Cmd
		m.blockInput, cmd = m.blockInput.Update(key)
		return cmd
	}
	switch key.String() {
	case "up", "k":
		if m.blockCursor > 0 {
			m.blockCursor--
		}
	case "down", "j":
		if m.blockCursor < len(m.blocks)-1 {
			m.blockCursor++
		}
	case "enter":
		if len(m.blocks) == 0 {
			return nil
		}
		return m.block(a, m.blocks[m.blockCursor], false)
	case "a":
		m.addingBlock = true
		m.blockInput.SetValue("")
		m.blockInput.Focus()
		return textinput.Blink
	case "b":
		m.mode = "list"
		return nil
	}
	return nil
}

func (m *mailInbox) View(a *App) string {
	if m.mode == "blocks" {
		return m.viewBlocks(a)
	}
	w := a.W
	var b strings.Builder
	heading := "Mail · inbox"
	if m.tab == "sent" {
		heading = "Mail · sent"
	}
	b.WriteString(Section(w, heading) + "\n")

	quota := "quota " + itoa(m.quotaUsed)
	if m.quotaMax > 0 {
		quota += "/" + itoa(m.quotaMax)
	} else {
		quota += " (unlimited)"
	}
	b.WriteString(styleDim.Render(render.Clip(quota+"   unread "+itoa(m.unread), w)) + "\n")

	if m.errText != "" {
		b.WriteString(styleWarn.Render(render.Clip("! "+m.errText, w)) + "\n")
	}
	if !m.loaded {
		b.WriteString(styleDim.Render("loading…"))
		return b.String()
	}
	if len(m.items) == 0 {
		b.WriteString(styleDim.Render(mailEmptyLine(m.tab)))
		return b.String()
	}

	for i, msg := range m.items {
		marker := " "
		if m.tab == "inbox" && msg.ReadAt.IsZero() {
			marker = "●"
		}
		who := "from " + msg.From
		if m.tab == "sent" {
			who = "to " + msg.To
		}
		left := marker + " " + who + "  " + msg.Subject
		b.WriteString(ListRow(w, left, mailStamp(msg.CreatedAt), i == m.cursor) + "\n")
	}
	b.WriteString(styleDim.Render(render.Clip("page starts at "+itoa(m.offset+1), w)))
	return b.String()
}

func (m *mailInbox) viewBlocks(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, "Mail · blocked senders") + "\n")
	b.WriteString(styleDim.Render(render.Clip("Blocked callers cannot send you mail.", w)) + "\n\n")
	switch {
	case m.errText != "":
		b.WriteString(styleWarn.Render(render.Clip("! "+m.errText, w)) + "\n")
	case len(m.blocks) == 0:
		b.WriteString(styleDim.Render("(no blocked handles)") + "\n")
	default:
		for i, h := range m.blocks {
			b.WriteString(ListRow(w, "  "+h, "", i == m.blockCursor) + "\n")
		}
	}
	if m.addingBlock {
		b.WriteString("\n" + LabeledInput("Add handle", m.blockInput) + "\n")
	}
	return b.String()
}

// --- reader ---

type mailView struct {
	BaseScreen
	ids       []string
	pos       int
	msg       *domain.Mail
	signature string
	pager     pager
	loaded    bool
	errText   string
	confirm   bool // second d confirms delete
}

type mailViewMsg struct {
	msg *domain.Mail
	sig string
	err error
}

type mailDeletedMsg struct {
	id  string
	err error
}

func newMailView(a *App, arg any) Screen {
	v := &mailView{
		BaseScreen: BaseScreen{Route: RouteMailView, TitleText: "Message",
			Hints: "n/p next/prev  r reply  d delete  j/k scroll  esc back"},
		pos: -1,
	}
	switch x := arg.(type) {
	case string:
		v.ids = []string{x}
		v.pos = 0
	case mailViewArg:
		v.ids, v.pos = x.IDs, x.Pos
	case *mailViewArg:
		if x != nil {
			v.ids, v.pos = x.IDs, x.Pos
		}
	}
	if v.pos < 0 || v.pos >= len(v.ids) {
		if len(v.ids) > 0 {
			v.pos = 0
		} else {
			v.pos = -1
		}
	}
	return v
}

func (v *mailView) Init(a *App) tea.Cmd { return v.load(a) }

func (v *mailView) load(a *App) tea.Cmd {
	id := ""
	if v.pos >= 0 && v.pos < len(v.ids) {
		id = v.ids[v.pos]
	}
	u := a.User()
	return func() tea.Msg {
		if u == nil || id == "" {
			return mailViewMsg{err: domain.ErrNotFound}
		}
		ctx := context.Background()
		msg, err := a.Mail.Message(ctx, u, id)
		if err != nil {
			return mailViewMsg{err: err}
		}
		sig, err := a.Mail.SenderSignature(ctx, u, msg)
		if err != nil {
			sig = ""
		}
		return mailViewMsg{msg: msg, sig: sig}
	}
}

func (v *mailView) Update(a *App, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case mailViewMsg:
		v.loaded = true
		if msg.err != nil {
			v.errText = friendlyError(msg.err)
			v.msg = nil
			return nil
		}
		v.errText = ""
		v.msg = msg.msg
		v.signature = msg.sig
		v.confirm = false
		text := msg.msg.Body
		if sig := strings.TrimSpace(msg.sig); sig != "" {
			text = strings.TrimRight(text, "\n") + "\n\n  -- \n" + sig
		}
		v.pager.SetText(text, max(20, a.W-2))
		return nil
	case mailDeletedMsg:
		if msg.err != nil {
			v.errText = friendlyError(msg.err)
			return nil
		}
		a.Flash("message deleted")
		return func() tea.Msg { return PopMsg{} }
	case tea.KeyMsg:
		switch msg.String() {
		case "n":
			if v.pos+1 >= len(v.ids) {
				a.Flash("last message in this mailbox")
				return nil
			}
			v.pos++
			v.loaded = false
			return v.load(a)
		case "p":
			if v.pos <= 0 {
				a.Flash("first message in this mailbox")
				return nil
			}
			v.pos--
			v.loaded = false
			return v.load(a)
		case "r":
			if v.msg == nil {
				return nil
			}
			u := a.User()
			to := v.msg.From
			if u != nil && v.msg.FromID == u.ID {
				to = v.msg.To
			}
			arg := mailComposeArg{
				To:      to,
				Subject: domain.SubjectReply(v.msg.Subject),
				Body:    domain.Quote(v.msg.From, v.msg.Body),
			}
			return func() tea.Msg { return NavigateMsg{Route: RouteMailCompose, Arg: arg} }
		case "d":
			if v.msg == nil {
				return nil
			}
			if !v.confirm {
				v.confirm = true
				a.Flash("press d again to delete this message")
				return nil
			}
			id := v.msg.ID
			u := a.User()
			return func() tea.Msg {
				err := a.Mail.Delete(context.Background(), u, id)
				return mailDeletedMsg{id: id, err: err}
			}
		case "up", "k":
			v.pager.Move(-1, v.bodyHeight(a))
		case "down", "j":
			v.pager.Move(1, v.bodyHeight(a))
		case "pgup":
			v.pager.Move(-v.bodyHeight(a), v.bodyHeight(a))
		case "pgdown", " ":
			v.pager.Move(v.bodyHeight(a), v.bodyHeight(a))
		}
	}
	return nil
}

// bodyHeight is the number of rows left for the message text after the
// headers and the scroll/position footer.
func (v *mailView) bodyHeight(a *App) int {
	return max(3, a.BodyHeight()-6)
}

func (v *mailView) View(a *App) string {
	w := a.W
	if v.errText != "" {
		return styleWarn.Render(render.Clip("! "+v.errText, w))
	}
	if !v.loaded || v.msg == nil {
		return styleDim.Render("loading…")
	}
	m := v.msg
	var b strings.Builder
	b.WriteString(styleBold.Render(render.Clip(m.Subject, w)) + "\n")
	b.WriteString(styleDim.Render(render.Clip("From: "+m.From+"    To: "+m.To, w)) + "\n")
	b.WriteString(styleDim.Render(render.Clip("Date: "+mailDate(m.CreatedAt), w)) + "\n")
	b.WriteString(Rule(w) + "\n")
	b.WriteString(v.pager.View(w, v.bodyHeight(a)))
	if v.confirm {
		b.WriteString("\n" + styleWarn.Render(render.Clip("delete this message? press d again to confirm", w)))
	} else if n := len(v.ids); n > 1 {
		b.WriteString("\n" + styleDim.Render(render.Clip("message "+itoa(v.pos+1)+" of "+itoa(n), w)))
	}
	return b.String()
}

// --- composer ---

type mailComposer struct {
	BaseScreen
	to      textinput.Model
	subject textinput.Model
	body    textarea.Model
	focus   int
	errText string
	sending bool
}

type mailSentMsg struct {
	msg *domain.Mail
	err error
}

func newMailCompose(a *App, arg any) Screen {
	pre := mailPrefill(arg)
	c := &mailComposer{
		BaseScreen: BaseScreen{Route: RouteMailCompose, TitleText: "Compose mail",
			Hints: "tab next  ctrl+s send  esc cancel"},
		to:      NewInput("recipient handle", 24),
		subject: NewInput("subject", 60),
	}
	c.to.CharLimit = 20
	c.subject.CharLimit = 120
	ta := textarea.New()
	ta.Placeholder = "message body"
	ta.SetWidth(max(20, a.W-2))
	ta.SetHeight(max(4, a.BodyHeight()-8))
	ta.CharLimit = max(1024, a.Cfg.Limits.PostMaxBytes)
	c.body = ta

	c.to.SetValue(pre.To)
	c.subject.SetValue(pre.Subject)
	if pre.Body != "" {
		c.body.SetValue(pre.Body)
	}
	switch {
	case strings.TrimSpace(pre.To) == "":
		c.focus = 0
		c.to.Focus()
	case strings.TrimSpace(pre.Subject) == "":
		c.focus = 1
		c.subject.Focus()
	default:
		c.focus = 2
		c.body.Focus()
	}
	return c
}

func (c *mailComposer) Init(a *App) tea.Cmd { return textinput.Blink }

func (c *mailComposer) blurAll() {
	c.to.Blur()
	c.subject.Blur()
	c.body.Blur()
}

func (c *mailComposer) focusField() {
	switch c.focus {
	case 0:
		c.to.Focus()
	case 1:
		c.subject.Focus()
	default:
		c.body.Focus()
	}
}

func (c *mailComposer) Update(a *App, msg tea.Msg) tea.Cmd {
	if sent, ok := msg.(mailSentMsg); ok {
		c.sending = false
		if sent.err != nil {
			c.errText = friendlyError(sent.err)
			return nil
		}
		a.Flash("mail sent to %s", sent.msg.To)
		return func() tea.Msg { return PopMsg{} }
	}
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		switch c.focus {
		case 0:
			c.to, cmd = c.to.Update(msg)
		case 1:
			c.subject, cmd = c.subject.Update(msg)
		default:
			c.body, cmd = c.body.Update(msg)
		}
		return cmd
	}
	switch key.String() {
	case "tab":
		c.blurAll()
		c.focus = (c.focus + 1) % 3
		c.focusField()
		return nil
	case "shift+tab":
		c.blurAll()
		c.focus = (c.focus + 2) % 3
		c.focusField()
		return nil
	case "ctrl+s":
		return c.submit(a)
	}
	var cmd tea.Cmd
	switch c.focus {
	case 0:
		c.to, cmd = c.to.Update(key)
	case 1:
		c.subject, cmd = c.subject.Update(key)
	default:
		c.body, cmd = c.body.Update(key)
	}
	return cmd
}

func (c *mailComposer) submit(a *App) tea.Cmd {
	if c.sending {
		return nil
	}
	c.errText = ""
	to := strings.TrimSpace(c.to.Value())
	if to == "" {
		c.errText = "recipient handle is required"
		return nil
	}
	c.sending = true
	subject := c.subject.Value()
	body := c.body.Value()
	u := a.User()
	return func() tea.Msg {
		msg, err := a.Mail.Send(context.Background(), u, to, subject, body)
		return mailSentMsg{msg: msg, err: err}
	}
}

func (c *mailComposer) View(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(LabeledInput("To (handle)", c.to) + "\n")
	b.WriteString(LabeledInput("Subject", c.subject) + "\n")
	b.WriteString(styleDim.Render("Message") + "\n")
	b.WriteString(c.body.View() + "\n")
	if c.errText != "" {
		b.WriteString("\n" + styleWarn.Render(render.Clip("! "+c.errText, w)) + "\n")
	} else if c.sending {
		b.WriteString("\n" + styleDim.Render("sending…") + "\n")
	}
	return b.String()
}
