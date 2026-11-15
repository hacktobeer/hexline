package tui

// Community screens: chat, oneliners, polls, bulletins, who's online.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/hub"
	"github.com/hacktobeer/hexline/internal/render"
)

// --- shared helpers (prefixed comm) ---

func commWhen(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("01-02 15:04")
}

func commIdle(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return "now"
	case d < time.Minute:
		return itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return itoa(int(d.Minutes())) + "m"
	default:
		return itoa(int(d.Hours())) + "h" + itoa(int(d.Minutes())%60) + "m"
	}
}

func commPollOpen(p domain.Poll, now time.Time) bool {
	return p.ClosesAt.IsZero() || now.Before(p.ClosesAt)
}

func commPollStatus(p domain.Poll, now time.Time) string {
	if commPollOpen(p, now) {
		return "open"
	}
	return "closed"
}

func commPollID(arg any) string {
	switch v := arg.(type) {
	case string:
		return strings.TrimSpace(v)
	case domain.Poll:
		return v.ID
	case *domain.Poll:
		if v != nil {
			return v.ID
		}
	}
	return ""
}

func commSafeCommunity(a *App) bool { return a != nil && a.Community != nil }

// --- chat ---

// commChatSub identifies one live chat subscription so a later chat screen can
// cancel an earlier one (bounded to one subscription per session).
type commChatSub struct {
	cancel func()
}

var commChatSubs sync.Map // key string -> *commChatSub

func commChatKey(a *App) string {
	if a != nil && a.SessionID != "" {
		return a.SessionID
	}
	return fmt.Sprintf("app:%p", a)
}

func commChatRegister(a *App, cancel func()) *commChatSub {
	key := commChatKey(a)
	if prev, ok := commChatSubs.LoadAndDelete(key); ok {
		if old, ok := prev.(*commChatSub); ok && old.cancel != nil {
			old.cancel()
		}
	}
	sub := &commChatSub{cancel: cancel}
	commChatSubs.Store(key, sub)
	return sub
}

func commChatRelease(a *App, sub *commChatSub) {
	if sub == nil {
		return
	}
	key := commChatKey(a)
	if cur, ok := commChatSubs.Load(key); ok && cur == sub {
		commChatSubs.Delete(key)
	}
	if sub.cancel != nil {
		sub.cancel()
		sub.cancel = nil
	}
}

type chatScreen struct {
	BaseScreen
	channel string
	events  []hub.Event
	input   textinput.Model
	sub     *commChatSub
	live    <-chan hub.Event
	owner   *App
}

func newChatScreen(a *App, arg any) Screen {
	channel := commChannelArg(arg)
	if channel == "sysop" && (a == nil || !a.IsModerator()) {
		channel = "global"
		if a != nil {
			a.Flash("the sysop channel is for moderators")
		}
	}
	s := &chatScreen{
		BaseScreen: BaseScreen{Route: RouteChat, TitleText: "Chat · " + channel, Hints: "enter send  /sysop switch  /quit leave  esc back"},
		channel:    channel,
	}
	s.input = NewInput("say something to #"+channel, 70)
	s.owner = a
	s.input.CharLimit = 400
	if commSafeCommunity(a) {
		s.events = a.Community.ChatHistory(channel)
	}
	return s
}

func commChannelArg(arg any) string {
	if s, ok := arg.(string); ok {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "sysop":
			return "sysop"
		}
	}
	return "global"
}

func (s *chatScreen) Init(a *App) tea.Cmd {
	s.releaseSubscription(a)
	s.live = nil
	if a.Hub != nil {
		ch, cancel := a.Hub.Subscribe("*")
		s.live = ch
		s.sub = commChatRegister(a, cancel)
	}
	s.input.Focus()
	cmds := []tea.Cmd{textinput.Blink}
	if s.live != nil {
		cmds = append(cmds, WaitForHub(s.live))
	}
	return tea.Batch(cmds...)
}

// OnLeave releases the broker subscription when the screen is popped.
func (s *chatScreen) OnLeave() {
	s.releaseSubscription(s.owner)
}

// releaseSubscription cancels a live broker subscription. Safe to call twice.
func (s *chatScreen) releaseSubscription(a *App) {
	if s.sub != nil {
		commChatRelease(a, s.sub)
		s.sub = nil
	}
}

func (s *chatScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch m := msg.(type) {
	case HubEventMsg:
		s.appendEvent(m.Event)
		if s.live != nil {
			return WaitForHub(s.live)
		}
		return nil
	case tea.KeyMsg:
		switch m.String() {
		case "enter":
			return s.submit(a)
		case "tab":
			s.input.Blur()
			return nil
		case "esc":
			// App.Update normally handles esc before the screen; keep this for
			// the case where chat is the root screen and to release the broker.
			s.releaseSubscription(a)
			return func() tea.Msg { return PopMsg{} }
		}
		var cmd tea.Cmd
		s.input, cmd = s.input.Update(msg)
		return cmd
	}
	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	return cmd
}

func (s *chatScreen) appendEvent(ev hub.Event) {
	switch ev.Kind {
	case hub.KindChat:
		if ev.Scope != "chat:"+s.channel {
			return
		}
	case hub.KindPresence:
		ev = hub.Event{Kind: hub.KindNotice, Scope: ev.Scope, Text: ev.Text, At: ev.At}
	case hub.KindNotice:
		// A broadcast notice is relevant to every screen.
	default:
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	s.events = append(s.events, ev)
	if len(s.events) > 200 {
		s.events = s.events[len(s.events)-200:]
	}
}

func (s *chatScreen) submit(a *App) tea.Cmd {
	text := strings.TrimSpace(s.input.Value())
	if text == "" {
		return nil
	}
	if strings.HasPrefix(text, "/") {
		return s.command(a, text)
	}
	if !commSafeCommunity(a) {
		return nil
	}
	if err := a.Community.ChatSend(context.Background(), a.User(), s.channel, text); err != nil {
		return a.Errorf(err, "")
	}
	s.input.SetValue("")
	return nil
}

func (s *chatScreen) command(a *App, text string) tea.Cmd {
	fields := strings.Fields(text)
	cmd := strings.ToLower(fields[0])
	switch cmd {
	case "/quit", "/leave":
		s.releaseSubscription(a)
		return func() tea.Msg { return PopMsg{} }
	case "/sysop":
		if !a.IsModerator() {
			a.Flash("the sysop channel is for moderators")
			return nil
		}
		return s.switchChannel(a, "sysop")
	case "/global":
		return s.switchChannel(a, "global")
	case "/help":
		a.Flash("/global  /sysop  /quit  — enter sends")
		return nil
	default:
		a.Flash("unknown chat command %q", cmd)
		return nil
	}
}

func (s *chatScreen) switchChannel(a *App, channel string) tea.Cmd {
	if channel == s.channel {
		return nil
	}
	s.releaseSubscription(a)
	s.channel = channel
	s.TitleText = "Chat · " + channel
	s.live = nil
	if commSafeCommunity(a) {
		s.events = a.Community.ChatHistory(channel)
	}
	if a.Hub != nil {
		ch, cancel := a.Hub.Subscribe("*")
		s.live = ch
		s.sub = commChatRegister(a, cancel)
	}
	s.input.Placeholder = "say something to #" + channel
	s.input.SetValue("")
	a.Flash("joined #%s", channel)
	if s.live != nil {
		return WaitForHub(s.live)
	}
	return nil
}

func (s *chatScreen) View(a *App) string {
	w := a.W
	height := a.BodyHeight() - 2
	if height < 1 {
		height = 1
	}
	lines := make([]string, 0, len(s.events))
	for _, ev := range s.events {
		lines = append(lines, commChatLine(w, ev))
	}
	if len(lines) > height {
		lines = lines[len(lines)-height:]
	}
	var b strings.Builder
	if len(lines) == 0 {
		b.WriteString(styleDim.Render("Joined #"+s.channel+". Say hello.") + "\n")
	} else {
		b.WriteString(strings.Join(lines, "\n") + "\n")
	}
	b.WriteString(styleDim.Render("#"+s.channel+" ") + s.input.View())
	return b.String()
}

func commChatLine(w int, ev hub.Event) string {
	if ev.Kind == hub.KindNotice {
		return styleDim.Render(render.Clip("* "+render.SanitizeLine(ev.Text), w))
	}
	when := ev.At.UTC().Format("15:04")
	who := render.SanitizeLine(ev.From)
	text := render.SanitizeLine(ev.Text)
	room := w - render.Width(when) - render.Width(who) - 3
	if room < 8 {
		room = 8
	}
	return styleDim.Render(when) + " " + styleAccent.Render(who) + ": " + render.Clip(text, room)
}

// --- one-liners ---

type onelinerScreen struct {
	BaseScreen
	items     []domain.Oneliner
	cursor    int
	input     textinput.Model
	composing bool
}

func newOnelinerScreen(a *App, _ any) Screen {
	s := &onelinerScreen{
		BaseScreen: BaseScreen{Route: RouteOneliners, TitleText: "One-liners",
			Hints: "c post  j/k move  d hide  u unhide  esc back"},
	}
	s.input = NewInput("say something (max 200)", 70)
	s.input.CharLimit = 200
	s.reload(a)
	return s
}

func (s *onelinerScreen) reload(a *App) {
	s.items = nil
	if !commSafeCommunity(a) {
		return
	}
	items, err := a.Community.Oneliners(context.Background(), 100)
	if err != nil {
		a.Flash("%s", friendlyError(err))
		return
	}
	// Hidden entries stay visible to moderators only.
	mod := a != nil && a.IsModerator()
	for _, o := range items {
		if o.Hidden && !mod {
			continue
		}
		s.items = append(s.items, o)
	}
	if s.cursor >= len(s.items) {
		s.cursor = len(s.items) - 1
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

func (s *onelinerScreen) selected() *domain.Oneliner {
	if s.cursor < 0 || s.cursor >= len(s.items) {
		return nil
	}
	return &s.items[s.cursor]
}

func (s *onelinerScreen) Init(a *App) tea.Cmd { return nil }

func (s *onelinerScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		if s.composing {
			var cmd tea.Cmd
			s.input, cmd = s.input.Update(msg)
			return cmd
		}
		return nil
	}
	if s.composing {
		switch key.String() {
		case "enter":
			return s.post(a)
		case "tab":
			s.composing = false
			s.input.Blur()
			return nil
		}
		var cmd tea.Cmd
		s.input, cmd = s.input.Update(msg)
		return cmd
	}
	switch key.String() {
	case "c":
		s.composing = true
		s.input.Focus()
		return textinput.Blink
	case "j", "down":
		if s.cursor < len(s.items)-1 {
			s.cursor++
		}
	case "k", "up":
		if s.cursor > 0 {
			s.cursor--
		}
	case "g":
		s.cursor = 0
	case "G":
		if len(s.items) > 0 {
			s.cursor = len(s.items) - 1
		}
	case "r":
		s.reload(a)
	case "d":
		return s.hide(a, true)
	case "u":
		return s.hide(a, false)
	}
	return nil
}

func (s *onelinerScreen) post(a *App) tea.Cmd {
	if !commSafeCommunity(a) {
		return nil
	}
	_, err := a.Community.PostOneliner(context.Background(), a.User(), s.input.Value())
	if err != nil {
		return a.Errorf(err, "")
	}
	s.input.SetValue("")
	s.input.Blur()
	s.composing = false
	s.reload(a)
	a.Flash("one-liner posted")
	return nil
}

func (s *onelinerScreen) hide(a *App, hide bool) tea.Cmd {
	o := s.selected()
	if !commSafeCommunity(a) || o == nil {
		return nil
	}
	if err := a.Community.HideOneliner(context.Background(), a.User(), o.ID, hide); err != nil {
		return a.Errorf(err, "")
	}
	s.reload(a)
	if hide {
		a.Flash("one-liner hidden")
	} else {
		a.Flash("one-liner restored")
	}
	return nil
}

func (s *onelinerScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, "One-liners") + "\n")
	if len(s.items) == 0 {
		b.WriteString(styleDim.Render("(nothing on the wall yet — press c and say hello)") + "\n\n")
	}
	for i, o := range s.items {
		body := o.Body
		if o.Hidden {
			body = "[hidden] " + body
		}
		meta := o.Author + " · " + commWhen(o.CreatedAt)
		b.WriteString(ListRow(w, body, meta, i == s.cursor) + "\n")
	}
	b.WriteString("\n" + styleDim.Render("new> ") + s.input.View())
	return b.String()
}

// --- polls ---

type pollListScreen struct {
	BaseScreen
	polls  []domain.Poll
	cursor int
}

func newPollList(a *App, _ any) Screen {
	s := &pollListScreen{BaseScreen: BaseScreen{Route: RoutePolls, TitleText: "Polls",
		Hints: "enter open  1-9 vote  j/k move  r refresh  esc back"}}
	s.reload(a)
	return s
}

func (s *pollListScreen) reload(a *App) {
	s.polls = nil
	if !commSafeCommunity(a) {
		return
	}
	polls, err := a.Community.Polls(context.Background(), a.User())
	if err != nil {
		a.Flash("%s", friendlyError(err))
		return
	}
	s.polls = polls
	if s.cursor >= len(s.polls) {
		s.cursor = len(s.polls) - 1
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

func (s *pollListScreen) Init(a *App) tea.Cmd { return nil }

func (s *pollListScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return nil
	}
	switch key.String() {
	case "j", "down":
		if s.cursor < len(s.polls)-1 {
			s.cursor++
		}
	case "k", "up":
		if s.cursor > 0 {
			s.cursor--
		}
	case "enter":
		if s.cursor >= 0 && s.cursor < len(s.polls) {
			id := s.polls[s.cursor].ID
			return func() tea.Msg { return NavigateMsg{Route: RoutePoll, Arg: id} }
		}
	case "r":
		s.reload(a)
	default:
		if n, ok := commDigit(key.String()); ok {
			return s.vote(a, n)
		}
	}
	return nil
}

func (s *pollListScreen) vote(a *App, n int) tea.Cmd {
	if s.cursor < 0 || s.cursor >= len(s.polls) {
		return nil
	}
	p := s.polls[s.cursor]
	if n < 1 || n > len(p.Options) {
		a.Flash("this poll has %d options", len(p.Options))
		return nil
	}
	if !commSafeCommunity(a) {
		return nil
	}
	if err := a.Community.Vote(context.Background(), a.User(), p.ID, p.Options[n-1].ID); err != nil {
		return a.Errorf(err, "")
	}
	s.reload(a)
	a.Flash("vote recorded")
	return nil
}

func (s *pollListScreen) View(a *App) string {
	w := a.W
	now := a.now()
	var b strings.Builder
	b.WriteString(Section(w, "Polls") + "\n")
	if len(s.polls) == 0 {
		b.WriteString(styleDim.Render("(no polls yet)") + "\n")
	}
	for i, p := range s.polls {
		mark := ""
		if p.MyVote != 0 {
			mark = " · you voted"
		}
		right := fmt.Sprintf("%d votes · %s%s", p.TotalVotes, commPollStatus(p, now), mark)
		b.WriteString(ListRow(w, p.Question, right, i == s.cursor) + "\n")
	}
	return b.String()
}

type pollViewScreen struct {
	BaseScreen
	id     string
	poll   *domain.Poll
	cursor int
}

func newPollView(a *App, arg any) Screen {
	s := &pollViewScreen{BaseScreen: BaseScreen{Route: RoutePoll, TitleText: "Poll",
		Hints: "1-9 vote  enter vote  j/k move  r refresh  esc back"}}
	s.id = commPollID(arg)
	s.reload(a)
	return s
}

func (s *pollViewScreen) reload(a *App) {
	s.poll = nil
	if !commSafeCommunity(a) || s.id == "" {
		return
	}
	p, err := a.Community.Poll(context.Background(), a.User(), s.id)
	if err != nil {
		a.Flash("%s", friendlyError(err))
		return
	}
	s.poll = p
	if s.cursor >= len(p.Options) {
		s.cursor = len(p.Options) - 1
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

func (s *pollViewScreen) Init(a *App) tea.Cmd { return nil }

func (s *pollViewScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok || s.poll == nil {
		return nil
	}
	switch key.String() {
	case "j", "down":
		if s.cursor < len(s.poll.Options)-1 {
			s.cursor++
		}
	case "k", "up":
		if s.cursor > 0 {
			s.cursor--
		}
	case "enter":
		return s.vote(a, s.cursor)
	case "r":
		s.reload(a)
	default:
		if n, ok := commDigit(key.String()); ok {
			return s.vote(a, n-1)
		}
	}
	return nil
}

func (s *pollViewScreen) vote(a *App, index int) tea.Cmd {
	if s.poll == nil || index < 0 || index >= len(s.poll.Options) {
		return nil
	}
	if !commSafeCommunity(a) {
		return nil
	}
	if err := a.Community.Vote(context.Background(), a.User(), s.poll.ID, s.poll.Options[index].ID); err != nil {
		return a.Errorf(err, "")
	}
	s.reload(a)
	a.Flash("vote recorded")
	return nil
}

func (s *pollViewScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	if s.poll == nil {
		b.WriteString(styleWarn.Render("Poll not found.") + "\n")
		return b.String()
	}
	p := s.poll
	now := a.now()
	b.WriteString(styleBold.Render(render.Clip(p.Question, w)) + "\n")
	b.WriteString(styleDim.Render("poll "+p.ID+" · "+commPollStatus(*p, now)) + "\n")
	if !p.ClosesAt.IsZero() {
		b.WriteString(styleDim.Render("closes "+commWhen(p.ClosesAt)) + "\n")
	}
	b.WriteString("\n")
	show := !commPollOpen(*p, now) || p.MyVote != 0
	for i, o := range p.Options {
		label := fmt.Sprintf("[%d] %s", i+1, o.Label)
		if show {
			bar := strings.Repeat("█", min(o.Votes, 20))
			right := fmt.Sprintf("%d", o.Votes)
			if o.ID == p.MyVote {
				label = "* " + label
			}
			b.WriteString(ListRow(w, label+" "+bar, right, i == s.cursor) + "\n")
		} else {
			b.WriteString(ListRow(w, label, "", i == s.cursor) + "\n")
		}
	}
	b.WriteString("\n")
	if !commPollOpen(*p, now) {
		b.WriteString(styleDim.Render(fmt.Sprintf("%d votes · poll closed", p.TotalVotes)) + "\n")
	} else if p.MyVote == 0 {
		b.WriteString(styleDim.Render("vote with 1-9 or enter to see results") + "\n")
	} else {
		b.WriteString(styleDim.Render(fmt.Sprintf("%d votes · your vote is marked *", p.TotalVotes)) + "\n")
	}
	return b.String()
}

func commDigit(s string) (int, bool) {
	if len(s) != 1 || s[0] < '1' || s[0] > '9' {
		return 0, false
	}
	return int(s[0] - '0'), true
}

// --- bulletins ---

type bulletinScreen struct {
	BaseScreen
	items []domain.Bulletin
	idx   int
	pager pager
}

func newBulletinScreen(a *App, _ any) Screen {
	s := &bulletinScreen{BaseScreen: BaseScreen{Route: RouteBulletins, TitleText: "Bulletins",
		Hints: "d dismiss  n/p next/prev  j/k scroll  r refresh  esc back"}}
	s.reload(a)
	return s
}

func (s *bulletinScreen) reload(a *App) {
	s.items = nil
	if !commSafeCommunity(a) {
		return
	}
	items, err := a.Community.Bulletins(context.Background(), a.User())
	if err != nil {
		a.Flash("%s", friendlyError(err))
		return
	}
	s.items = items
	if s.idx >= len(s.items) {
		s.idx = len(s.items) - 1
	}
	if s.idx < 0 {
		s.idx = 0
	}
	s.loadCurrent(a)
}

func (s *bulletinScreen) loadCurrent(a *App) {
	if s.idx < 0 || s.idx >= len(s.items) {
		s.pager.SetText("", a.W-2)
		return
	}
	s.pager.SetText(s.items[s.idx].Body, a.W-2)
}

func (s *bulletinScreen) Init(a *App) tea.Cmd { return nil }

func (s *bulletinScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return nil
	}
	height := a.BodyHeight() - 6
	if height < 1 {
		height = 1
	}
	switch key.String() {
	case "j", "down":
		s.pager.Move(1, height)
	case "k", "up":
		s.pager.Move(-1, height)
	case " ", "pgdown":
		s.pager.Move(height, height)
	case "pgup":
		s.pager.Move(-height, height)
	case "g":
		s.pager.Move(-len(s.pager.Lines()), height)
	case "G":
		s.pager.Move(len(s.pager.Lines()), height)
	case "n", "tab":
		if s.idx < len(s.items)-1 {
			s.idx++
			s.loadCurrent(a)
		}
	case "p", "shift+tab":
		if s.idx > 0 {
			s.idx--
			s.loadCurrent(a)
		}
	case "r":
		s.reload(a)
	case "d":
		return s.dismiss(a)
	}
	return nil
}

func (s *bulletinScreen) dismiss(a *App) tea.Cmd {
	if s.idx < 0 || s.idx >= len(s.items) || !commSafeCommunity(a) {
		return nil
	}
	if err := a.Community.Dismiss(context.Background(), a.User(), s.items[s.idx].ID); err != nil {
		return a.Errorf(err, "")
	}
	s.reload(a)
	a.Flash("bulletin dismissed")
	return nil
}

func (s *bulletinScreen) View(a *App) string {
	w := a.W
	height := a.BodyHeight() - 6
	if height < 1 {
		height = 1
	}
	var b strings.Builder
	b.WriteString(Section(w, "Bulletins") + "\n")
	if len(s.items) == 0 {
		b.WriteString(styleDim.Render("(no active bulletins — nice and quiet)") + "\n")
		return b.String()
	}
	cur := s.items[s.idx]
	b.WriteString(styleBold.Render(render.Clip(cur.Title, w)) + "\n")
	b.WriteString(styleDim.Render(fmt.Sprintf("%d/%d · updated %s", s.idx+1, len(s.items), commWhen(cur.UpdatedAt))) + "\n")
	b.WriteString(Rule(w) + "\n")
	b.WriteString(s.pager.View(w, height))
	return b.String()
}

// --- who's online ---

type commWhoTickMsg struct{}

func commWhoTickCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(time.Time) tea.Msg { return commWhoTickMsg{} })
}

type whoScreen struct {
	BaseScreen
	nodes  []hub.Node
	cursor int
}

func newWhoScreen(a *App, _ any) Screen {
	s := &whoScreen{BaseScreen: BaseScreen{Route: RouteWho, TitleText: "Who's online",
		Hints: "j/k move  r refresh  esc back"}}
	s.reload(a)
	return s
}

func (s *whoScreen) reload(a *App) {
	s.nodes = nil
	if a == nil || a.Presence == nil {
		return
	}
	s.nodes = a.Presence.List()
	if s.cursor >= len(s.nodes) {
		s.cursor = len(s.nodes) - 1
	}
	if s.cursor < 0 {
		s.cursor = 0
	}
}

func (s *whoScreen) Init(a *App) tea.Cmd {
	s.reload(a)
	return commWhoTickCmd()
}

func (s *whoScreen) Update(a *App, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case commWhoTickMsg:
		s.reload(a)
		return commWhoTickCmd()
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			if s.cursor < len(s.nodes)-1 {
				s.cursor++
			}
		case "k", "up":
			if s.cursor > 0 {
				s.cursor--
			}
		case "r":
			s.reload(a)
		}
	}
	return nil
}

func (s *whoScreen) View(a *App) string {
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, "Who's online") + "\n")
	if len(s.nodes) == 0 {
		b.WriteString(styleDim.Render("(nobody else is online)") + "\n")
		return b.String()
	}
	now := a.now()
	for i, n := range s.nodes {
		left := fmt.Sprintf("%2d  %-18s %s", n.Node, n.Handle, n.Activity)
		idle := commIdle(now.Sub(n.LastSeen))
		b.WriteString(ListRow(w, left, idle, i == s.cursor) + "\n")
	}
	return b.String()
}
