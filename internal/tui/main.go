package tui

import (
	"context"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/render"
)

type mainMenu struct {
	BaseScreen
	menu   Menu
	counts mainCountsMsg
	loaded bool
}

type mainCountsMsg struct {
	boards int
	mail   int
	err    error
}

func newMainMenu(a *App, _ any) Screen {
	m := &mainMenu{BaseScreen: BaseScreen{Route: RouteMain, TitleText: "Main", Hints: "b boards  m mail  f files  c chat  o one-liners  l bulletins  w who  s settings  q quit"}}
	items := []MenuItem{
		{Key: "b", Label: "Boards", Hint: "", Route: RouteBoards},
		{Key: "m", Label: "Mail", Hint: "", Route: RouteMail},
		{Key: "f", Label: "Files", Hint: "", Route: RouteFiles},
		{Key: "c", Label: "Chat", Hint: "", Route: RouteChat},
		{Key: "o", Label: "One-liners", Hint: "", Route: RouteOneliners},
		{Key: "p", Label: "Polls", Hint: "", Route: RoutePolls},
		{Key: "l", Label: "Bulletins", Hint: "", Route: RouteBulletins},
		{Key: "w", Label: "Who's online", Hint: "", Route: RouteWho},
		{Key: "s", Label: "Settings", Hint: "", Route: RouteProfile},
		{Key: "?", Label: "Help", Hint: "", Route: RouteHelp},
	}
	if a.Sess.ReadOnly {
		items = items[:0]
		items = append(items,
			MenuItem{Key: "b", Label: "Boards", Route: RouteBoards},
			MenuItem{Key: "f", Label: "Files", Route: RouteFiles},
			MenuItem{Key: "w", Label: "Who's online", Route: RouteWho},
			MenuItem{Key: "?", Label: "Help", Route: RouteHelp},
		)
	}
	if a.IsModerator() {
		items = append(items, MenuItem{Key: "a", Label: "Sysop menu", Route: RouteAdmin})
	}
	if a.IsSysop() {
		items = append(items, MenuItem{Key: "a", Label: "Sysop menu", Route: RouteAdmin})
	}
	m.menu = Menu{Items: dedupeMenu(items)}
	return m
}

func dedupeMenu(items []MenuItem) []MenuItem {
	seen := map[string]bool{}
	out := items[:0]
	for _, it := range items {
		if seen[it.Key] {
			continue
		}
		seen[it.Key] = true
		out = append(out, it)
	}
	return out
}

func (m *mainMenu) Init(a *App) tea.Cmd {
	u := a.User()
	if u == nil || a.Sess.ReadOnly {
		m.loaded = true
		return nil
	}
	return func() tea.Msg {
		var msg mainCountsMsg
		msg.boards, msg.err = a.Boards.UnreadTotal(context.Background(), u.ID)
		if msg.err == nil {
			msg.mail, msg.err = a.Mail.UnreadCount(context.Background(), u.ID)
		}
		return msg
	}
}

func (m *mainMenu) Update(a *App, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case mainCountsMsg:
		m.counts = msg
		m.loaded = true
		return nil
	case tea.KeyMsg:
		key := msg.String()
		if key == "q" {
			return func() tea.Msg { return QuitMsg{} }
		}
		item, activate := m.menu.HandleKey(key)
		if item != nil && activate {
			return func() tea.Msg {
				return NavigateMsg{Route: item.Route, Arg: item.Arg}
			}
		}
	}
	return nil
}

func (m *mainMenu) View(a *App) string {
	w := a.W
	var b strings.Builder

	u := a.User()
	greeting := "Welcome, caller."
	if u != nil {
		greeting = "Welcome back, " + u.Handle + "."
		if u.IsProbation() {
			greeting += " You are on probation: uploads and links are off until you have 10 posts over 3 days."
		}
	}
	b.WriteString(styleBold.Render(render.Clip(greeting, w)) + "\n")

	if m.loaded && !a.Sess.ReadOnly {
		status := "  no new mail"
		if m.counts.mail > 0 {
			status = styleOK.Render("  " + itoa(m.counts.mail) + " new mail")
		}
		posts := ""
		if m.counts.boards > 0 {
			posts = styleOK.Render("  " + itoa(m.counts.boards) + " unread posts")
		}
		b.WriteString(status + posts + "\n")
	}
	b.WriteString("\n")

	// Refresh hints with live counts on the relevant rows.
	for i := range m.menu.Items {
		switch m.menu.Items[i].Route {
		case RouteBoards:
			if m.counts.boards > 0 {
				m.menu.Items[i].Hint = itoa(m.counts.boards) + " unread"
			}
		case RouteMail:
			if m.counts.mail > 0 {
				m.menu.Items[i].Hint = itoa(m.counts.mail) + " unread"
			}
		}
	}
	b.WriteString(m.menu.View(w) + "\n\n")

	motd := a.Cfg.UI.MOTD
	if strings.TrimSpace(motd) == "" {
		motd = "No MOTD set. Posterity is watching — post something worth reading."
	}
	b.WriteString(styleDim.Render("── today ──") + "\n")
	b.WriteString(render.Render(motd, render.Options{Width: w - 2, ANSI: true}))

	return b.String()
}
