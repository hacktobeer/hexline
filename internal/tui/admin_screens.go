package tui

// Sysop screens: menu, users, areas, audit, stats, broadcast.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/hacktobeer/hexline/internal/domain"
	"github.com/hacktobeer/hexline/internal/render"
	"github.com/hacktobeer/hexline/internal/service"
)

// --- shared helpers ---

func admDenied(a *App) bool { return !a.IsModerator() }

func admDeniedView() string { return styleWarn.Render("permission denied") }

func admPageSize() int { return 20 }

func admBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func admRandomPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "changeme-now"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func admWhen(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

// --- menu ---

type adminMenu struct {
	BaseScreen
	menu   Menu
	stats  *service.Stats
	loaded bool
	err    string
}

type admStatsMsg struct {
	stats *service.Stats
	err   error
}

func newAdminMenu(a *App, _ any) Screen {
	m := &adminMenu{BaseScreen: BaseScreen{
		Route: RouteAdmin, TitleText: "Sysop",
		Hints: "enter open  p prune hint  esc back",
	}}
	m.menu = Menu{Items: []MenuItem{
		{Key: "u", Label: "Users", Hint: "roles, status, passwords", Route: RouteAdminUsers},
		{Key: "a", Label: "Areas", Hint: "create, ACLs, delete", Route: RouteAdminAreas},
		{Key: "l", Label: "Audit log", Hint: "privileged actions", Route: RouteAdminAudit},
		{Key: "s", Label: "Stats", Hint: "board counters", Route: RouteAdminStats},
		{Key: "b", Label: "Broadcast", Hint: "notice to every node", Route: RouteAdminBroadcast},
		{Key: "p", Label: "Prune", Hint: "retention: bbs admin prune --dry-run"},
	}}
	return m
}

func (m *adminMenu) Init(a *App) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	return func() tea.Msg {
		s, err := a.Admin.Stats(context.Background())
		return admStatsMsg{stats: s, err: err}
	}
}

func (m *adminMenu) Update(a *App, msg tea.Msg) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	switch msg := msg.(type) {
	case admStatsMsg:
		m.stats = msg.stats
		m.err = ""
		if msg.err != nil {
			m.err = friendlyError(msg.err)
		}
		m.loaded = true
		return nil
	case tea.KeyMsg:
		item, activate := m.menu.HandleKey(msg.String())
		if item == nil || !activate {
			return nil
		}
		if item.Route == "" {
			a.Flash("prune runs nightly; use `bbs admin prune --dry-run` to preview")
			return nil
		}
		return func() tea.Msg { return NavigateMsg{Route: item.Route, Arg: item.Arg} }
	}
	return nil
}

func (m *adminMenu) View(a *App) string {
	if admDenied(a) {
		return admDeniedView()
	}
	var b strings.Builder
	b.WriteString(Section(a.W, "Sysop menu") + "\n")
	if m.stats != nil {
		b.WriteString(styleDim.Render(fmt.Sprintf(
			"%d users (%d active, %d probation, %d suspended) · %d areas · %d files",
			m.stats.Users, m.stats.Active, m.stats.Probation, m.stats.Suspended,
			m.stats.Areas, m.stats.Files)) + "\n")
	}
	if m.err != "" {
		b.WriteString(styleWarn.Render("! "+m.err) + "\n")
	}
	b.WriteString("\n" + m.menu.View(a.W) + "\n\n")
	b.WriteString(styleDim.Render("Bulletins and polls are managed from `bbs admin bulletin|poll`.") + "\n")
	return b.String()
}

// --- users ---

type adminUsers struct {
	BaseScreen
	users    []domain.User
	total    int
	offset   int
	cursor   int
	mode     string // list, actions, password
	selected *domain.User
	password string
	err      string
	loaded   bool
}

type admUsersMsg struct {
	users  []domain.User
	total  int
	offset int
	err    error
}

func newAdminUsers(a *App, _ any) Screen {
	u := &adminUsers{BaseScreen: BaseScreen{
		Route: RouteAdminUsers, TitleText: "Users",
		Hints: "enter actions  n/p page  esc back",
	}, mode: "list"}
	return u
}

func (u *adminUsers) Init(a *App) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	return u.loadCmd(a)
}

func (u *adminUsers) loadCmd(a *App) tea.Cmd {
	offset := u.offset
	return func() tea.Msg {
		users, err := a.Store.ListUsers(admPageSize(), offset)
		total, terr := a.Store.CountUsers()
		if err == nil {
			err = terr
		}
		return admUsersMsg{users: users, total: total, offset: offset, err: err}
	}
}

func (u *adminUsers) ensureLoaded(a *App) {
	if u.loaded || admDenied(a) {
		return
	}
	users, err := a.Store.ListUsers(admPageSize(), u.offset)
	total, terr := a.Store.CountUsers()
	if err == nil {
		err = terr
	}
	u.apply(admUsersMsg{users: users, total: total, offset: u.offset, err: err})
}

func (u *adminUsers) apply(msg admUsersMsg) {
	u.users = msg.users
	u.total = msg.total
	u.offset = msg.offset
	u.loaded = true
	u.err = ""
	if msg.err != nil {
		u.err = friendlyError(msg.err)
	}
	if u.cursor >= len(u.users) {
		u.cursor = max(0, len(u.users)-1)
	}
}

func (u *adminUsers) Update(a *App, msg tea.Msg) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	switch msg := msg.(type) {
	case admUsersMsg:
		u.apply(msg)
		return nil
	case tea.KeyMsg:
		key := msg.String()
		if u.mode == "password" {
			u.mode = "list"
			u.password = ""
			return u.loadCmd(a)
		}
		if u.mode == "actions" {
			return u.actions(a, key)
		}
		switch key {
		case "up", "k":
			if u.cursor > 0 {
				u.cursor--
			}
		case "down", "j":
			if u.cursor < len(u.users)-1 {
				u.cursor++
			}
		case "n":
			if u.offset+admPageSize() < u.total {
				u.offset += admPageSize()
				u.cursor = 0
				u.loaded = false
				u.ensureLoaded(a)
			}
		case "p":
			if u.offset > 0 {
				u.offset -= admPageSize()
				if u.offset < 0 {
					u.offset = 0
				}
				u.cursor = 0
				u.loaded = false
				u.ensureLoaded(a)
			}
		case "enter", "right":
			if len(u.users) > 0 {
				sel := u.users[u.cursor]
				u.selected = &sel
				u.mode = "actions"
				u.err = ""
			}
		}
	}
	return nil
}

func (u *adminUsers) actions(a *App, key string) tea.Cmd {
	if u.selected == nil {
		u.mode = "list"
		return nil
	}
	target := u.selected
	ctx := context.Background()
	switch key {
	case "b", "left":
		u.mode = "list"
		u.err = ""
	case "p":
		if err := a.Auth.Promote(ctx, a.User(), target.ID); err != nil {
			u.err = friendlyError(err)
			return nil
		}
		a.Flash("%s promoted", target.Handle)
		u.mode = "list"
		return u.loadCmd(a)
	case "x":
		next := domain.StatusActive
		if target.Status == domain.StatusActive {
			next = domain.StatusSuspended
		}
		if err := a.Admin.SetUserStatus(ctx, a.User(), target.ID, next); err != nil {
			u.err = friendlyError(err)
			return nil
		}
		a.Flash("%s is now %s", target.Handle, next)
		u.mode = "list"
		return u.loadCmd(a)
	case "u", "m", "s":
		roles := map[string]domain.Role{"u": domain.RoleUser, "m": domain.RoleModerator, "s": domain.RoleSysop}
		role := roles[key]
		if err := a.Admin.SetUserRole(ctx, a.User(), target.ID, role); err != nil {
			u.err = friendlyError(err)
			return nil
		}
		a.Flash("%s is now %s", target.Handle, role)
		u.mode = "list"
		return u.loadCmd(a)
	case "r":
		if !a.IsSysop() {
			u.err = "permission denied"
			return nil
		}
		pass := admRandomPassword()
		if err := a.Auth.ResetPassword(ctx, target.Handle, pass); err != nil {
			u.err = friendlyError(err)
			return nil
		}
		u.password = pass
		u.mode = "password"
		a.Flash("password for %s reset", target.Handle)
		return nil
	case "a":
		return func() tea.Msg {
			return NavigateMsg{Route: RouteAdminAudit, Arg: admAuditFilter{
				UserID: target.ID, Handle: target.Handle,
			}}
		}
	}
	return nil
}

func (u *adminUsers) View(a *App) string {
	if admDenied(a) {
		return admDeniedView()
	}
	u.ensureLoaded(a)
	w := a.W
	if u.mode == "password" {
		var b strings.Builder
		b.WriteString(Section(w, "Password reset") + "\n\n")
		if u.selected != nil {
			b.WriteString("Handle: " + styleBold.Render(u.selected.Handle) + "\n")
		}
		b.WriteString("One-time password: " + styleOK.Render(u.password) + "\n\n")
		b.WriteString(styleWarn.Render("This is shown once. Hand it over securely.") + "\n")
		b.WriteString(styleDim.Render("press any key to return to the user list") + "\n")
		return b.String()
	}
	if u.mode == "actions" && u.selected != nil {
		var b strings.Builder
		b.WriteString(Section(w, "Action: "+u.selected.Handle) + "\n")
		b.WriteString(styleDim.Render(fmt.Sprintf("%s · %s · calls %d · created %s",
			u.selected.Role, u.selected.Status, u.selected.Calls, admWhen(u.selected.CreatedAt))) + "\n\n")
		rows := []struct{ key, label string }{
			{"p", "promote to active"},
			{"x", "suspend / activate"},
			{"u", "set role: user"},
			{"m", "set role: moderator"},
			{"s", "set role: sysop"},
			{"r", "reset password (generates one)"},
			{"a", "view audit for this user"},
			{"b", "back to list"},
		}
		for _, r := range rows {
			b.WriteString(fmt.Sprintf("[%s] %s\n", strings.ToUpper(r.key), r.label))
		}
		if u.err != "" {
			b.WriteString("\n" + styleWarn.Render("! "+render.Clip(u.err, w-2)) + "\n")
		}
		return b.String()
	}

	var b strings.Builder
	b.WriteString(Section(w, fmt.Sprintf("Users %d–%d of %d",
		min(u.offset+1, u.total), min(u.offset+len(u.users), u.total), u.total)) + "\n")
	if u.err != "" {
		b.WriteString(styleWarn.Render("! "+u.err) + "\n")
	}
	if len(u.users) == 0 {
		b.WriteString(styleDim.Render("(no accounts)") + "\n")
	}
	for i, user := range u.users {
		right := fmt.Sprintf("%s  %s  %d calls  %s", user.Role, user.Status, user.Calls,
			user.CreatedAt.Format("2006-01-02"))
		b.WriteString(ListRow(w, " "+user.Handle, right, i == u.cursor) + "\n")
	}
	return b.String()
}

// --- areas ---

type adminAreas struct {
	BaseScreen
	areas     []domain.Area
	fileAreas []domain.FileArea
	cursor    int
	mode      string // list, form, delete
	editing   *domain.Area
	fields    []textinput.Model
	focus     int
	err       string
	loaded    bool
}

type admAreasMsg struct {
	areas     []domain.Area
	fileAreas []domain.FileArea
	err       error
}

func newAdminAreas(a *App, _ any) Screen {
	return &adminAreas{BaseScreen: BaseScreen{
		Route: RouteAdminAreas, TitleText: "Areas",
		Hints: "c create  e edit ACL  d delete  esc back",
	}, mode: "list"}
}

func (v *adminAreas) Init(a *App) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	return v.loadCmd(a)
}

func (v *adminAreas) loadCmd(a *App) tea.Cmd {
	return func() tea.Msg {
		areas, err := a.Store.AdminListAreas()
		fas, ferr := a.Store.ListFileAreas()
		if err == nil {
			err = ferr
		}
		return admAreasMsg{areas: areas, fileAreas: fas, err: err}
	}
}

func (v *adminAreas) ensureLoaded(a *App) {
	if v.loaded || admDenied(a) {
		return
	}
	areas, err := a.Store.AdminListAreas()
	fas, ferr := a.Store.ListFileAreas()
	if err == nil {
		err = ferr
	}
	v.apply(admAreasMsg{areas: areas, fileAreas: fas, err: err})
}

func (v *adminAreas) apply(msg admAreasMsg) {
	v.areas = msg.areas
	v.fileAreas = msg.fileAreas
	v.loaded = true
	v.err = ""
	if msg.err != nil {
		v.err = friendlyError(msg.err)
	}
	if v.cursor >= len(v.areas) {
		v.cursor = max(0, len(v.areas)-1)
	}
}

func (v *adminAreas) openForm(a *App, existing *domain.Area) {
	v.mode = "form"
	v.editing = existing
	v.err = ""
	labels := []string{"tag", "name", "description", "acl read", "acl post", "acl moderate"}
	v.fields = nil
	for _, label := range labels {
		v.fields = append(v.fields, NewInput(label, 40))
	}
	v.fields[0].CharLimit = 24
	if existing != nil {
		v.fields[0].SetValue(existing.Tag)
		v.fields[1].SetValue(existing.Name)
		v.fields[2].SetValue(existing.Description)
		v.fields[3].SetValue(domain.FormatACL(existing.ACL.Read))
		v.fields[4].SetValue(domain.FormatACL(existing.ACL.Post))
		v.fields[5].SetValue(domain.FormatACL(existing.ACL.Moderate))
	} else {
		v.fields[0].Placeholder = "e.g. retro"
		v.fields[3].SetValue("user")
		v.fields[4].SetValue("user")
		v.fields[5].SetValue("moderator")
	}
	for i := range v.fields {
		v.fields[i].Blur()
	}
	v.focus = 0
	v.fields[0].Focus()
}

func (v *adminAreas) Update(a *App, msg tea.Msg) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	switch msg := msg.(type) {
	case admAreasMsg:
		v.apply(msg)
		return nil
	case tea.KeyMsg:
		key := msg.String()
		switch v.mode {
		case "delete":
			switch key {
			case "y":
				if v.editing == nil {
					v.mode = "list"
					return nil
				}
				if err := a.Admin.DeleteArea(context.Background(), a.User(), v.editing.ID, false); err != nil {
					v.err = friendlyError(err)
					v.mode = "list"
					return nil
				}
				a.Flash("area %s deleted", v.editing.Tag)
				v.mode = "list"
				v.loaded = false
				return v.loadCmd(a)
			case "n":
				v.mode = "list"
				v.editing = nil
				v.err = ""
			}
			return nil
		case "form":
			return v.formUpdate(a, msg)
		}
		switch key {
		case "up", "k":
			if v.cursor > 0 {
				v.cursor--
			}
		case "down", "j":
			if v.cursor < len(v.areas)-1 {
				v.cursor++
			}
		case "c":
			v.openForm(a, nil)
		case "e":
			if len(v.areas) > 0 {
				area := v.areas[v.cursor]
				v.openForm(a, &area)
			}
		case "d":
			if len(v.areas) > 0 {
				area := v.areas[v.cursor]
				v.editing = &area
				v.mode = "delete"
				v.err = ""
			}
		}
	}
	return nil
}

func (v *adminAreas) formUpdate(a *App, msg tea.Msg) tea.Cmd {
	switch key := msg.(tea.KeyMsg).String(); key {
	case "tab", "down":
		v.fields[v.focus].Blur()
		v.focus = (v.focus + 1) % len(v.fields)
		v.fields[v.focus].Focus()
		return nil
	case "shift+tab", "up":
		v.fields[v.focus].Blur()
		v.focus = (v.focus - 1 + len(v.fields)) % len(v.fields)
		v.fields[v.focus].Focus()
		return nil
	case "ctrl+s":
		return v.submit(a)
	}
	var cmd tea.Cmd
	v.fields[v.focus], cmd = v.fields[v.focus].Update(msg)
	return cmd
}

func (v *adminAreas) submit(a *App) tea.Cmd {
	tag := strings.TrimSpace(v.fields[0].Value())
	name := strings.TrimSpace(v.fields[1].Value())
	desc := strings.TrimSpace(v.fields[2].Value())
	readACL := v.fields[3].Value()
	postACL := v.fields[4].Value()
	modACL := v.fields[5].Value()
	ctx := context.Background()
	if v.editing == nil {
		area, err := a.Admin.CreateArea(ctx, a.User(), tag, name, desc, 10,
			readACL, postACL, modACL)
		if err != nil {
			v.err = friendlyError(err)
			return nil
		}
		a.Flash("area %s created", area.Tag)
	} else {
		err := a.Admin.UpdateArea(ctx, a.User(), v.editing.ID, name, desc, v.editing.SortOrder,
			readACL, postACL, modACL, v.editing.RetentionDays, v.editing.RateLimitPerHour)
		if err != nil {
			v.err = friendlyError(err)
			return nil
		}
		a.Flash("area %s updated", v.editing.Tag)
	}
	v.mode = "list"
	v.editing = nil
	v.fields = nil
	v.loaded = false
	return v.loadCmd(a)
}

func (v *adminAreas) View(a *App) string {
	if admDenied(a) {
		return admDeniedView()
	}
	v.ensureLoaded(a)
	w := a.W
	if v.mode == "delete" && v.editing != nil {
		var b strings.Builder
		b.WriteString(Section(w, "Delete area") + "\n\n")
		b.WriteString(fmt.Sprintf("Delete %s — %s?\n", styleBold.Render(v.editing.Tag), v.editing.Name))
		b.WriteString(styleWarn.Render("This cannot be undone. Areas with threads are refused.") + "\n\n")
		b.WriteString("y confirm   n cancel\n")
		if v.err != "" {
			b.WriteString("\n" + styleWarn.Render("! "+v.err) + "\n")
		}
		return b.String()
	}
	if v.mode == "form" {
		var b strings.Builder
		title := "New area"
		if v.editing != nil {
			title = "Edit area " + v.editing.Tag
		}
		b.WriteString(Section(w, title) + "\n\n")
		labels := []string{"Tag (lowercase, 2-24)", "Name", "Description", "Read ACL", "Post ACL", "Moderate ACL"}
		for i, f := range v.fields {
			b.WriteString(LabeledInput(labels[i], f) + "\n")
		}
		b.WriteString(styleDim.Render("ACLs are comma-separated roles: user, moderator, sysop") + "\n")
		if v.err != "" {
			b.WriteString("\n" + styleWarn.Render("! "+render.Clip(v.err, w-2)) + "\n")
		}
		return b.String()
	}

	var b strings.Builder
	b.WriteString(Section(w, "Message areas") + "\n")
	if v.err != "" {
		b.WriteString(styleWarn.Render("! "+v.err) + "\n")
	}
	if len(v.areas) == 0 {
		b.WriteString(styleDim.Render("(none)") + "\n")
	}
	for i, area := range v.areas {
		right := fmt.Sprintf("read %s · post %s · mod %s",
			domain.FormatACL(area.ACL.Read), domain.FormatACL(area.ACL.Post),
			domain.FormatACL(area.ACL.Moderate))
		b.WriteString(ListRow(w, " "+area.Tag+" — "+area.Name, right, i == v.cursor) + "\n")
	}
	b.WriteString("\n" + Section(w, "File areas") + "\n")
	if len(v.fileAreas) == 0 {
		b.WriteString(styleDim.Render("(none)") + "\n")
	}
	for _, area := range v.fileAreas {
		right := fmt.Sprintf("read %s · upload %s · %s",
			domain.FormatACL(area.ACL.Read), domain.FormatACL(area.ACL.Post), admBytes(area.QuotaBytes))
		b.WriteString(ListRow(w, " "+area.Tag+" — "+area.Name, right, false) + "\n")
	}
	return b.String()
}

// --- audit ---

type admAuditFilter struct {
	UserID string
	Handle string
}

type adminAudit struct {
	BaseScreen
	all      []domain.AuditEntry
	entries  []domain.AuditEntry
	page     int
	pageSize int
	filter   admAuditFilter
	loaded   bool
	err      string
}

type admAuditMsg struct {
	entries []domain.AuditEntry
	err     error
}

func newAdminAudit(a *App, arg any) Screen {
	v := &adminAudit{BaseScreen: BaseScreen{
		Route: RouteAdminAudit, TitleText: "Audit log",
		Hints: "n/p page  esc back",
	}, pageSize: 15}
	if f, ok := arg.(admAuditFilter); ok {
		v.filter = f
		v.TitleText = "Audit — " + f.Handle
	}
	return v
}

func (v *adminAudit) Init(a *App) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	return v.loadCmd(a)
}

func (v *adminAudit) loadCmd(a *App) tea.Cmd {
	limit := 100
	if v.filter.UserID != "" || v.filter.Handle != "" {
		limit = 500
	}
	return func() tea.Msg {
		entries, err := a.Admin.ListAudit(context.Background(), limit)
		return admAuditMsg{entries: entries, err: err}
	}
}

func (v *adminAudit) ensureLoaded(a *App) {
	if v.loaded || admDenied(a) {
		return
	}
	limit := 100
	if v.filter.UserID != "" || v.filter.Handle != "" {
		limit = 500
	}
	entries, err := a.Admin.ListAudit(context.Background(), limit)
	v.apply(admAuditMsg{entries: entries, err: err})
}

func (v *adminAudit) apply(msg admAuditMsg) {
	v.loaded = true
	v.err = ""
	if msg.err != nil {
		v.err = friendlyError(msg.err)
	}
	v.all = v.all[:0]
	for _, e := range msg.entries {
		if !admAuditMatches(e, v.filter) {
			continue
		}
		v.all = append(v.all, e)
	}
	v.clamp()
}

func admAuditMatches(e domain.AuditEntry, f admAuditFilter) bool {
	if f.UserID == "" && f.Handle == "" {
		return true
	}
	if f.UserID != "" && (e.ActorID == f.UserID || e.TargetID == f.UserID) {
		return true
	}
	if f.Handle != "" && strings.EqualFold(e.Actor, f.Handle) {
		return true
	}
	return false
}

func (v *adminAudit) clamp() {
	pages := (len(v.all) + v.pageSize - 1) / v.pageSize
	if pages < 1 {
		pages = 1
	}
	if v.page >= pages {
		v.page = pages - 1
	}
	if v.page < 0 {
		v.page = 0
	}
	start := v.page * v.pageSize
	end := start + v.pageSize
	if start > len(v.all) {
		start = len(v.all)
	}
	if end > len(v.all) {
		end = len(v.all)
	}
	v.entries = v.all[start:end]
}

func (v *adminAudit) Update(a *App, msg tea.Msg) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	switch msg := msg.(type) {
	case admAuditMsg:
		v.apply(msg)
		return nil
	case tea.KeyMsg:
		switch msg.String() {
		case "n", "right":
			v.page++
			v.clamp()
		case "p", "left":
			v.page--
			v.clamp()
		}
	}
	return nil
}

func (v *adminAudit) View(a *App) string {
	if admDenied(a) {
		return admDeniedView()
	}
	v.ensureLoaded(a)
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, v.TitleText) + "\n")
	if v.err != "" {
		b.WriteString(styleWarn.Render("! "+v.err) + "\n")
	}
	if len(v.all) == 0 {
		b.WriteString(styleDim.Render("(no audit entries)") + "\n")
		return b.String()
	}
	pages := (len(v.all) + v.pageSize - 1) / v.pageSize
	b.WriteString(styleDim.Render(fmt.Sprintf("%d entries · page %d/%d", len(v.all), v.page+1, pages)) + "\n")
	for _, e := range v.entries {
		actor := e.Actor
		if actor == "" {
			actor = "system"
		}
		target := e.TargetKind
		if e.TargetID != "" {
			target += ":" + e.TargetID
		}
		left := e.At.UTC().Format("01-02 15:04") + "  " + actor
		right := e.Action + "  " + target
		b.WriteString(ListRow(w, " "+left, right, false) + "\n")
	}
	return b.String()
}

// --- stats ---

type adminStats struct {
	BaseScreen
	stats  *service.Stats
	loaded bool
	err    string
}

type admStatsScreenMsg struct {
	stats *service.Stats
	err   error
}

func newAdminStats(a *App, _ any) Screen {
	return &adminStats{BaseScreen: BaseScreen{
		Route: RouteAdminStats, TitleText: "Stats", Hints: "r refresh  esc back",
	}}
}

func (v *adminStats) Init(a *App) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	return func() tea.Msg {
		s, err := a.Admin.Stats(context.Background())
		return admStatsScreenMsg{stats: s, err: err}
	}
}

func (v *adminStats) ensureLoaded(a *App) {
	if v.loaded || admDenied(a) {
		return
	}
	s, err := a.Admin.Stats(context.Background())
	v.stats = s
	v.loaded = true
	if err != nil {
		v.err = friendlyError(err)
	}
}

func (v *adminStats) Update(a *App, msg tea.Msg) tea.Cmd {
	if admDenied(a) {
		return nil
	}
	switch msg := msg.(type) {
	case admStatsScreenMsg:
		v.stats = msg.stats
		v.loaded = true
		v.err = ""
		if msg.err != nil {
			v.err = friendlyError(msg.err)
		}
	case tea.KeyMsg:
		if msg.String() == "r" {
			return v.Init(a)
		}
	}
	return nil
}

func (v *adminStats) View(a *App) string {
	if admDenied(a) {
		return admDeniedView()
	}
	v.ensureLoaded(a)
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, "Board stats") + "\n")
	if v.err != "" {
		b.WriteString(styleWarn.Render("! "+v.err) + "\n")
	}
	if v.stats == nil {
		b.WriteString(styleDim.Render("(no data)") + "\n")
		return b.String()
	}
	s := v.stats
	rows := []struct {
		key, value string
	}{
		{"Users", itoa(s.Users)},
		{"Active", itoa(s.Active)},
		{"Probation", itoa(s.Probation)},
		{"Suspended", itoa(s.Suspended)},
		{"Message areas", itoa(s.Areas)},
		{"Threads", itoa(s.Threads)},
		{"Posts", itoa(s.Posts)},
		{"File areas", itoa(s.FileAreas)},
		{"Files", itoa(s.Files)},
		{"Mail", itoa(s.Mail)},
		{"One-liners", itoa(s.Oneliners)},
		{"Sessions (24h)", itoa(s.Sessions24h)},
		{"Database", admBytes(s.DBBytes)},
	}
	for _, row := range rows {
		b.WriteString(ListRow(w, " "+row.key, row.value, false) + "\n")
	}
	return b.String()
}

// --- broadcast ---

type adminBroadcast struct {
	BaseScreen
	area textarea.Model
	sent bool
	err  string
}

func newAdminBroadcast(a *App, _ any) Screen {
	ta := textarea.New()
	ta.Placeholder = "Message every connected caller will see…"
	ta.SetWidth(60)
	ta.SetHeight(5)
	ta.CharLimit = 2000
	ta.Focus()
	return &adminBroadcast{BaseScreen: BaseScreen{
		Route: RouteAdminBroadcast, TitleText: "Broadcast",
		Hints: "ctrl+s send  esc cancel",
	}, area: ta}
}

func (v *adminBroadcast) Init(a *App) tea.Cmd { return textarea.Blink }

func (v *adminBroadcast) Update(a *App, msg tea.Msg) tea.Cmd {
	if !a.IsSysop() {
		return nil
	}
	key, isKey := msg.(tea.KeyMsg)
	if isKey && key.String() == "ctrl+s" {
		text := strings.TrimSpace(v.area.Value())
		if err := a.Admin.Broadcast(context.Background(), a.User(), text); err != nil {
			v.err = friendlyError(err)
			v.sent = false
			return nil
		}
		v.err = ""
		v.sent = true
		a.Flash("notice published to every node")
		v.area.Reset()
		return nil
	}
	var cmd tea.Cmd
	v.area, cmd = v.area.Update(msg)
	return cmd
}

func (v *adminBroadcast) View(a *App) string {
	if !a.IsSysop() {
		return admDeniedView()
	}
	w := a.W
	var b strings.Builder
	b.WriteString(Section(w, "Broadcast notice") + "\n\n")
	b.WriteString(styleDim.Render("Publishes a notice to every connected session (scope \"*\").") + "\n\n")
	b.WriteString(v.area.View() + "\n")
	if v.sent {
		b.WriteString(styleOK.Render("✓ notice published") + "\n")
	}
	if v.err != "" {
		b.WriteString(styleWarn.Render("! "+render.Clip(v.err, w-2)) + "\n")
	}
	return b.String()
}
