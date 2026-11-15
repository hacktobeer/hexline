package tui

import tea "github.com/charmbracelet/bubbletea"

// Route identifies a screen.
type Route string

// Screen routes.
const (
	RouteMain     Route = "main"
	RouteRegister Route = "register"
	RouteHelp     Route = "help"
	RouteProfile  Route = "profile"
	RoutePassword Route = "password"

	RouteBoards  Route = "boards"
	RouteThreads Route = "threads"
	RoutePosts   Route = "posts"
	RouteCompose Route = "compose"
	RouteSearch  Route = "search"

	RouteMail        Route = "mail"
	RouteMailView    Route = "mail/view"
	RouteMailCompose Route = "mail/compose"

	RouteFiles      Route = "files"
	RouteFileList   Route = "files/list"
	RouteFileDetail Route = "files/detail"
	RouteUpload     Route = "files/upload"

	RouteChat      Route = "chat"
	RouteOneliners Route = "oneliners"
	RoutePolls     Route = "polls"
	RoutePoll      Route = "poll"
	RouteBulletins Route = "bulletins"
	RouteWho       Route = "who"

	RouteAdmin          Route = "admin"
	RouteAdminUsers     Route = "admin/users"
	RouteAdminAreas     Route = "admin/areas"
	RouteAdminAudit     Route = "admin/audit"
	RouteAdminStats     Route = "admin/stats"
	RouteAdminBroadcast Route = "admin/broadcast"
)

// newScreen is the single navigation table. Feature files supply the
// constructors; missing screens resolve to nil.
func newScreen(a *App, r Route, arg any) Screen {
	switch r {
	case RouteMain:
		return newMainMenu(a, arg)
	case RouteRegister:
		return newRegisterScreen(a, arg)
	case RouteHelp:
		return newHelpScreen(a, arg)
	case RouteProfile:
		return newProfileScreen(a, arg)
	case RoutePassword:
		return newPasswordScreen(a, arg)

	case RouteBoards:
		return newBoardList(a, arg)
	case RouteThreads:
		return newThreadList(a, arg)
	case RoutePosts:
		return newPostView(a, arg)
	case RouteCompose:
		return newComposeScreen(a, arg)
	case RouteSearch:
		return newSearchScreen(a, arg)

	case RouteMail:
		return newMailInbox(a, arg)
	case RouteMailView:
		return newMailView(a, arg)
	case RouteMailCompose:
		return newMailCompose(a, arg)

	case RouteFiles:
		return newFileAreaList(a, arg)
	case RouteFileList:
		return newFileList(a, arg)
	case RouteFileDetail:
		return newFileDetail(a, arg)
	case RouteUpload:
		return newUploadScreen(a, arg)

	case RouteChat:
		return newChatScreen(a, arg)
	case RouteOneliners:
		return newOnelinerScreen(a, arg)
	case RoutePolls:
		return newPollList(a, arg)
	case RoutePoll:
		return newPollView(a, arg)
	case RouteBulletins:
		return newBulletinScreen(a, arg)
	case RouteWho:
		return newWhoScreen(a, arg)

	case RouteAdmin:
		return newAdminMenu(a, arg)
	case RouteAdminUsers:
		return newAdminUsers(a, arg)
	case RouteAdminAreas:
		return newAdminAreas(a, arg)
	case RouteAdminAudit:
		return newAdminAudit(a, arg)
	case RouteAdminStats:
		return newAdminStats(a, arg)
	case RouteAdminBroadcast:
		return newAdminBroadcast(a, arg)
	}
	return nil
}

// stubScreen is the placeholder used before a feature lands.
type stubScreen struct {
	BaseScreen
	body string
}

func newStub(route Route, title, hints string) *stubScreen {
	return &stubScreen{BaseScreen: BaseScreen{Route: route, TitleText: title, Hints: hints}, body: "(coming soon)"}
}

func (s *stubScreen) Init(a *App) tea.Cmd { return nil }

func (s *stubScreen) Update(a *App, msg tea.Msg) tea.Cmd { return nil }

func (s *stubScreen) View(a *App) string {
	return styleDim.Render(s.body)
}
