package tui

// Community screens: chat, oneliners, polls, bulletins, who's online.

func newChatScreen(a *App, arg any) Screen {
	return newStub(RouteChat, "Chat", "enter send  esc back")
}

func newOnelinerScreen(a *App, arg any) Screen {
	return newStub(RouteOneliners, "One-liners", "enter post  esc back")
}

func newPollList(a *App, arg any) Screen {
	return newStub(RoutePolls, "Polls", "enter vote  esc back")
}

func newPollView(a *App, arg any) Screen {
	return newStub(RoutePoll, "Poll", "1-9 vote  esc back")
}

func newBulletinScreen(a *App, arg any) Screen {
	return newStub(RouteBulletins, "Bulletins", "esc back")
}

func newWhoScreen(a *App, arg any) Screen {
	return newStub(RouteWho, "Who's online", "esc back")
}
