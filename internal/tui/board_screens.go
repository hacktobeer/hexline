package tui

// Board screens: area list, thread list, post reader, composer, search.
// Implemented by the boards feature.

func newBoardList(a *App, arg any) Screen {
	return newStub(RouteBoards, "Boards", "enter open  esc back")
}

func newThreadList(a *App, arg any) Screen {
	return newStub(RouteThreads, "Threads", "enter read  esc back")
}

func newPostView(a *App, arg any) Screen {
	return newStub(RoutePosts, "Thread", "r reply  esc back")
}

func newComposeScreen(a *App, arg any) Screen {
	return newStub(RouteCompose, "Compose", "ctrl+s post  esc cancel")
}

func newSearchScreen(a *App, arg any) Screen {
	return newStub(RouteSearch, "Search", "enter search  esc back")
}
