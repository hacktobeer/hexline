package tui

// Mail screens: inbox, reader, composer.

func newMailInbox(a *App, arg any) Screen {
	return newStub(RouteMail, "Mail", "enter read  c compose  esc back")
}

func newMailView(a *App, arg any) Screen {
	return newStub(RouteMailView, "Message", "r reply  d delete  esc back")
}

func newMailCompose(a *App, arg any) Screen {
	return newStub(RouteMailCompose, "Compose mail", "ctrl+s send  esc cancel")
}
