package tui

// Sysop screens: menu, users, areas, audit, stats, broadcast.

func newAdminMenu(a *App, arg any) Screen {
	return newStub(RouteAdmin, "Sysop", "enter open  esc back")
}

func newAdminUsers(a *App, arg any) Screen {
	return newStub(RouteAdminUsers, "Users", "enter act  esc back")
}

func newAdminAreas(a *App, arg any) Screen {
	return newStub(RouteAdminAreas, "Areas", "esc back")
}

func newAdminAudit(a *App, arg any) Screen {
	return newStub(RouteAdminAudit, "Audit log", "esc back")
}

func newAdminStats(a *App, arg any) Screen {
	return newStub(RouteAdminStats, "Stats", "esc back")
}

func newAdminBroadcast(a *App, arg any) Screen {
	return newStub(RouteAdminBroadcast, "Broadcast", "ctrl+s send  esc cancel")
}
