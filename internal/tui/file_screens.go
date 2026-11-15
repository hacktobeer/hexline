package tui

// File screens: areas, listing, detail, upload.

func newFileAreaList(a *App, arg any) Screen {
	return newStub(RouteFiles, "Files", "enter open  esc back")
}

func newFileList(a *App, arg any) Screen {
	return newStub(RouteFileList, "Files", "enter detail  u upload  esc back")
}

func newFileDetail(a *App, arg any) Screen {
	return newStub(RouteFileDetail, "File", "d download  esc back")
}

func newUploadScreen(a *App, arg any) Screen {
	return newStub(RouteUpload, "Upload", "ctrl+s upload  esc cancel")
}
