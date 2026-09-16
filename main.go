package main

import (
	"fyne.io/fyne/v2/app"

	"github.com/showx/TcpShow/internal/ui"
)

func main() {
	a := app.NewWithID("com.showx.tcpshow")
	a.Settings().SetTheme(&ui.Theme{})
	w := a.NewWindow("TcpShow")
	ui.Setup(w)
	w.ShowAndRun()
}
