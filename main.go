package main

import (
	_ "embed"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/showx/TcpShow/internal/ui"
)

//go:embed Icon.png
var iconData []byte

func main() {
	a := app.NewWithID("com.showx.tcpshow")
	icon := fyne.NewStaticResource("Icon.png", iconData)
	a.SetIcon(icon)
	a.Settings().SetTheme(&ui.Theme{})
	w := a.NewWindow("TcpShow")
	w.SetIcon(icon)
	ui.Setup(w)
	w.ShowAndRun()
}
