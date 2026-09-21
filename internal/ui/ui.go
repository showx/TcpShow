package ui

import (
	"fmt"
	"image/color"
	"strconv"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/showx/TcpShow/internal/ca"
	"github.com/showx/TcpShow/internal/proxy"
	"github.com/showx/TcpShow/internal/store"
	"github.com/showx/TcpShow/internal/sysproxy"
)

var cols = []string{"#", "方法", "状态", "主机", "路径", "类型", "大小", "耗时"}

type App struct {
	win     fyne.Window
	store   *store.Store
	proxy   *proxy.Proxy
	issuer  *ca.Issuer

	portEntry   *widget.Entry
	filterEntry *widget.Entry
	recordCheck *widget.Check
	sysCheck    *widget.Check
	startBtn    *widget.Button
	status      *widget.Label
	table       *widget.Table
	reqHead     *widget.Entry
	reqBody     *widget.Entry
	respHead    *widget.Entry
	respBody    *widget.Entry
	urlLabel    *widget.Label

	view       []*store.Session
	selected   *store.Session
	sysOn      bool
	certOK     bool
	refreshing atomic.Bool
}

func Setup(w fyne.Window) {
	issuer, err := ca.LoadOrCreate()
	if err != nil {
		dialog.ShowError(err, w)
	}
	st := store.New()
	a := &App{
		win:    w,
		store:  st,
		issuer: issuer,
		proxy:  proxy.New(issuer, st),
	}
	w.SetContent(a.build())
	w.Resize(fyne.NewSize(1280, 780))
	w.SetMaster()
	w.SetMainMenu(fyne.NewMainMenu(
		fyne.NewMenu("文件",
			fyne.NewMenuItem("安装 CA 证书", a.installCert),
			fyne.NewMenuItem("复制为 cURL", a.copyCurl),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("清空记录", func() {
				a.selected = nil
				a.store.Clear()
				a.showSession(nil)
			}),
		),
		fyne.NewMenu("帮助",
			fyne.NewMenuItem("关于 TcpShow", func() {
				dialog.ShowInformation("关于 TcpShow", "简单的 HTTP/HTTPS 抓包软件。\n默认代理端口 8888。", a.win)
			}),
		),
	))
	w.SetCloseIntercept(func() {
		a.shutdown()
		w.Close()
	})
	st.OnChange(a.scheduleRefresh)
	a.certOK = sysproxy.CertTrusted()
	a.startProxy()
	a.syncStartBtn()
}

func (a *App) build() fyne.CanvasObject {
	a.portEntry = widget.NewEntry()
	a.portEntry.SetText("8888")
	a.portEntry.SetPlaceHolder("端口")

	a.startBtn = widget.NewButton("停止", a.toggleProxy)
	a.startBtn.Importance = widget.DangerImportance

	a.recordCheck = widget.NewCheck("录制", func(v bool) {
		a.store.SetRecording(v)
		a.refreshStatus()
	})
	a.recordCheck.SetChecked(true)

	a.sysCheck = widget.NewCheck("系统代理", func(v bool) {
		a.toggleSysProxy(v)
	})

	clearBtn := widget.NewButton("清空", func() {
		a.selected = nil
		a.store.Clear()
		a.showSession(nil)
	})
	caBtn := widget.NewButton("安装证书", a.installCert)
	curlBtn := widget.NewButton("复制 cURL", a.copyCurl)

	a.filterEntry = widget.NewEntry()
	a.filterEntry.SetPlaceHolder("过滤 method / host / path")
	a.filterEntry.OnChanged = func(string) { a.scheduleRefresh() }

	toolbar := container.NewHBox(
		widget.NewLabel("端口"),
		sized(a.portEntry, 70),
		a.startBtn,
		a.recordCheck,
		a.sysCheck,
		clearBtn,
		caBtn,
		curlBtn,
	)
	top := container.NewBorder(nil, nil, nil, nil, container.NewVBox(
		toolbar,
		a.filterEntry,
	))

	a.urlLabel = widget.NewLabel("选择一条请求")
	a.urlLabel.Wrapping = fyne.TextWrapBreak
	a.urlLabel.TextStyle = fyne.TextStyle{Monospace: true}

	a.reqHead = newReadView()
	a.reqBody = newReadView()
	a.respHead = newReadView()
	a.respBody = newReadView()

	reqSplit := container.NewVSplit(scroll(a.reqHead), scroll(a.reqBody))
	reqSplit.SetOffset(0.4)
	respSplit := container.NewVSplit(scroll(a.respHead), scroll(a.respBody))
	respSplit.SetOffset(0.4)

	tabs := container.NewAppTabs(
		container.NewTabItem("请求", reqSplit),
		container.NewTabItem("响应", respSplit),
	)
	detail := container.NewBorder(a.urlLabel, nil, nil, nil, tabs)

	a.table = widget.NewTable(
		func() (int, int) { return len(a.view), len(cols) },
		func() fyne.CanvasObject {
			label := widget.NewLabel(" ")
			label.Truncation = fyne.TextTruncateEllipsis
			return label
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			label := o.(*widget.Label)
			if id.Row < 0 || id.Row >= len(a.view) {
				label.SetText("")
				return
			}
			s := a.view[id.Row]
			label.TextStyle = fyne.TextStyle{Monospace: id.Col == 0 || id.Col == 1 || id.Col == 2}
			label.SetText(cellText(s, id.Col))
		},
	)
	a.table.ShowHeaderRow = true
	a.table.CreateHeader = func() fyne.CanvasObject {
		l := widget.NewLabel(" ")
		l.TextStyle = fyne.TextStyle{Bold: true}
		return l
	}
	a.table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		l := o.(*widget.Label)
		if id.Col >= 0 && id.Col < len(cols) {
			l.SetText(cols[id.Col])
		}
	}
	a.table.OnSelected = func(id widget.TableCellID) {
		if id.Row >= 0 && id.Row < len(a.view) {
			a.selected = a.view[id.Row]
			a.showSession(a.selected)
		}
	}
	a.table.SetColumnWidth(0, 50)
	a.table.SetColumnWidth(1, 70)
	a.table.SetColumnWidth(2, 60)
	a.table.SetColumnWidth(3, 180)
	a.table.SetColumnWidth(4, 220)
	a.table.SetColumnWidth(5, 90)
	a.table.SetColumnWidth(6, 80)
	a.table.SetColumnWidth(7, 70)

	split := container.NewHSplit(a.table, detail)
	split.SetOffset(0.52)

	a.status = widget.NewLabel("")
	a.refreshStatus()

	return container.NewBorder(top, a.status, nil, nil, split)
}

func (a *App) toggleProxy() {
	if a.proxy.Running() {
		a.stopProxy()
		return
	}
	a.startProxy()
}

func (a *App) startProxy() {
	port := stringsTrim(a.portEntry.Text)
	if _, err := strconv.Atoi(port); err != nil {
		dialog.ShowError(fmt.Errorf("端口无效"), a.win)
		return
	}
	if err := a.proxy.Start(":" + port); err != nil {
		a.syncStartBtn()
		dialog.ShowError(err, a.win)
		return
	}
	a.syncStartBtn()
	a.refreshStatus()
}

func (a *App) stopProxy() {
	_ = a.proxy.Stop()
	if a.sysOn {
		a.sysCheck.SetChecked(false)
	}
	a.syncStartBtn()
	a.refreshStatus()
}

func (a *App) syncStartBtn() {
	if a.proxy != nil && a.proxy.Running() {
		a.startBtn.SetText("停止")
		a.startBtn.Importance = widget.DangerImportance
		a.portEntry.Disable()
		return
	}
	a.startBtn.SetText("启动")
	a.startBtn.Importance = widget.HighImportance
	a.portEntry.Enable()
}

func (a *App) toggleSysProxy(on bool) {
	port := stringsTrim(a.portEntry.Text)
	if on {
		if !a.proxy.Running() {
			a.sysCheck.SetChecked(false)
			dialog.ShowInformation("系统代理", "请先启动抓包代理", a.win)
			return
		}
		if err := sysproxy.Set("127.0.0.1", port); err != nil {
			a.sysCheck.SetChecked(false)
			dialog.ShowError(err, a.win)
			return
		}
		a.sysOn = true
	} else if a.sysOn {
		if err := sysproxy.Clear(); err != nil {
			dialog.ShowError(err, a.win)
		}
		a.sysOn = false
	}
	a.refreshStatus()
}

func (a *App) installCert() {
	if a.issuer == nil {
		dialog.ShowError(fmt.Errorf("证书未生成"), a.win)
		return
	}
	path := a.issuer.CertPEMPath()
	if sysproxy.CertTrusted() {
		a.onCertReady(path)
		return
	}
	go func() {
		err := sysproxy.TrustCert(path)
		fyne.Do(func() {
			if err != nil {
				dialog.ShowError(fmt.Errorf("信任证书失败：%v\n\n也可以手动：钥匙串访问 → 系统 → TcpShow CA → 信任 → 始终信任", err), a.win)
				a.refreshStatus()
				return
			}
			a.onCertReady(path)
		})
	}()
}

func (a *App) onCertReady(path string) {
	a.certOK = true
	if !a.sysOn && a.proxy != nil && a.proxy.Running() {
		a.sysCheck.SetChecked(true)
	}
	a.refreshStatus()
	dialog.ShowInformation("证书已就绪",
		"TcpShow CA 已设为系统信任的根证书，系统代理已打开。\n\n"+
			"请完全退出并重新打开浏览器，再访问 https 网站。\n\n"+
			"Firefox 不使用系统钥匙串，需要在 Firefox 里单独导入：\n"+path,
		a.win)
}

func (a *App) copyCurl() {
	if a.selected == nil {
		dialog.ShowInformation("复制 cURL", "请先选择一条请求", a.win)
		return
	}
	a.win.Clipboard().SetContent(a.selected.Curl())
}

func (a *App) showSession(s *store.Session) {
	if s == nil {
		a.urlLabel.SetText("选择一条请求")
		a.reqHead.SetText("")
		a.reqBody.SetText("")
		a.respHead.SetText("")
		a.respBody.SetText("")
		return
	}
	a.urlLabel.SetText(fmt.Sprintf("%s %s", s.Method, s.URL))
	a.reqHead.SetText(s.RequestRaw())
	a.reqBody.SetText(s.ReqDisplay)
	a.respHead.SetText(s.ResponseRaw())
	a.respBody.SetText(s.RespDisplay)
}

func (a *App) scheduleRefresh() {
	if !a.refreshing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		time.Sleep(40 * time.Millisecond)
		fyne.Do(func() {
			a.refreshing.Store(false)
			a.reload()
		})
	}()
}

func (a *App) reload() {
	var keepID int
	if a.selected != nil {
		keepID = a.selected.ID
	}
	a.view = a.store.Filtered(a.filterEntry.Text)
	a.table.Refresh()
	if keepID != 0 {
		for i, s := range a.view {
			if s.ID == keepID {
				a.selected = s
				a.showSession(s)
				a.table.Select(widget.TableCellID{Row: i, Col: 0})
				break
			}
		}
	}
	a.refreshStatus()
}

func (a *App) refreshStatus() {
	if a.status == nil {
		return
	}
	state := "已停止"
	if a.proxy != nil && a.proxy.Running() {
		state = "监听 " + a.proxy.Addr()
	}
	rec := "暂停"
	if a.store.Recording() {
		rec = "录制中"
	}
	sys := ""
	if a.sysOn {
		sys = "  ·  系统代理已开"
	}
	cert := "证书未信任"
	if a.certOK {
		cert = "证书已信任"
	}
	a.status.SetText(fmt.Sprintf("%s  ·  %s  ·  %s  ·  %d 条%s", state, rec, cert, a.store.Len(), sys))
}

func (a *App) shutdown() {
	if a.sysOn {
		_ = sysproxy.Clear()
		a.sysOn = false
	}
	if a.proxy != nil {
		_ = a.proxy.Stop()
	}
}

func cellText(s *store.Session, col int) string {
	switch col {
	case 0:
		return strconv.Itoa(s.ID)
	case 1:
		return s.Method
	case 2:
		return s.StatusText()
	case 3:
		return s.Host
	case 4:
		return s.Path
	case 5:
		ct := s.ContentType
		if i := indexByte(ct, ';'); i >= 0 {
			ct = ct[:i]
		}
		return ct
	case 6:
		return s.SizeText()
	case 7:
		return s.TimeText()
	}
	return ""
}

func newReadView() *widget.Entry {
	e := widget.NewMultiLineEntry()
	e.Wrapping = fyne.TextWrapOff
	e.TextStyle = fyne.TextStyle{Monospace: true}
	return e
}

func scroll(o fyne.CanvasObject) fyne.CanvasObject {
	return container.NewScroll(o)
}

func sized(o fyne.CanvasObject, width float32) fyne.CanvasObject {
	return container.NewGridWrap(fyne.NewSize(width, 36), o)
}

func stringsTrim(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Theme gives Charles-like orange primary.
type Theme struct{}

func (t *Theme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	if n == theme.ColorNamePrimary {
		return color.NRGBA{R: 0xE5, G: 0x6B, B: 0x1A, A: 0xFF}
	}
	return theme.DefaultTheme().Color(n, v)
}

func (t *Theme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(n)
}

func (t *Theme) Font(s fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(s)
}

func (t *Theme) Size(n fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(n)
}
