use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{
    Align, Button, Color32, Context, CornerRadius, FontData, FontDefinitions, FontFamily, FontId,
    Id, Key, Label, Layout, RichText, Sense, Stroke, TextEdit, TextStyle, TextWrapMode, Vec2,
};
use egui_extras::{Column, TableBuilder};

use crate::ca::Ca;
use crate::guide;
use crate::proxy::ProxyHandle;
use crate::store::{format_bytes, format_duration, Detail, Store, Summary};
use crate::sysproxy;

const ORANGE: Color32 = Color32::from_rgb(0xE5, 0x6B, 0x1A);
const GREEN: Color32 = Color32::from_rgb(0x3D, 0xD6, 0x8C);
const BLUE: Color32 = Color32::from_rgb(0x6C, 0xB6, 0xFF);
const AMBER: Color32 = Color32::from_rgb(0xE5, 0xA0, 0x4A);
const RED: Color32 = Color32::from_rgb(0xF0, 0x71, 0x78);
const PURPLE: Color32 = Color32::from_rgb(0xC7, 0x92, 0xEA);

enum Event {
    CertCheck(bool),
    CertInstalled(Result<(), String>),
    SysProxy(Result<SysChange, String>),
    PhoneReach { gen: u64, ok: bool },
}

struct SysChange {
    enabled: bool,
    service: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Request,
    Response,
}

#[derive(Clone)]
struct Popup {
    title: String,
    body: String,
}

struct Toast {
    text: String,
    until: Instant,
}

pub struct TcpShowApp {
    store: Arc<Store>,
    ca: Option<Arc<Ca>>,
    ca_error: Option<String>,
    proxy: Option<ProxyHandle>,
    port: String,
    filter: String,
    applied_filter: String,
    recording: bool,
    phone_mode: bool,
    show_phone: bool,
    lan_ip: Option<Ipv4Addr>,
    lan_at: Option<Instant>,
    phone_ok: Option<bool>,
    phone_check: Option<(Ipv4Addr, u16)>,
    phone_checked_at: Option<Instant>,
    phone_gen: u64,
    qr_key: String,
    qr: Option<egui::TextureHandle>,
    sys_proxy: bool,
    sys_service: String,
    sys_busy: bool,
    cert_busy: bool,
    cert_trusted: Option<bool>,
    selected: Option<u64>,
    detail: Option<Detail>,
    tab: Tab,
    follow: bool,
    wrap_body: bool,
    split: f32,
    summaries: Vec<Summary>,
    seen_gen: u64,
    req_head: String,
    req_body: String,
    resp_head: String,
    resp_body: String,
    popup: Option<Popup>,
    toast: Option<Toast>,
    events: Receiver<Event>,
    tx: Sender<Event>,
    shutdown_done: bool,
}

impl TcpShowApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);
        apply_style(&cc.egui_ctx);
        let (tx, events) = mpsc::channel();
        let (ca, ca_error) = match Ca::load_or_create() {
            Ok(ca) => (Some(Arc::new(ca)), None),
            Err(err) => (None, Some(err.to_string())),
        };
        let store = Arc::new(Store::new());
        let mut app = Self {
            store,
            ca,
            ca_error: ca_error.clone(),
            proxy: None,
            port: "8888".into(),
            filter: String::new(),
            applied_filter: String::new(),
            recording: true,
            phone_mode: false,
            show_phone: false,
            lan_ip: None,
            lan_at: None,
            phone_ok: None,
            phone_check: None,
            phone_checked_at: None,
            phone_gen: 0,
            qr_key: String::new(),
            qr: None,
            sys_proxy: false,
            sys_service: String::new(),
            sys_busy: false,
            cert_busy: false,
            cert_trusted: None,
            selected: None,
            detail: None,
            tab: Tab::Response,
            follow: true,
            wrap_body: true,
            split: 0.56,
            summaries: Vec::new(),
            seen_gen: 0,
            req_head: String::new(),
            req_body: String::new(),
            resp_head: String::new(),
            resp_body: String::new(),
            popup: ca_error.map(|body| Popup {
                title: "证书还没准备好".into(),
                body,
            }),
            toast: None,
            events,
            tx,
            shutdown_done: false,
        };
        app.start_proxy();
        app.spawn_cert_check();
        app
    }

    fn proxy_running(&self) -> bool {
        self.proxy.as_ref().is_some_and(ProxyHandle::running)
    }

    fn listen_addr(&self) -> String {
        self.proxy
            .as_ref()
            .map(|proxy| proxy.addr().to_string())
            .unwrap_or_else(|| format!("127.0.0.1:{}", self.port.trim()))
    }

    fn start_proxy(&mut self) {
        if self.proxy_running() {
            return;
        }
        let port: u16 = match self.port.trim().parse() {
            Ok(port) if port > 0 => port,
            _ => {
                self.popup = Some(Popup {
                    title: "端口无效".into(),
                    body: "请填写 1 到 65535 之间的端口。".into(),
                });
                return;
            }
        };
        match ProxyHandle::start(
            &self.bind_spec(port),
            self.ca.clone(),
            Arc::clone(&self.store),
        ) {
            Ok(proxy) => self.proxy = Some(proxy),
            Err(err) => {
                self.popup = Some(Popup {
                    title: "代理没有启动".into(),
                    body: friendly_bind(err),
                });
            }
        }
    }

    fn bind_spec(&self, port: u16) -> String {
        if self.phone_mode {
            format!("0.0.0.0:{port}")
        } else {
            format!("127.0.0.1:{port}")
        }
    }

    fn current_port(&self) -> u16 {
        self.proxy
            .as_ref()
            .and_then(|proxy| proxy.addr().rsplit_once(':')?.1.parse().ok())
            .or_else(|| self.port.trim().parse().ok())
            .unwrap_or(8888)
    }

    fn set_phone_mode(&mut self, on: bool) {
        if self.phone_mode == on {
            return;
        }
        self.phone_mode = on;
        self.show_phone = on;
        self.lan_at = None;
        self.phone_ok = None;
        self.phone_check = None;
        self.phone_checked_at = None;
        self.phone_gen = self.phone_gen.wrapping_add(1);
        if self.proxy.is_none() {
            return;
        }
        if let Some(mut proxy) = self.proxy.take() {
            proxy.stop();
        }
        self.start_proxy();
        if !self.proxy_running() {
            self.phone_mode = !on;
            self.show_phone = false;
            self.start_proxy();
            if self.proxy_running() {
                self.popup = Some(Popup {
                    title: "手机抓包没有打开".into(),
                    body: "监听局域网失败，已经回到只抓本机。".into(),
                });
            }
        }
    }

    fn refresh_lan(&mut self) {
        let stale = self
            .lan_at
            .map(|at| at.elapsed() > Duration::from_secs(2))
            .unwrap_or(true);
        if !stale {
            return;
        }
        self.lan_ip = crate::lan::preferred_ipv4();
        self.lan_at = Some(Instant::now());
    }

    fn status_listen(&self) -> String {
        if self.phone_mode {
            if let Some(ip) = self.lan_ip {
                let text = format!("手机 {ip}:{}", self.current_port());
                return if self.phone_ok == Some(false) {
                    format!("{text} 不通")
                } else {
                    text
                };
            }
        }
        format!("监听 {}", self.listen_addr())
    }

    fn schedule_phone_check(&mut self) {
        if !self.phone_mode || !self.proxy_running() {
            self.phone_ok = None;
            self.phone_check = None;
            return;
        }
        let Some(ip) = self.lan_ip else {
            self.phone_ok = None;
            return;
        };
        let port = self.current_port();
        let retry = self.phone_ok == Some(false)
            && self
                .phone_checked_at
                .map(|at| at.elapsed() > Duration::from_secs(2))
                .unwrap_or(false);
        if self.phone_check == Some((ip, port)) && !retry {
            return;
        }
        self.phone_check = Some((ip, port));
        self.phone_checked_at = Some(Instant::now());
        self.phone_ok = None;
        self.phone_gen = self.phone_gen.wrapping_add(1);
        let gen = self.phone_gen;
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let ok = std::net::TcpStream::connect_timeout(
                &SocketAddr::from((ip, port)),
                Duration::from_millis(400),
            )
            .is_ok();
            let _ = tx.send(Event::PhoneReach { gen, ok });
        });
    }

    fn stop_proxy(&mut self) {
        if self.sys_proxy {
            self.apply_sys_proxy(false);
        }
        if let Some(mut proxy) = self.proxy.take() {
            proxy.stop();
        }
    }

    fn spawn_cert_check(&self) {
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Event::CertCheck(sysproxy::cert_trusted()));
        });
    }

    fn install_cert(&mut self, ctx: &Context) {
        let Some(ca) = &self.ca else {
            self.popup = Some(Popup {
                title: "证书未生成".into(),
                body: self
                    .ca_error
                    .clone()
                    .unwrap_or_else(|| "本地 CA 没有创建成功。".into()),
            });
            return;
        };
        if self.cert_trusted == Some(true) {
            self.on_cert_ready(ca.cert_path().display().to_string());
            return;
        }
        self.cert_busy = true;
        let path = ca.cert_path().display().to_string();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(Event::CertInstalled(sysproxy::trust_cert(&path)));
            ctx.request_repaint();
        });
    }

    fn on_cert_ready(&mut self, path: String) {
        self.cert_trusted = Some(true);
        if !self.sys_proxy && self.proxy_running() {
            self.apply_sys_proxy(true);
        }
        self.popup = Some(Popup {
            title: "证书已就绪".into(),
            body: format!(
                "TcpShow CA 已设为系统信任的根证书。\n\n请完全退出并重新打开浏览器，再访问 https 网站。\n\nFirefox 不使用系统钥匙串，需要在 Firefox 里单独导入这个文件：\n{path}"
            ),
        });
    }

    fn apply_sys_proxy(&mut self, enable: bool) {
        if self.sys_busy {
            return;
        }
        if enable && !self.proxy_running() {
            self.popup = Some(Popup {
                title: "系统代理".into(),
                body: "请先启动抓包代理。".into(),
            });
            return;
        }
        self.sys_busy = true;
        let tx = self.tx.clone();
        if enable {
            let port = self
                .listen_addr()
                .rsplit_once(':')
                .map(|(_, port)| port.to_string())
                .unwrap_or_else(|| self.port.trim().to_string());
            std::thread::spawn(move || {
                let result = sysproxy::set("127.0.0.1", &port).map(|service| SysChange {
                    enabled: true,
                    service,
                });
                let _ = tx.send(Event::SysProxy(result));
            });
        } else {
            let service = self.sys_service.clone();
            std::thread::spawn(move || {
                let result = sysproxy::clear(&service).map(|()| SysChange {
                    enabled: false,
                    service,
                });
                let _ = tx.send(Event::SysProxy(result));
            });
        }
    }

    fn pump(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::CertCheck(trusted) => self.cert_trusted = Some(trusted),
                Event::CertInstalled(result) => {
                    self.cert_busy = false;
                    match result {
                        Ok(()) => {
                            let path = self
                                .ca
                                .as_ref()
                                .map(|ca| ca.cert_path().display().to_string())
                                .unwrap_or_default();
                            self.on_cert_ready(path);
                        }
                        Err(err) => {
                            self.popup = Some(Popup {
                                title: "信任证书失败".into(),
                                body: format!("{err}\n\n也可以手动打开「钥匙串访问」→ 系统 → TcpShow CA → 信任 → 始终信任。"),
                            });
                        }
                    }
                }
                Event::PhoneReach { gen, ok } => {
                    if gen == self.phone_gen {
                        self.phone_ok = Some(ok);
                    }
                }
                Event::SysProxy(result) => {
                    self.sys_busy = false;
                    match result {
                        Ok(change) => {
                            self.sys_proxy = change.enabled;
                            if change.enabled {
                                self.sys_service = change.service;
                            }
                        }
                        Err(err) => {
                            self.popup = Some(Popup {
                                title: "系统代理没有改成功".into(),
                                body: err,
                            });
                        }
                    }
                }
            }
        }
    }

    fn sync_view(&mut self) {
        let generation = self.store.generation();
        if generation == self.seen_gen && self.filter == self.applied_filter {
            return;
        }
        self.seen_gen = generation;
        self.applied_filter = self.filter.clone();
        self.summaries = self.store.filtered(&self.filter);
        let fingerprint = self.selected.and_then(|id| {
            self.summaries
                .iter()
                .find(|summary| summary.id == id)
                .map(|summary| summary.updated)
        });
        let current = self
            .detail
            .as_ref()
            .map(|detail| (detail.id, detail.updated));
        if self.selected.is_some()
            && current
                .map(|(id, updated)| Some(id) == self.selected && Some(updated) == fingerprint)
                == Some(true)
        {
            return;
        }
        self.load_detail();
    }

    fn load_detail(&mut self) {
        let Some(id) = self.selected else {
            self.detail = None;
            self.req_head.clear();
            self.req_body.clear();
            self.resp_head.clear();
            self.resp_body.clear();
            return;
        };
        let Some(detail) = self.store.detail(id) else {
            self.selected = None;
            self.detail = None;
            return;
        };
        self.req_head = detail.req_head.clone();
        self.req_body = detail.req_body.clone();
        self.resp_head = detail.resp_head.clone();
        self.resp_body = detail.resp_body.clone();
        self.detail = Some(detail);
    }

    fn move_selection(&mut self, delta: isize) {
        if self.summaries.is_empty() {
            return;
        }
        let current = self
            .selected
            .and_then(|id| self.summaries.iter().position(|summary| summary.id == id))
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, self.summaries.len() as isize - 1) as usize;
        self.selected = Some(self.summaries[next].id);
        self.follow = false;
        self.load_detail();
    }

    fn copy_curl(&mut self, ctx: &Context) {
        let Some(detail) = &self.detail else {
            self.toast("请先选择一条请求");
            return;
        };
        ctx.copy_text(detail.curl.clone());
        self.toast("已复制 cURL");
    }

    fn copy_url(&mut self, ctx: &Context) {
        let Some(detail) = &self.detail else {
            self.toast("请先选择一条请求");
            return;
        };
        ctx.copy_text(detail.url.clone());
        self.toast("已复制 URL");
    }

    fn copy_body(&mut self, ctx: &Context) {
        let Some(detail) = &self.detail else {
            self.toast("请先选择一条请求");
            return;
        };
        let text = if self.tab == Tab::Request {
            detail.req_body_full.clone()
        } else {
            detail.resp_body_full.clone()
        };
        if text.is_empty() {
            self.toast("这条没有正文");
            return;
        }
        ctx.copy_text(text);
        self.toast("已复制正文");
    }

    fn clear_sessions(&mut self) {
        self.store.clear();
        self.selected = None;
        self.detail = None;
        self.req_head.clear();
        self.req_body.clear();
        self.resp_head.clear();
        self.resp_body.clear();
    }

    fn toast(&mut self, text: impl Into<String>) {
        self.toast = Some(Toast {
            text: text.into(),
            until: Instant::now() + Duration::from_secs(2),
        });
    }

    fn text_focused(ctx: &Context) -> bool {
        ctx.memory(|memory| {
            [
                "filter",
                "port",
                "req_head",
                "req_body",
                "resp_head",
                "resp_body",
            ]
            .iter()
            .any(|id| memory.has_focus(Id::new(*id)))
        })
    }

    fn shutdown(&mut self) {
        if self.shutdown_done {
            return;
        }
        self.shutdown_done = true;
        if self.sys_proxy || !self.sys_service.is_empty() {
            let _ = sysproxy::clear(&self.sys_service);
            self.sys_proxy = false;
        }
        if let Some(mut proxy) = self.proxy.take() {
            proxy.stop();
        }
    }
}

impl Drop for TcpShowApp {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl eframe::App for TcpShowApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.pump();
        self.refresh_lan();
        self.schedule_phone_check();
        self.sync_view();
        ctx.request_repaint_after(Duration::from_millis(if self.proxy_running() {
            80
        } else {
            250
        }));
        if ctx.input(|input| input.viewport().close_requested()) {
            self.shutdown();
        }
        if !Self::text_focused(ctx) {
            if ctx.input(|input| input.key_pressed(Key::ArrowDown)) {
                self.move_selection(1);
            }
            if ctx.input(|input| input.key_pressed(Key::ArrowUp)) {
                self.move_selection(-1);
            }
        }
        if ctx.input(|input| input.modifiers.command && input.key_pressed(Key::F)) {
            ctx.memory_mut(|memory| memory.request_focus(Id::new("filter")));
        }

        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(4.0);
            egui::menu::bar(ui, |ui| {
                ui.menu_button("文件", |ui| {
                    if ui.button("安装 CA 证书").clicked() {
                        self.install_cert(ctx);
                        ui.close_menu();
                    }
                    if ui.button("复制为 cURL").clicked() {
                        self.copy_curl(ctx);
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("清空记录").clicked() {
                        self.clear_sessions();
                        ui.close_menu();
                    }
                });
                ui.menu_button("帮助", |ui| {
                    if ui.button("关于 TcpShow").clicked() {
                        self.popup = Some(Popup {
                            title: "关于 TcpShow".into(),
                            body: "简单的 HTTP/HTTPS 抓包软件。\n默认代理端口 8888。\n\n只抓你自己授权的流量。".into(),
                        });
                        ui.close_menu();
                    }
                });
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("端口");
                ui.add_enabled(
                    !self.proxy_running(),
                    TextEdit::singleline(&mut self.port)
                        .desired_width(64.0)
                        .hint_text("8888")
                        .id(Id::new("port")),
                );
                if self.proxy_running() {
                    if ui.add(Button::new("停止").fill(Color32::from_rgb(0xA3, 0x3B, 0x32))).clicked() {
                        self.stop_proxy();
                    }
                } else if ui.add(Button::new("启动").fill(ORANGE)).clicked() {
                    self.start_proxy();
                }
                if ui.checkbox(&mut self.recording, "录制").on_hover_text("暂停后仍然转发，只是不再记入列表").changed() {
                    self.store.set_recording(self.recording);
                }
                let mut phone = self.phone_mode;
                if ui
                    .checkbox(&mut phone, "手机抓包")
                    .on_hover_text("同一 Wi-Fi 下的手机可以连过来。代理会监听所有网卡。")
                    .changed()
                {
                    self.set_phone_mode(phone);
                }
                ui.add_enabled_ui(!self.sys_busy, |ui| {
                    let mut want = self.sys_proxy;
                    if ui.checkbox(&mut want, "系统代理").on_hover_text("让 macOS 的网页和安全网页流量走这个代理").changed() {
                        self.apply_sys_proxy(want);
                    }
                });
                if ui.button("清空").clicked() {
                    self.clear_sessions();
                }
                if ui.button(if self.cert_busy { "正在安装…" } else { "安装证书" }).clicked() && !self.cert_busy {
                    self.install_cert(ctx);
                }
                if ui.button("复制 cURL").clicked() {
                    self.copy_curl(ctx);
                }
                ui.checkbox(&mut self.follow, "跟随最新").on_hover_text("新请求到来时列表滚到底部");
            });
            ui.add_space(2.0);
            ui.add(
                TextEdit::singleline(&mut self.filter)
                    .hint_text("过滤 method / host / path / 状态    ⌘F")
                    .desired_width(f32::INFINITY)
                    .id(Id::new("filter")),
            );
            if self.phone_mode {
                ui.horizontal_wrapped(|ui| {
                    if let Some(ip) = self.lan_ip {
                        let url = guide::phone_url(ip, self.current_port());
                        ui.colored_label(ORANGE, &url);
                        if ui.button("复制链接").clicked() {
                            ctx.copy_text(url);
                            self.toast("已复制链接");
                        }
                        match self.phone_ok {
                            Some(true) => {
                                ui.colored_label(GREEN, "本机可打开");
                            }
                            Some(false) => {
                                ui.colored_label(RED, "本机打不开");
                            }
                            None => {
                                ui.label("正在确认…");
                            }
                        }
                    } else {
                        ui.colored_label(AMBER, "没有找到 Wi-Fi 地址");
                    }
                    if crate::lan::has_virtual_adapter() {
                        ui.label("已避开虚拟网卡");
                    }
                    if self.show_phone {
                        if ui.button("返回请求").clicked() {
                            self.show_phone = false;
                        }
                    } else if ui.button("连接说明").clicked() {
                        self.show_phone = true;
                    }
                });
            }
            ui.add_space(4.0);
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let (color, state) = if self.proxy_running() {
                    (GREEN, self.status_listen())
                } else {
                    (RED, "已停止".to_string())
                };
                ui.colored_label(color, "●");
                ui.add(Label::new(state).selectable(true));
                ui.label("·");
                ui.label(if self.store.recording() {
                    "录制中"
                } else {
                    "已暂停"
                });
                ui.label("·");
                ui.colored_label(
                    match self.cert_trusted {
                        Some(true) => GREEN,
                        Some(false) => AMBER,
                        None => Color32::GRAY,
                    },
                    match self.cert_trusted {
                        Some(true) => "证书已信任",
                        Some(false) => "证书未信任",
                        None => "正在检查证书",
                    },
                );
                ui.label("·");
                ui.label(format!("{} 条", self.store.len()));
                if self.sys_proxy {
                    ui.label("·");
                    ui.colored_label(GREEN, "系统代理已开");
                }
                if self.cert_busy || self.sys_busy {
                    ui.label("·");
                    ui.label("正在等待系统…");
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if let Some(toast) = &self.toast {
                        if Instant::now() < toast.until {
                            ui.colored_label(ORANGE, &toast.text);
                        }
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.split_view(ui, ctx);
        });

        if let Some(popup) = self.popup.clone() {
            let mut close = false;
            egui::Window::new(&popup.title)
                .collapsible(false)
                .resizable(true)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .default_width(460.0)
                .show(ctx, |ui| {
                    ui.set_min_width(420.0);
                    ui.label(popup.body);
                    ui.add_space(10.0);
                    if ui.button("好").clicked() {
                        close = true;
                    }
                });
            if close {
                self.popup = None;
            }
        }
    }
}

impl TcpShowApp {
    fn split_view(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        let available = ui.available_size();
        let gap = 6.0;
        let left = (available.x * self.split).clamp(360.0, (available.x - 340.0).max(360.0));
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                Vec2::new(left, available.y),
                Layout::top_down(Align::Min),
                |ui| {
                    ui.set_min_size(Vec2::new(left, available.y));
                    self.request_table(ui);
                },
            );
            let (rect, response) =
                ui.allocate_exact_size(Vec2::new(gap, available.y), Sense::drag());
            if response.dragged() {
                self.split = ((left + response.drag_delta().x) / available.x).clamp(0.28, 0.72);
            }
            if response.hovered() || response.dragged() {
                ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
            }
            ui.painter().rect_filled(
                rect.shrink2(Vec2::new(2.0, 0.0)),
                CornerRadius::ZERO,
                Color32::from_rgb(0x3A, 0x3A, 0x3E),
            );
            let right = (available.x - left - gap).max(280.0);
            ui.allocate_ui_with_layout(
                Vec2::new(right, available.y),
                Layout::top_down(Align::Min),
                |ui| {
                    ui.set_min_size(Vec2::new(right, available.y));
                    self.detail_panel(ui, ctx);
                },
            );
        });
    }

    fn request_table(&mut self, ui: &mut egui::Ui) {
        if self.summaries.is_empty() {
            ui.add_space(24.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new(if self.filter.trim().is_empty() {
                        "还没有请求"
                    } else {
                        "没有匹配的请求"
                    })
                    .size(16.0),
                );
                ui.add_space(6.0);
                ui.label(if self.filter.trim().is_empty() {
                    if self.phone_mode {
                        "按右侧说明连上手机后，请求会出现在这里。"
                    } else {
                        "打开系统代理，或勾选「手机抓包」。"
                    }
                } else {
                    "换个关键词，或清空过滤框。"
                });
            });
            return;
        }
        let height = ui.available_height();
        let rows = std::mem::take(&mut self.summaries);
        let mut clicked = None;
        let mut context_id = None;
        let selected = self.selected;
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .stick_to_bottom(self.follow)
            .sense(Sense::click())
            .min_scrolled_height(height)
            .max_scroll_height(height)
            .column(Column::exact(52.0))
            .column(Column::exact(68.0))
            .column(Column::exact(56.0))
            .column(Column::initial(190.0).clip(true).resizable(true))
            .column(Column::remainder().clip(true))
            .column(Column::initial(120.0).clip(true).resizable(true))
            .column(Column::exact(72.0))
            .column(Column::exact(72.0))
            .header(24.0, |mut header| {
                for name in ["#", "方法", "状态", "主机", "路径", "类型", "大小", "耗时"]
                {
                    header.col(|ui| {
                        ui.strong(name);
                    });
                }
            })
            .body(|body| {
                body.rows(22.0, rows.len(), |mut row| {
                    let summary = &rows[row.index()];
                    let is_selected = selected == Some(summary.id);
                    row.set_selected(is_selected);
                    row.col(|ui| {
                        ui.monospace(summary.id.to_string());
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(&summary.method)
                                .monospace()
                                .color(method_color(&summary.method))
                                .strong(),
                        );
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(status_label(summary))
                                .monospace()
                                .color(status_color(summary))
                                .strong(),
                        );
                    });
                    row.col(|ui| {
                        ui.label(&summary.host);
                    });
                    row.col(|ui| {
                        ui.label(&summary.path);
                    });
                    row.col(|ui| {
                        ui.label(
                            RichText::new(&summary.content_type).color(Color32::from_gray(180)),
                        );
                    });
                    row.col(|ui| {
                        ui.monospace(format_bytes(summary.resp_size));
                    });
                    row.col(|ui| {
                        ui.monospace(format_duration(summary.duration));
                    });
                    if row.response().clicked() {
                        clicked = Some(summary.id);
                    }
                    row.response().context_menu(|ui| {
                        if ui.button("查看这条").clicked() {
                            context_id = Some(summary.id);
                            ui.close_menu();
                        }
                    });
                });
            });
        self.summaries = rows;
        if let Some(id) = clicked.or(context_id) {
            self.selected = Some(id);
            self.follow = false;
            self.show_phone = false;
            self.load_detail();
        }
    }

    fn detail_panel(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        if self.phone_mode && self.show_phone {
            self.phone_guide(ui, ctx);
            return;
        }
        let Some(detail) = self.detail.clone() else {
            self.empty_detail(ui);
            return;
        };
        ui.add(
            Label::new(
                RichText::new(&detail.title)
                    .monospace()
                    .size(14.0)
                    .color(Color32::WHITE),
            )
            .wrap_mode(TextWrapMode::Wrap),
        );
        ui.label(RichText::new(&detail.meta).color(Color32::from_gray(180)));
        if !detail.error.is_empty() {
            ui.colored_label(RED, &detail.error);
        }
        let truncated = match self.tab {
            Tab::Request => detail.req_truncated || detail.req_clipped,
            Tab::Response => detail.resp_truncated || detail.resp_clipped,
        };
        if truncated {
            ui.colored_label(AMBER, "正文很长，界面只保留前面一段。转发本身没有被截断。");
        }
        ui.horizontal(|ui| {
            if ui.button("复制 URL").clicked() {
                self.copy_url(ctx);
            }
            if ui.button("复制 cURL").clicked() {
                self.copy_curl(ctx);
            }
            if ui.button("复制正文").clicked() {
                self.copy_body(ctx);
            }
            ui.separator();
            if ui
                .selectable_label(self.tab == Tab::Request, "请求")
                .clicked()
            {
                self.tab = Tab::Request;
            }
            if ui
                .selectable_label(self.tab == Tab::Response, "响应")
                .clicked()
            {
                self.tab = Tab::Response;
            }
            ui.checkbox(&mut self.wrap_body, "换行");
        });
        let wrap_body = self.wrap_body;
        let (head_id, body_id, head, body) = match self.tab {
            Tab::Request => (
                "req_head",
                "req_body",
                &mut self.req_head,
                &mut self.req_body,
            ),
            Tab::Response => (
                "resp_head",
                "resp_body",
                &mut self.resp_head,
                &mut self.resp_body,
            ),
        };
        let head_rows = lines(head, 4, 14);
        let body_rows = lines(body, 10, 40);
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    TextEdit::multiline(head)
                        .font(TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(head_rows)
                        .code_editor()
                        .id(Id::new(head_id)),
                );
                ui.add_space(6.0);
                let mut editor = TextEdit::multiline(body)
                    .font(TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(body_rows)
                    .id(Id::new(body_id));
                if !wrap_body {
                    editor = editor.code_editor();
                }
                ui.add(editor);
            });
    }

    fn empty_detail(&self, ui: &mut egui::Ui) {
        ui.add_space(28.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("TcpShow").size(28.0).color(ORANGE).strong());
            ui.add_space(8.0);
            ui.label("本机 HTTP / HTTPS 抓包");
        });
        ui.add_space(16.0);
        ui.label("开始抓 HTTPS：");
        ui.label("1. 底部显示正在监听");
        ui.label("2. 点「安装证书」，在系统弹窗里输入本机密码");
        ui.label("3. 勾选「系统代理」，然后完全退出并重新打开浏览器");
        ui.add_space(10.0);
        ui.label("也可以只让某个程序走代理：");
        ui.monospace("export http_proxy=http://127.0.0.1:8888");
        ui.monospace("export https_proxy=http://127.0.0.1:8888");
        ui.add_space(10.0);
        ui.label("Firefox 不使用系统钥匙串，需要单独导入证书。");
        ui.add_space(10.0);
        ui.label("抓手机：勾选「手机抓包」。手机和电脑连同一个 Wi-Fi，扫二维码安装证书，再把 Wi-Fi 代理填成窗口里的地址。");
        ui.label("上下方向键可以在列表里移动。点一条请求后，跟随最新会先停下来。");
    }

    fn phone_guide(&mut self, ui: &mut egui::Ui, ctx: &Context) {
        let port = self.current_port();
        let ip_text = self.lan_ip.map(|ip| ip.to_string());
        let url = self.lan_ip.map(|ip| guide::phone_url(ip, port));
        if let Some(url) = &url {
            self.ensure_qr(ctx, url);
        }
        let qr = self.qr.clone();
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new("抓手机").size(22.0).color(ORANGE).strong());
            ui.add_space(4.0);
            ui.label("手机和电脑连同一个 Wi-Fi。用系统相机扫，不要用微信扫。");
            ui.label("先打开安装页并装好证书，最后再改手机代理。");
            ui.add_space(8.0);
            match self.phone_ok {
                Some(true) => {
                    ui.colored_label(GREEN, "电脑自己能打开这个地址，手机也可以试。");
                }
                Some(false) => {
                    ui.colored_label(RED, "电脑自己都打不开这个地址。先确认勾着「手机抓包」，并允许传入连接。");
                }
                None => {
                    ui.label("正在确认电脑自己能不能打开这个地址…");
                }
            }
            if crate::lan::has_virtual_adapter() {
                ui.colored_label(AMBER, "检测到 Clash 一类虚拟网卡，二维码用的是 Wi-Fi 地址。");
            }
            ui.add_space(10.0);
            match &ip_text {
                Some(ip) => {
                    ui.label("服务器");
                    ui.label(RichText::new(ip).size(24.0).monospace().strong());
                    ui.label("端口");
                    ui.label(RichText::new(port.to_string()).size(24.0).monospace().strong());
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("复制服务器").clicked() {
                            ctx.copy_text(ip.clone());
                            self.toast("已复制服务器地址");
                        }
                        if ui.button("复制端口").clicked() {
                            ctx.copy_text(port.to_string());
                            self.toast("已复制端口");
                        }
                        if let Some(url) = &url {
                            if ui.button("复制链接").clicked() {
                                ctx.copy_text(url.clone());
                                self.toast("已复制链接");
                            }
                        }
                    });
                    if let Some(url) = &url {
                        ui.label(RichText::new(url).monospace().color(Color32::from_gray(190)));
                    }
                    ui.add_space(8.0);
                    if let Some(texture) = &qr {
                        ui.add(egui::Image::from_texture(texture).fit_to_exact_size(Vec2::splat(220.0)));
                    }
                }
                None => {
                    ui.colored_label(AMBER, "没有找到 Wi-Fi 地址。先把电脑连上 Wi-Fi，再重新勾选「手机抓包」。");
                }
            }
            ui.add_space(12.0);
            ui.label("用系统相机扫二维码。先在手机上打开安装页，照页面做。如果 Mac 问是否允许传入连接，选允许。");
            ui.add_space(8.0);
            ui.label(RichText::new("iPhone").strong());
            ui.label("1. 点「下载描述文件」。Safari 说「已下载描述文件」时，还没装上。");
            ui.label("2. 设置 → 通用 → VPN 与设备管理（旧系统叫「描述文件」）→ TcpShow CA → 安装。");
            ui.label("3. 设置 → 通用 → 关于本机 → 证书信任设置，打开 TcpShow CA。不打开的话，HTTPS 打不开。");
            ui.label("4. 设置 → 无线局域网 → 当前网络右边的 ⓘ → 配置代理 → 手动。服务器和端口分开填，不要开「鉴定」。");
            ui.label("5. 若开了 iCloud 专用代理，先关掉。然后把 Safari 划掉重开。");
            ui.add_space(8.0);
            ui.label(RichText::new("Android").strong());
            ui.colored_label(AMBER, "下载完不要直接点那个文件。点了会提示安装不了。");
            ui.label("1. 在安装页点「下载证书」，文件名是 TcpShow-CA.cer，先不要改 Wi-Fi 代理。");
            ui.label("2. 到系统设置里找「加密与凭据」或「凭据存储」→ 安装证书 → 一定选「CA 证书」。");
            ui.label("3. 不要选「VPN 和应用用户证书」。那个要私钥，这个根证书没有，所以会装失败。");
            ui.label("4. 警告页点「仍然安装」，再去「下载」文件夹选 TcpShow-CA.cer。");
            ui.label("5. 到「可信凭据 → 用户」里能看到 TcpShow CA，才算装上。");
            ui.label("6. WLAN 里长按当前 Wi-Fi → 修改网络 → 高级选项 → 代理 → 手动。主机名填服务器，端口填端口。");
            ui.label("7. 用 Chrome 打开网站。很多 App 不信任用户证书，Chrome 可以。");
            ui.add_space(6.0);
            ui.label("小米：设置 → 密码与安全 → 更多安全设置 → 加密与凭据 → CA 证书");
            ui.label("华为：设置 → 安全 → 更多安全设置 → 加密和凭据 → 从存储设备安装");
            ui.label("三星：设置 → 安全与隐私 → 其他安全设置 → 从设备存储安装 → CA 证书");
            ui.label("OPPO：设置 → 密码与安全 → 系统安全 → 凭据存储 → CA 证书");
            ui.label("vivo：设置 → 安全 → 更多安全设置 → 加密与凭据 → CA 证书");
            ui.add_space(8.0);
            ui.label(RichText::new("关掉「手机抓包」后，手机就连不过来了。").color(Color32::from_gray(170)));
        });
    }

    fn ensure_qr(&mut self, ctx: &Context, url: &str) {
        if self.qr_key == url && self.qr.is_some() {
            return;
        }
        let Some(image) = qr_image(url) else {
            return;
        };
        self.qr = Some(ctx.load_texture("tcpshow-phone-qr", image, egui::TextureOptions::NEAREST));
        self.qr_key = url.to_string();
    }
}

fn lines(text: &str, min: usize, max: usize) -> usize {
    text.lines().count().clamp(min, max)
}

fn status_label(summary: &Summary) -> String {
    if summary.has_error && summary.status == 0 {
        "ERR".into()
    } else if summary.status == 0 {
        "...".into()
    } else {
        summary.status.to_string()
    }
}

fn status_color(summary: &Summary) -> Color32 {
    if summary.has_error && summary.status == 0 {
        return RED;
    }
    match summary.status {
        0 => Color32::GRAY,
        200..=299 => GREEN,
        300..=399 => BLUE,
        400..=499 => AMBER,
        _ => RED,
    }
}

fn method_color(method: &str) -> Color32 {
    match method {
        "GET" => BLUE,
        "POST" => GREEN,
        "PUT" | "PATCH" => AMBER,
        "DELETE" => RED,
        "CONNECT" => PURPLE,
        _ => Color32::from_gray(210),
    }
}

fn friendly_bind(err: anyhow::Error) -> String {
    let text = err.to_string();
    if text.contains("Address already in use") || text.contains("AddrInUse") {
        format!("端口已被占用。\n\n{text}")
    } else {
        text
    }
}

fn install_fonts(ctx: &Context) {
    let mut fonts = FontDefinitions::default();
    insert_font(
        &mut fonts,
        "arial",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        true,
        false,
    );
    insert_font(
        &mut fonts,
        "cjk",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        true,
        true,
    );
    insert_font(
        &mut fonts,
        "mono",
        "/System/Library/Fonts/Monaco.ttf",
        false,
        false,
    );
    ctx.set_fonts(fonts);
}

fn insert_font(
    fonts: &mut FontDefinitions,
    name: &str,
    path: &str,
    proportional: bool,
    fallback_only: bool,
) {
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    fonts
        .font_data
        .insert(name.to_owned(), Arc::new(FontData::from_owned(bytes)));
    if proportional {
        let family = fonts.families.entry(FontFamily::Proportional).or_default();
        if fallback_only {
            family.push(name.to_owned());
        } else {
            family.insert(0, name.to_owned());
        }
    }
    let family = fonts.families.entry(FontFamily::Monospace).or_default();
    if name == "mono" {
        family.insert(0, name.to_owned());
    } else if name == "cjk" {
        family.push(name.to_owned());
    }
}

fn qr_image(url: &str) -> Option<egui::ColorImage> {
    let code = qrcode::QrCode::new(url.as_bytes()).ok()?;
    let modules = code.width();
    let quiet = 4usize;
    let scale = 8usize;
    let side = (modules + quiet * 2) * scale;
    let mut rgba = vec![255u8; side * side * 4];
    let colors = code.to_colors();
    for y in 0..modules {
        for x in 0..modules {
            if colors[y * modules + x] != qrcode::Color::Dark {
                continue;
            }
            for dy in 0..scale {
                for dx in 0..scale {
                    let px = (x + quiet) * scale + dx;
                    let py = (y + quiet) * scale + dy;
                    let i = (py * side + px) * 4;
                    rgba[i] = 0;
                    rgba[i + 1] = 0;
                    rgba[i + 2] = 0;
                    rgba[i + 3] = 255;
                }
            }
        }
    }
    Some(egui::ColorImage::from_rgba_unmultiplied(
        [side, side],
        &rgba,
    ))
}

fn apply_style(ctx: &Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = Color32::from_rgb(0x1C, 0x1C, 0x1E);
    style.visuals.window_fill = Color32::from_rgb(0x24, 0x24, 0x28);
    style.visuals.extreme_bg_color = Color32::from_rgb(0x12, 0x12, 0x14);
    style.visuals.faint_bg_color = Color32::from_rgb(0x2A, 0x2A, 0x2E);
    style.visuals.code_bg_color = Color32::from_rgb(0x12, 0x12, 0x14);
    style.visuals.hyperlink_color = ORANGE;
    style.visuals.selection.bg_fill = Color32::from_rgb(0x5C, 0x34, 0x18);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, ORANGE);
    style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(0x2C, 0x2C, 0x30);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x3A, 0x3A, 0x40);
    style.visuals.widgets.active.bg_fill = ORANGE;
    style.visuals.widgets.open.bg_fill = Color32::from_rgb(0x3A, 0x3A, 0x40);
    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(13.5, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(13.5, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(12.5, FontFamily::Monospace),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(12.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(18.0, FontFamily::Proportional),
    );
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 4.0);
    ctx.set_style(style);
}
