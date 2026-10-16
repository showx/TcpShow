use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::ca::{install_crypto, Ca};
use crate::guide;
use crate::store::{decode_for_display, Session, Store, DISPLAY_CAP};

const BUFFER_CAP: usize = 8 * 1024 * 1024;

type DynErr = Box<dyn std::error::Error + Send + Sync>;
type OutBody = http_body_util::combinators::BoxBody<Bytes, DynErr>;
type Connector = hyper_rustls::HttpsConnector<HttpConnector>;
type HttpClient = Client<Connector, OutBody>;

pub struct ProxyHandle {
    addr: String,
    shutdown: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl ProxyHandle {
    pub fn start(addr: &str, ca: Option<Arc<Ca>>, store: Arc<Store>) -> anyhow::Result<Self> {
        install_crypto();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (shutdown, shutdown_rx) = watch::channel(false);
        let running = Arc::new(AtomicBool::new(false));
        let running_thread = Arc::clone(&running);
        let addr = addr.to_string();
        let thread = std::thread::Builder::new()
            .name("tcpshow-proxy".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = ready_tx.send(Err(anyhow::anyhow!(err)));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let listener = match TcpListener::bind(&addr).await {
                        Ok(listener) => listener,
                        Err(err) => {
                            let _ = ready_tx.send(Err(err.into()));
                            return;
                        }
                    };
                    let bound = match listener.local_addr() {
                        Ok(addr) => addr.to_string(),
                        Err(err) => {
                            let _ = ready_tx.send(Err(err.into()));
                            return;
                        }
                    };
                    running_thread.store(true, Ordering::Relaxed);
                    let _ = ready_tx.send(Ok(bound));
                    let listen_port = listener.local_addr().map(|addr| addr.port()).unwrap_or(0);
                    let state = State {
                        client: build_client(),
                        ca,
                        store,
                        listen_port,
                    };
                    if let Err(err) = serve(listener, state, shutdown_rx).await {
                        eprintln!("TcpShow: 代理退出: {err}");
                    }
                    running_thread.store(false, Ordering::Relaxed);
                });
            })
            .context("无法启动代理线程")?;
        let bound = ready_rx.recv().context("代理线程没有返回监听地址")??;
        Ok(Self {
            addr: bound,
            shutdown,
            thread: Some(thread),
            running,
        })
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn stop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone)]
struct State {
    client: HttpClient,
    ca: Option<Arc<Ca>>,
    store: Arc<Store>,
    listen_port: u16,
}

async fn serve(
    listener: TcpListener,
    state: State,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        let state = state.clone();
                        async move { Ok::<_, std::convert::Infallible>(state.handle(req, peer).await) }
                    });
                    let connection = http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(io, service)
                        .with_upgrades();
                    if let Err(err) = connection.await {
                        let text = err.to_string();
                        if !text.contains("connection closed") && !text.contains("reset") {
                            eprintln!("TcpShow: 连接结束: {text}");
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

impl State {
    async fn handle(&self, req: Request<Incoming>, peer: SocketAddr) -> Response<OutBody> {
        if req.method() != Method::CONNECT {
            if let Some(page) =
                guide::classify(req.method(), req.uri(), req.headers(), self.listen_port)
            {
                let seen = guide::seen_host(req.uri(), req.headers());
                let der = self.ca.as_ref().map(|ca| ca.cert_der().to_vec());
                let pem = self.ca.as_ref().and_then(|ca| ca.cert_pem());
                let doc = guide::render(
                    page,
                    &seen,
                    self.listen_port,
                    der.as_deref(),
                    pem.as_deref(),
                );
                return document_response(doc);
            }
        }
        if req.method() == Method::CONNECT {
            return self.handle_connect(req, peer);
        }
        self.forward(req, peer, false).await
    }

    fn handle_connect(&self, req: Request<Incoming>, peer: SocketAddr) -> Response<OutBody> {
        let hostport = req
            .uri()
            .authority()
            .map(|authority| authority.to_string())
            .unwrap_or_default();
        if hostport.is_empty() {
            return text_response(StatusCode::BAD_REQUEST, "CONNECT 缺少目标地址");
        }
        let state = self.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => state.mitm(upgraded, hostport, peer).await,
                Err(err) => state.fail_connect(&hostport, format!("连接升级失败: {err}")),
            }
        });
        Response::builder()
            .status(StatusCode::OK)
            .body(empty_body())
            .unwrap()
    }

    async fn mitm(&self, upgraded: Upgraded, hostport: String, peer: SocketAddr) {
        let host = host_only(&hostport);
        let Some(ca) = self.ca.clone() else {
            self.fail_connect(&hostport, "证书未生成".into());
            return;
        };
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(HostResolver {
                ca,
                host: host.clone(),
            }));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let tls = match acceptor.accept(TokioIo::new(upgraded)).await {
            Ok(tls) => tls,
            Err(err) => {
                self.fail_connect(
                    &hostport,
                    format!("TLS 握手失败: {err}（CA 未被系统信任，请点「安装证书」并输入密码）"),
                );
                return;
            }
        };
        let state = self.clone();
        let service = service_fn(move |req| {
            let state = state.clone();
            let hostport = hostport.clone();
            async move {
                let req = rewrite_https(req, &hostport);
                Ok::<_, std::convert::Infallible>(state.forward(req, peer, true).await)
            }
        });
        let io = TokioIo::new(tls);
        let _ = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service)
            .await;
    }

    fn fail_connect(&self, hostport: &str, error: String) {
        let host = host_only(hostport);
        let _ = self.store.begin(Session {
            id: 0,
            updated: 0,
            scheme: "https".into(),
            method: "CONNECT".into(),
            host: host.clone(),
            path: "/".into(),
            url: format!("https://{host}/"),
            status: 0,
            content_type: String::new(),
            req_headers: Vec::new(),
            resp_headers: Vec::new(),
            req_body: Vec::new(),
            req_display: String::new(),
            resp_display: String::new(),
            req_truncated: false,
            resp_truncated: false,
            req_size: 0,
            resp_size: 0,
            duration: Some(Duration::ZERO),
            error,
        });
    }

    async fn forward(
        &self,
        req: Request<Incoming>,
        _peer: SocketAddr,
        mitm: bool,
    ) -> Response<OutBody> {
        let started = Instant::now();
        let (parts, body) = req.into_parts();
        let method = parts.method.clone();
        let uri = match absolute_uri(&parts.uri, &parts.headers, mitm) {
            Ok(uri) => uri,
            Err(err) => return text_response(StatusCode::BAD_REQUEST, &err),
        };
        let loaded = match read_limited(body, BUFFER_CAP).await {
            Ok(loaded) => loaded,
            Err(err) => {
                return text_response(StatusCode::BAD_REQUEST, &format!("读取请求失败: {err}"))
            }
        };
        let (req_bytes, req_forward, req_truncated) = split_loaded(loaded);
        let req_size = content_length(&parts.headers).unwrap_or(req_bytes.len() as u64);
        let req_headers = with_host(
            pretty_headers(&parts.headers),
            host_header(&uri, &parts.headers),
        );
        let path = path_of(&uri);
        let host = display_host(&uri);
        let scheme = uri
            .scheme_str()
            .unwrap_or(if mitm { "https" } else { "http" })
            .to_string();
        let req_display = decode_for_display(&req_headers, &req_bytes);
        let session_id = self.store.begin(Session {
            id: 0,
            updated: 0,
            scheme: scheme.clone(),
            method: method.to_string(),
            host,
            path,
            url: uri.to_string(),
            status: 0,
            content_type: String::new(),
            req_headers: req_headers.clone(),
            resp_headers: Vec::new(),
            req_body: req_bytes.clone(),
            req_display,
            resp_display: String::new(),
            req_truncated,
            resp_truncated: false,
            req_size,
            resp_size: 0,
            duration: None,
            error: String::new(),
        });

        let mut upstream_headers = cleaned_headers(&parts.headers);
        apply_length(
            &mut upstream_headers,
            &method,
            req_forward_len(&req_forward),
        );
        let upstream = Request::builder()
            .method(method)
            .uri(uri)
            .body(req_forward)
            .unwrap();
        let mut upstream = upstream;
        *upstream.headers_mut() = upstream_headers;

        let response = match tokio::time::timeout(
            Duration::from_secs(45),
            self.client.request(upstream),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                let message = friendly_error(&err.to_string());
                self.fail(session_id, started, &message);
                return text_response(StatusCode::BAD_GATEWAY, &message);
            }
            Err(_) => {
                let message = "等待上游响应超时".to_string();
                self.fail(session_id, started, &message);
                return text_response(StatusCode::GATEWAY_TIMEOUT, &message);
            }
        };

        let status = response.status();
        let (resp_parts, resp_body) = response.into_parts();
        let loaded = match read_limited(resp_body, BUFFER_CAP).await {
            Ok(loaded) => loaded,
            Err(err) => {
                let message = format!("读取响应失败: {err}");
                self.fail(session_id, started, &message);
                return text_response(StatusCode::BAD_GATEWAY, &message);
            }
        };
        let (resp_bytes, resp_forward, resp_truncated) = split_loaded(loaded);
        let resp_headers = pretty_headers(&resp_parts.headers);
        let content_type = resp_parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let resp_size = content_length(&resp_parts.headers).unwrap_or(resp_bytes.len() as u64);
        let resp_display = decode_for_display(&resp_headers, &resp_bytes);
        if let Some(id) = session_id {
            let duration = started.elapsed();
            self.store.finish(id, |session| {
                session.status = status.as_u16();
                session.content_type = content_type;
                session.resp_headers = resp_headers;
                session.resp_display = resp_display;
                session.resp_truncated = resp_truncated;
                session.resp_size = if resp_truncated {
                    resp_size.max(resp_bytes.len() as u64)
                } else {
                    resp_bytes.len() as u64
                };
                session.duration = Some(duration);
                session.error.clear();
            });
        }

        let mut headers = cleaned_headers(&resp_parts.headers);
        if let Some(len) = forward_len(&resp_forward) {
            headers.remove(header::TRANSFER_ENCODING);
            if let Ok(value) = HeaderValue::from_str(&len.to_string()) {
                headers.insert(header::CONTENT_LENGTH, value);
            }
        } else {
            headers.remove(header::CONTENT_LENGTH);
            headers.remove(header::TRANSFER_ENCODING);
        }
        let mut response = Response::new(resp_forward);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }

    fn fail(&self, id: Option<u64>, started: Instant, message: &str) {
        let Some(id) = id else {
            return;
        };
        let duration = started.elapsed();
        let message = message.to_string();
        self.store.finish(id, |session| {
            session.error = message;
            session.duration = Some(duration);
        });
    }
}

struct HostResolver {
    ca: Arc<Ca>,
    host: String,
}

impl std::fmt::Debug for HostResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostResolver")
            .field("host", &self.host)
            .finish()
    }
}

impl rustls::server::ResolvesServerCert for HostResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.ca.resolve(client_hello, &self.host)
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_client() -> HttpClient {
    // 调试抓包：上游证书错误也要能看到响应，和 Charles 的默认行为一致。
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(60))
        .build(connector)
}

enum Loaded<B> {
    Full(Bytes),
    Partial { head: Bytes, rest: B },
}

async fn read_limited<B>(mut body: B, limit: usize) -> Result<Loaded<B>, String>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|err| err.to_string())?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buf.extend_from_slice(&data);
        if buf.len() > limit {
            return Ok(Loaded::Partial {
                head: Bytes::from(buf),
                rest: body,
            });
        }
    }
    Ok(Loaded::Full(Bytes::from(buf)))
}

fn split_loaded<B>(loaded: Loaded<B>) -> (Vec<u8>, OutBody, bool)
where
    B: hyper::body::Body<Data = Bytes> + Unpin + Send + Sync + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    match loaded {
        Loaded::Full(bytes) => {
            let truncated = bytes.len() > DISPLAY_CAP;
            let stored = if truncated {
                bytes.slice(..DISPLAY_CAP).to_vec()
            } else {
                bytes.to_vec()
            };
            (stored, full_body(bytes), truncated)
        }
        Loaded::Partial { head, rest } => {
            let stored = if head.len() > DISPLAY_CAP {
                head.slice(..DISPLAY_CAP).to_vec()
            } else {
                head.to_vec()
            };
            let body = Prefixed {
                prefix: Some(head),
                rest,
            }
            .map_err(|err| Box::new(err) as DynErr)
            .boxed();
            (stored, body, true)
        }
    }
}

struct Prefixed<B> {
    prefix: Option<Bytes>,
    rest: B,
}

impl<B> hyper::body::Body for Prefixed<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(prefix) = this.prefix.take() {
            if !prefix.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(prefix))));
            }
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }
}

fn req_forward_len(body: &OutBody) -> Option<u64> {
    HttpBody::size_hint(body).exact()
}

fn forward_len(body: &OutBody) -> Option<u64> {
    HttpBody::size_hint(body).exact()
}

fn full_body(bytes: Bytes) -> OutBody {
    Full::new(bytes)
        .map_err(|err| -> DynErr { match err {} })
        .boxed()
}

fn empty_body() -> OutBody {
    full_body(Bytes::new())
}

fn document_response(doc: guide::Document) -> Response<OutBody> {
    let mut builder = Response::builder()
        .status(doc.status)
        .header(header::CONTENT_TYPE, doc.content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_LENGTH, doc.body.len());
    if let Some(filename) = doc.filename {
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        );
    }
    builder.body(full_body(Bytes::from(doc.body))).unwrap()
}

fn text_response(status: StatusCode, message: &str) -> Response<OutBody> {
    let body = format!("{message}\n");
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len())
        .body(full_body(Bytes::from(body)))
        .unwrap()
}

fn rewrite_https(req: Request<Incoming>, authority: &str) -> Request<Incoming> {
    let (mut parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|item| item.as_str())
        .unwrap_or("/");
    if let Ok(uri) = format!("https://{authority}{path}").parse() {
        parts.uri = uri;
    }
    Request::from_parts(parts, body)
}

fn absolute_uri(uri: &Uri, headers: &HeaderMap, mitm: bool) -> Result<Uri, String> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri.clone());
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "请求缺少 Host".to_string())?;
    let path = uri
        .path_and_query()
        .map(|item| item.as_str())
        .unwrap_or("/");
    let scheme = if mitm { "https" } else { "http" };
    format!("{scheme}://{host}{path}")
        .parse()
        .map_err(|err| format!("请求地址无效: {err}"))
}

fn path_of(uri: &Uri) -> String {
    match uri.path_and_query() {
        Some(path) if !path.as_str().is_empty() => {
            let text = path.as_str();
            if text.starts_with('/') {
                text.to_string()
            } else {
                format!("/{text}")
            }
        }
        _ => "/".into(),
    }
}

fn display_host(uri: &Uri) -> String {
    let Some(authority) = uri.authority() else {
        return String::new();
    };
    let scheme = uri.scheme_str().unwrap_or("http");
    let host = authority.host();
    match authority.port_u16() {
        Some(80) if scheme == "http" => host.to_string(),
        Some(443) if scheme == "https" => host.to_string(),
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

fn host_header<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> &'a str {
    if let Some(value) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    {
        return value;
    }
    uri.authority()
        .map(|authority| authority.as_str())
        .unwrap_or("")
}

fn with_host(mut headers: Vec<(String, String)>, host: &str) -> Vec<(String, String)> {
    if host.is_empty()
        || headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        return headers;
    }
    headers.insert(0, ("Host".into(), host.to_string()));
    headers
}

fn pretty_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (pretty_name(name.as_str()), value_string(value)))
        .collect()
}

fn pretty_name(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn value_string(value: &HeaderValue) -> String {
    value
        .to_str()
        .map(str::to_string)
        .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

fn cleaned_headers(src: &HeaderMap) -> HeaderMap {
    let extra = connection_names(src);
    let mut dst = HeaderMap::new();
    for (name, value) in src.iter() {
        if is_hop(name.as_str()) || extra.iter().any(|item| item == name) {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
    dst
}

fn connection_names(headers: &HeaderMap) -> Vec<HeaderName> {
    let Some(value) = headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
    else {
        return Vec::new();
    };
    value
        .split(',')
        .filter_map(|item| HeaderName::from_bytes(item.trim().as_bytes()).ok())
        .collect()
}

fn is_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn apply_length(headers: &mut HeaderMap, method: &Method, length: Option<u64>) {
    headers.remove(header::TRANSFER_ENCODING);
    if length.unwrap_or(0) == 0 && (*method == Method::GET || *method == Method::HEAD) {
        headers.remove(header::CONTENT_LENGTH);
        return;
    }
    if let Some(length) = length {
        if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
            headers.insert(header::CONTENT_LENGTH, value);
        }
    }
}

fn host_only(hostport: &str) -> String {
    if let Some(rest) = hostport.strip_prefix('[') {
        if let Some((host, _)) = rest.split_once(']') {
            return host.to_string();
        }
    }
    if let Some((host, port)) = hostport.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            return host.to_string();
        }
    }
    hostport.to_string()
}

fn friendly_error(err: &str) -> String {
    let lower = err.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        format!("连接上游超时: {err}")
    } else if lower.contains("connection refused") {
        format!("上游拒绝连接: {err}")
    } else if lower.contains("dns")
        || lower.contains("failed to lookup")
        || lower.contains("nodename")
    {
        format!("域名解析失败: {err}")
    } else {
        err.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::Ca;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use std::convert::Infallible;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    async fn captures_http_and_post_body() {
        let upstream = spawn_origin(false).await;
        let (proxy, store, _dir) = start_proxy().await;
        let client = client_for(proxy.addr());
        let response = client
            .post(format!("{upstream}/hello"))
            .body("hi")
            .send()
            .await
            .unwrap();
        let text = response.text().await.unwrap();
        assert!(text.contains("ok"));
        wait_done(&store).await;
        let detail = store.detail(1).unwrap();
        assert!(detail.title.contains("POST"));
        assert!(detail.title.contains("/hello"));
        assert!(detail.req_body_full.contains("hi"));
        assert!(detail.resp_body_full.contains("\"ok\""));
        assert!(detail.meta.contains("200"));
    }

    #[tokio::test]
    async fn captures_https() {
        let upstream = spawn_origin(true).await;
        let (proxy, store, _dir) = start_proxy().await;
        let client = client_for(proxy.addr());
        let response = client.get(format!("{upstream}/ping")).send().await.unwrap();
        let text = response.text().await.unwrap();
        assert_eq!(text, "pong");
        wait_done(&store).await;
        let detail = store.detail(1).unwrap();
        assert!(detail.title.starts_with("GET https://"));
        assert!(detail.resp_body_full.contains("pong"));
        assert!(detail.meta.contains("200"));
    }

    #[tokio::test]
    async fn serves_phone_install_page_without_recording_it() {
        let (proxy, store, _dir) = start_proxy().await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap();
        let html = client
            .get(format!("http://{}/", proxy.addr()))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(html.contains("iPhone"));
        assert!(html.contains("Android"));
        let cert = client
            .get(format!("http://{}/cert.crt", proxy.addr()))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(cert.first().copied(), Some(0x30));
        let profile = client
            .get(format!("http://{}/ios", proxy.addr()))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(profile.contains("com.apple.security.root"));
        assert_eq!(store.len(), 0);
    }

    async fn start_proxy() -> (ProxyHandle, Arc<Store>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(Ca::load_or_create_in(dir.path()).unwrap());
        let store = Arc::new(Store::new());
        let proxy = ProxyHandle::start("127.0.0.1:0", Some(ca), Arc::clone(&store)).unwrap();
        (proxy, store, dir)
    }

    fn client_for(addr: &str) -> reqwest::Client {
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{addr}")).unwrap())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap()
    }

    async fn wait_done(store: &Store) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if let Some(detail) = store.detail(1) {
                if detail.meta.contains("200") || detail.meta.contains("ERR") {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("会话没有完成: {}", store.len());
    }

    async fn spawn_origin(tls: bool) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        if tls {
            let acceptor = test_acceptor();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service_fn(origin_service))
                            .await;
                    });
                }
            });
            format!("https://127.0.0.1:{port}")
        } else {
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    tokio::spawn(async move {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service_fn(origin_service))
                            .await;
                    });
                }
            });
            format!("http://127.0.0.1:{port}")
        }
    }

    async fn origin_service(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path().to_string();
        let bytes = req.into_body().collect().await.unwrap().to_bytes();
        let (content_type, body) = if path.contains("ping") {
            ("text/plain", Bytes::from_static(b"pong"))
        } else {
            let _ = bytes;
            ("application/json", Bytes::from_static(br#"{"ok":true}"#))
        };
        Ok(Response::builder()
            .header(header::CONTENT_TYPE, content_type)
            .body(Full::new(body))
            .unwrap())
    }

    fn test_acceptor() -> TlsAcceptor {
        install_crypto();
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let cert = CertificateDer::from(cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }
}
