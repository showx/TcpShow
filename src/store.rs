use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use parking_lot::Mutex;
use serde_json::Value;

pub const MAX_SESSIONS: usize = 10_000;
pub const DISPLAY_CAP: usize = 2 * 1024 * 1024;
const VIEW_CHARS: usize = 200_000;

#[derive(Clone)]
pub struct Session {
    pub id: u64,
    pub updated: u64,
    pub scheme: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub url: String,
    pub status: u16,
    pub content_type: String,
    pub req_headers: Vec<(String, String)>,
    pub resp_headers: Vec<(String, String)>,
    pub req_body: Vec<u8>,
    pub req_display: String,
    pub resp_display: String,
    pub req_truncated: bool,
    pub resp_truncated: bool,
    pub req_size: u64,
    pub resp_size: u64,
    pub duration: Option<Duration>,
    pub error: String,
}

impl Session {
    pub fn status_text(&self) -> String {
        if !self.error.is_empty() && self.status == 0 {
            return "ERR".to_string();
        }
        if self.status == 0 {
            return "...".to_string();
        }
        self.status.to_string()
    }

    pub fn request_raw(&self) -> String {
        let mut out = format!("{} {} HTTP/1.1\n", self.method, self.path);
        for (name, value) in &self.req_headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push('\n');
        }
        out
    }

    pub fn response_raw(&self) -> String {
        if !self.error.is_empty() && self.status == 0 {
            return format!("Error: {}", self.error);
        }
        let mut out = format!("HTTP/1.1 {}\n", self.status);
        for (name, value) in &self.resp_headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push('\n');
        }
        if !self.error.is_empty() {
            out.push_str("\n");
            out.push_str(&self.error);
            out.push('\n');
        }
        out
    }

    pub fn curl(&self) -> String {
        let mut out = format!("curl -k -X {} '{}'", self.method, escape_quote(&self.url));
        for (name, value) in &self.req_headers {
            let lower = name.to_ascii_lowercase();
            if lower == "host" || lower == "content-length" || lower == "transfer-encoding" {
                continue;
            }
            out.push_str(" \\\n  -H '");
            out.push_str(&escape_quote(name));
            out.push_str(": ");
            out.push_str(&escape_quote(value));
            out.push('\'');
        }
        if !self.req_body.is_empty() && self.method != "GET" && self.method != "HEAD" {
            let text = String::from_utf8_lossy(&self.req_body);
            out.push_str(" \\\n  --data-binary '");
            out.push_str(&escape_quote(&text));
            out.push('\'');
        }
        out
    }
}

#[derive(Clone)]
pub struct Summary {
    pub id: u64,
    pub updated: u64,
    pub method: String,
    pub status: u16,
    pub has_error: bool,
    pub host: String,
    pub path: String,
    pub content_type: String,
    pub resp_size: u64,
    pub duration: Option<Duration>,
}

#[derive(Clone)]
pub struct Detail {
    pub id: u64,
    pub updated: u64,
    pub title: String,
    pub meta: String,
    pub url: String,
    pub curl: String,
    pub req_head: String,
    pub req_body: String,
    pub resp_head: String,
    pub resp_body: String,
    pub req_body_full: String,
    pub resp_body_full: String,
    pub req_clipped: bool,
    pub resp_clipped: bool,
    pub req_truncated: bool,
    pub resp_truncated: bool,
    pub error: String,
}

struct Inner {
    sessions: Vec<Session>,
    next_id: u64,
    revision: u64,
    recording: bool,
}

pub struct Store {
    inner: Mutex<Inner>,
    generation: AtomicU64,
}

impl Store {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                sessions: Vec::new(),
                next_id: 1,
                revision: 1,
                recording: true,
            }),
            generation: AtomicU64::new(1),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn recording(&self) -> bool {
        self.inner.lock().recording
    }

    pub fn set_recording(&self, recording: bool) {
        self.inner.lock().recording = recording;
        self.bump();
    }

    pub fn len(&self) -> usize {
        self.inner.lock().sessions.len()
    }

    pub fn begin(&self, mut session: Session) -> Option<u64> {
        let mut inner = self.inner.lock();
        if !inner.recording {
            return None;
        }
        let id = inner.next_id;
        inner.next_id += 1;
        session.id = id;
        session.updated = inner.revision;
        inner.revision += 1;
        inner.sessions.push(session);
        if inner.sessions.len() > MAX_SESSIONS {
            let overflow = inner.sessions.len() - MAX_SESSIONS;
            inner.sessions.drain(0..overflow);
        }
        drop(inner);
        self.bump();
        Some(id)
    }

    pub fn finish(&self, id: u64, edit: impl FnOnce(&mut Session)) {
        let mut inner = self.inner.lock();
        let revision = inner.revision;
        inner.revision = revision + 1;
        if let Some(session) = inner.sessions.iter_mut().find(|s| s.id == id) {
            edit(session);
            session.updated = revision;
        }
        drop(inner);
        self.bump();
    }

    pub fn clear(&self) {
        self.inner.lock().sessions.clear();
        self.bump();
    }

    pub fn filtered(&self, query: &str) -> Vec<Summary> {
        let inner = self.inner.lock();
        let query = query.trim().to_ascii_lowercase();
        inner
            .sessions
            .iter()
            .filter(|session| query.is_empty() || matches_query(session, &query))
            .map(summary_of)
            .collect()
    }

    pub fn detail(&self, id: u64) -> Option<Detail> {
        let inner = self.inner.lock();
        inner.sessions.iter().find(|s| s.id == id).map(detail_of)
    }

    fn bump(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

fn matches_query(session: &Session, query: &str) -> bool {
    let status = session.status_text();
    let haystack = format!(
        "{} {} {} {} {} {}",
        session.method, session.host, session.path, session.url, status, session.content_type
    );
    haystack.to_ascii_lowercase().contains(query)
}

fn summary_of(session: &Session) -> Summary {
    Summary {
        id: session.id,
        updated: session.updated,
        method: session.method.clone(),
        status: session.status,
        has_error: !session.error.is_empty(),
        host: session.host.clone(),
        path: session.path.clone(),
        content_type: short_type(&session.content_type),
        resp_size: session.resp_size,
        duration: session.duration,
    }
}

fn detail_of(session: &Session) -> Detail {
    let (req_body, req_clipped) = clip_view(&session.req_display);
    let (resp_body, resp_clipped) = clip_view(&session.resp_display);
    let meta = format!(
        "{}  ·  请求 {}  ·  响应 {}  ·  {}  ·  {}",
        session.status_text(),
        format_bytes(session.req_size),
        format_bytes(session.resp_size),
        format_duration(session.duration),
        if session.scheme == "https" {
            "HTTPS"
        } else {
            "HTTP"
        }
    );
    Detail {
        id: session.id,
        updated: session.updated,
        title: format!("{} {}", session.method, session.url),
        meta,
        url: session.url.clone(),
        curl: session.curl(),
        req_head: session.request_raw(),
        req_body,
        resp_head: session.response_raw(),
        resp_body,
        req_body_full: session.req_display.clone(),
        resp_body_full: session.resp_display.clone(),
        req_clipped,
        resp_clipped,
        req_truncated: session.req_truncated,
        resp_truncated: session.resp_truncated,
        error: session.error.clone(),
    }
}

fn clip_view(text: &str) -> (String, bool) {
    let mut count = 0;
    for (idx, _) in text.char_indices() {
        if count == VIEW_CHARS {
            return (text[..idx].to_string(), true);
        }
        count += 1;
    }
    (text.to_string(), false)
}

pub fn format_bytes(n: u64) -> String {
    if n < 1024 {
        return format!("{n} B");
    }
    if n < 1024 * 1024 {
        return format!("{:.1} KB", n as f64 / 1024.0);
    }
    format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
}

pub fn format_duration(duration: Option<Duration>) -> String {
    let Some(duration) = duration else {
        return String::new();
    };
    if duration.as_secs() == 0 {
        format!("{} ms", duration.as_millis())
    } else {
        format!("{:.1} s", duration.as_secs_f64())
    }
}

pub fn decode_for_display(headers: &[(String, String)], body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    let encoding = header_value(headers, "content-encoding");
    let decoded = decode_encodings(encoding, body);
    let mut content_type = header_value(headers, "content-type")
        .unwrap_or("")
        .to_string();
    if let Some((left, _)) = content_type.split_once(';') {
        content_type = left.trim().to_string();
    }
    let show_json = content_type.to_ascii_lowercase().contains("json") || looks_json(&decoded);
    if show_json {
        if let Ok(value) = serde_json::from_slice::<Value>(trim_ascii(&decoded)) {
            if let Ok(pretty) = serde_json::to_string_pretty(&value) {
                return pretty;
            }
        }
    }
    if std::str::from_utf8(&decoded).is_ok() && !decoded.contains(&0) {
        return String::from_utf8_lossy(&decoded).into_owned();
    }
    hex_dump(&decoded)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn decode_encodings(encoding: Option<&str>, body: &[u8]) -> Vec<u8> {
    let Some(encoding) = encoding else {
        return body.to_vec();
    };
    let parts: Vec<&str> = encoding
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty() && !part.eq_ignore_ascii_case("identity"))
        .collect();
    let mut data = body.to_vec();
    for part in parts.into_iter().rev() {
        if let Some(next) = decode_one(part, &data) {
            data = next;
        }
    }
    if data.len() > DISPLAY_CAP {
        data.truncate(DISPLAY_CAP);
    }
    data
}

fn decode_one(encoding: &str, data: &[u8]) -> Option<Vec<u8>> {
    match encoding.to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => read_limited(GzDecoder::new(data)),
        "deflate" => {
            read_limited(DeflateDecoder::new(data)).or_else(|| read_limited(ZlibDecoder::new(data)))
        }
        "br" => read_limited(brotli::Decompressor::new(data, 4096)),
        _ => None,
    }
}

fn read_limited(reader: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader
        .take(DISPLAY_CAP as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn looks_json(body: &[u8]) -> bool {
    let body = trim_ascii(body);
    body.len() > 1
        && ((body[0] == b'{' && body[body.len() - 1] == b'}')
            || (body[0] == b'[' && body[body.len() - 1] == b']'))
}

fn trim_ascii(body: &[u8]) -> &[u8] {
    let start = body
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(body.len());
    let end = body
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &body[start..end]
}

fn hex_dump(data: &[u8]) -> String {
    let shown = data.len().min(1024);
    let mut out = String::from("[binary]\n");
    for (row, chunk) in data[..shown].chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", row * 16));
        for (index, byte) in chunk.iter().enumerate() {
            if index == 8 {
                out.push(' ');
            }
            out.push_str(&format!("{byte:02x} "));
        }
        let pad = 16 - chunk.len();
        for index in 0..pad {
            if chunk.len() + index == 8 {
                out.push(' ');
            }
            out.push_str("   ");
        }
        out.push(' ');
        for byte in chunk {
            out.push(if (32..127).contains(byte) {
                *byte as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }
    if data.len() > shown {
        out.push_str(&format!("\n… 还有 {} 字节未显示\n", data.len() - shown));
    }
    out
}

fn short_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

fn escape_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_prints_json() {
        let headers = vec![("Content-Type".into(), "application/json".into())];
        let text = decode_for_display(&headers, br#"{"a":1}"#);
        assert!(text.contains("\"a\""));
        assert!(text.contains('\n'));
    }

    #[test]
    fn decodes_gzip_json() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(br#"{"a":1}"#).unwrap();
        let gzip = encoder.finish().unwrap();
        let headers = vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Encoding".into(), "gzip".into()),
        ];
        let text = decode_for_display(&headers, &gzip);
        assert!(text.contains("\"a\""), "{text}");
    }

    #[test]
    fn filters_and_pauses() {
        let store = Store::new();
        store
            .begin(sample(
                "GET",
                "example.com",
                "/hello",
                "http://example.com/hello",
            ))
            .unwrap();
        store
            .begin(sample("POST", "api.test", "/v1", "http://api.test/v1"))
            .unwrap();
        assert_eq!(store.filtered("example").len(), 1);
        assert_eq!(store.filtered("POST").len(), 1);
        store.set_recording(false);
        assert!(store.begin(sample("GET", "x", "/", "http://x/")).is_none());
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn curl_escapes_quotes() {
        let mut session = sample("POST", "example.com", "/a", "http://example.com/a");
        session.req_headers = vec![("X-Name".into(), "a'b".into())];
        session.req_body = b"n'ame".to_vec();
        let curl = session.curl();
        assert!(curl.contains("curl -k -X POST 'http://example.com/a'"));
        assert!(curl.contains("-H 'X-Name: a'\\''b'"));
        assert!(curl.contains("--data-binary 'n'\\''ame'"));
    }

    fn sample(method: &str, host: &str, path: &str, url: &str) -> Session {
        Session {
            id: 0,
            updated: 0,
            scheme: "http".into(),
            method: method.into(),
            host: host.into(),
            path: path.into(),
            url: url.into(),
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
            duration: None,
            error: String::new(),
        }
    }
}
