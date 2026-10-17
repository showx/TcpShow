use std::net::Ipv4Addr;

use http::{HeaderMap, Method, Uri};

use crate::lan;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Home,
    Cert,
    Pem,
    Profile,
    Missing,
}

pub struct Document {
    pub status: u16,
    pub content_type: &'static str,
    pub filename: Option<&'static str>,
    pub body: Vec<u8>,
}

pub fn classify(method: &Method, uri: &Uri, headers: &HeaderMap, listen_port: u16) -> Option<Page> {
    if *method != Method::GET && *method != Method::HEAD {
        return our_host(uri, headers, listen_port).then_some(Page::Missing);
    }
    if !our_host(uri, headers, listen_port) {
        return None;
    }
    Some(match uri.path() {
        "/" | "/index.html" => Page::Home,
        "/cert" | "/cert.crt" | "/ca.crt" | "/ssl" => Page::Cert,
        "/cert.pem" | "/ca.pem" => Page::Pem,
        "/ios" | "/apple.mobileconfig" => Page::Profile,
        _ => Page::Missing,
    })
}

pub fn render(
    page: Page,
    seen_host: &str,
    listen_port: u16,
    cert_der: Option<&[u8]>,
    cert_pem: Option<&str>,
) -> Document {
    let endpoint = phone_endpoint(seen_host, listen_port);
    match page {
        Page::Home => Document {
            status: 200,
            content_type: "text/html; charset=utf-8",
            filename: None,
            body: home_html(&endpoint).into_bytes(),
        },
        Page::Cert => {
            cert_document(cert_der, "application/x-x509-ca-cert", Some("TcpShow-CA.cer"), false, None)
        }
        Page::Pem => cert_document(
            cert_pem.map(str::as_bytes),
            "application/x-pem-file",
            Some("TcpShow-CA.pem"),
            false,
            None,
        ),
        Page::Profile => match cert_der {
            Some(der) => Document {
                status: 200,
                content_type: "application/x-apple-aspen-config",
                filename: Some("TcpShow.mobileconfig"),
                body: mobileconfig(der).into_bytes(),
            },
            None => missing_cert(),
        },
        Page::Missing => Document {
            status: 404,
            content_type: "text/html; charset=utf-8",
            filename: None,
            body: format!(
                "<!doctype html><meta charset=\"utf-8\"><title>TcpShow</title><p>这个地址没有页面。</p><p><a href=\"/\">回到安装页</a></p>"
            )
            .into_bytes(),
        },
    }
}

fn cert_document(
    bytes: Option<&[u8]>,
    content_type: &'static str,
    filename: Option<&'static str>,
    _pem: bool,
    _unused: Option<()>,
) -> Document {
    match bytes {
        Some(bytes) => Document {
            status: 200,
            content_type,
            filename,
            body: bytes.to_vec(),
        },
        None => missing_cert(),
    }
}

fn missing_cert() -> Document {
    Document {
        status: 503,
        content_type: "text/plain; charset=utf-8",
        filename: None,
        body: "证书还没生成，请先在电脑上打开 TcpShow。\n".into(),
    }
}

pub fn phone_url(ip: Ipv4Addr, port: u16) -> String {
    format!("http://{ip}:{port}/")
}

pub fn seen_host(uri: &Uri, headers: &HeaderMap) -> String {
    if let Some(authority) = uri.authority() {
        return authority.to_string();
    }
    headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn phone_endpoint(seen_host: &str, listen_port: u16) -> Endpoint {
    let (name, _) = split_host_port(seen_host);
    if let Ok(ip) = name.parse::<Ipv4Addr>() {
        if !ip.is_loopback() && !ip.is_unspecified() {
            return Endpoint {
                ip: ip.to_string(),
                port: listen_port,
            };
        }
    }
    if let Some(ip) = lan::preferred_ipv4() {
        return Endpoint {
            ip: ip.to_string(),
            port: listen_port,
        };
    }
    Endpoint {
        ip: name,
        port: listen_port,
    }
}

struct Endpoint {
    ip: String,
    port: u16,
}

fn our_host(uri: &Uri, headers: &HeaderMap, listen_port: u16) -> bool {
    let host = if let Some(authority) = uri.authority() {
        authority.as_str().to_string()
    } else {
        headers
            .get(http::header::HOST)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    if host.is_empty() {
        return false;
    }
    let (name, port) = split_host_port(&host);
    if port.unwrap_or(80) != listen_port {
        return false;
    }
    is_local_name(&name)
}

fn is_local_name(name: &str) -> bool {
    if name.eq_ignore_ascii_case("localhost")
        || name == "127.0.0.1"
        || name == "::1"
        || name.eq_ignore_ascii_case("tcpshow.local")
    {
        return true;
    }
    if let Ok(ip) = name.parse::<Ipv4Addr>() {
        return ip.is_loopback() || lan::ipv4_addrs().contains(&ip);
    }
    false
}

fn split_host_port(host: &str) -> (String, Option<u16>) {
    if let Some(rest) = host.strip_prefix('[') {
        if let Some((name, rest)) = rest.split_once(']') {
            let port = rest.strip_prefix(':').and_then(|value| value.parse().ok());
            return (name.to_string(), port);
        }
    }
    if let Some((name, port)) = host.rsplit_once(':') {
        if !name.is_empty() && !name.contains(':') && port.chars().all(|ch| ch.is_ascii_digit()) {
            return (name.to_string(), port.parse().ok());
        }
    }
    (host.to_string(), None)
}

fn home_html(endpoint: &Endpoint) -> String {
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TcpShow</title>
<style>
  body {{ margin:0; padding:24px; background:#111; color:#f4f4f5; font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif; }}
  .note {{ background:#3a2a14; color:#f6d7a8; border-radius:12px; padding:12px 14px; }}
  h1 {{ color:#e56b1a; font-size:32px; margin:0 0 8px; }}
  h2 {{ font-size:22px; margin:28px 0 8px; }}
  p, li {{ line-height:1.55; }}
  .box {{ background:#1c1c1e; border-radius:16px; padding:16px 18px; margin:16px 0; }}
  .label {{ color:#a1a1aa; font-size:14px; }}
  .big {{ font-size:34px; font-weight:700; margin:2px 0 12px; word-break:break-all; }}
  a.btn {{ display:block; background:#e56b1a; color:#111; text-align:center; text-decoration:none; font-weight:700; padding:16px; border-radius:14px; margin:10px 0; font-size:18px; }}
  a.secondary {{ background:#2c2c30; color:#fff; }}
  ol {{ padding-left:22px; }}
  li {{ margin:12px 0; }}
  .warn {{ color:#f6d7a8; }}
</style>
<h1>TcpShow</h1>
<p class="note">用系统相机打开本页，不要用微信。先装证书，确认装上了，再改手机代理。代理填错或开太早，这个页面会打不开。</p>
<p>手机和电脑要在同一个 Wi-Fi。</p>
<div class="box">
  <div class="label">服务器</div>
  <div class="big">{ip}</div>
  <div class="label">端口</div>
  <div class="big">{port}</div>
</div>
<a class="btn" href="/ios">iPhone：下载描述文件</a>
<a class="btn secondary" href="/cert.crt">Android：下载证书</a>

<h2>iPhone</h2>
<ol>
  <li>点上面的「下载描述文件」。Safari 只会说「已下载描述文件」，这时还没装上。</li>
  <li>打开「设置 → 通用 → VPN 与设备管理」。旧系统里叫「描述文件」或「描述文件与设备管理」。点 TcpShow CA → 安装，输入锁屏密码。</li>
  <li>再打开「设置 → 通用 → 关于本机 → 证书信任设置」，把 TcpShow CA 的开关打开。这一步不做，HTTPS 网站打不开。</li>
  <li>打开「设置 → 无线局域网」，点当前 Wi-Fi 右边的 ⓘ → 配置代理 → 手动。服务器填 {ip}，端口填 {port}。不要打开「鉴定」。</li>
  <li>如果开了 iCloud 专用代理，到「设置 → Apple ID → iCloud → 专用代理」先关掉，否则有些流量不经过 TcpShow。</li>
  <li>把 Safari 从后台划掉，再打开一个网站。电脑上的 TcpShow 会出现请求。</li>
</ol>

<h2>Android</h2>
<p class="warn">下载完不要点通知栏或文件管理器里的证书。那样会提示安装不了。这个文件是 CA 根证书，没有私钥，不能当「VPN 和应用用户证书」来装。</p>
<ol>
  <li>点上面的「下载证书」，等 TcpShow-CA.cer 进「下载」文件夹。先不要改 Wi-Fi 代理。</li>
  <li>打开系统设置，找到「加密与凭据」或「凭据存储」，点「安装证书」，一定选「CA 证书」。不要选「VPN 和应用用户证书」。</li>
  <li>系统会警告流量可能被监控，点「仍然安装」，再选刚下载的 TcpShow-CA.cer。</li>
  <li>装好后到「可信凭据 → 用户」里应能看到 TcpShow CA。看不到就是没装上。</li>
  <li>打开 WLAN，长按当前 Wi-Fi → 修改网络 → 高级选项 → 代理 → 手动。主机名填 {ip}，端口填 {port}，保存。</li>
  <li>用 Chrome 打开一个网站。Android 7 以上，很多 App 不信任用户安装的证书，Chrome 可以。银行类 App 通常抓不到 HTTPS。</li>
</ol>
<p>各品牌进「安装证书」的常见位置：</p>
<ul>
  <li>原生 / 像素：设置 → 安全性和隐私 → 更多安全和隐私设置 → 加密与凭据 → 安装证书 → CA 证书</li>
  <li>小米 / 红米：设置 → 密码与安全 → 隐私 → 更多安全设置 → 加密与凭据 → 安装证书 → CA 证书</li>
  <li>华为 / 荣耀：设置 → 安全 → 更多安全设置 → 加密和凭据 → 从存储设备安装 → CA 证书</li>
  <li>三星：设置 → 安全与隐私 → 其他安全设置 → 从设备存储安装 → CA 证书</li>
  <li>OPPO / 一加 / realme：设置 → 密码与安全 → 系统安全 → 凭据存储 → 安装证书 → CA 证书</li>
  <li>vivo / iQOO：设置 → 安全 → 更多安全设置 → 加密与凭据 → 安装证书 → CA 证书</li>
</ul>
"#,
        ip = endpoint.ip,
        port = endpoint.port,
    )
}

fn mobileconfig(der: &[u8]) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadDisplayName</key><string>TcpShow CA</string>
<key>PayloadIdentifier</key><string>com.showx.tcpshow.ca</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>8C1B6B2E-7A1D-4E5A-9C1A-6B2E8C1B6B2E</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadContent</key>
<array><dict>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadIdentifier</key><string>com.showx.tcpshow.ca.cert</string>
<key>PayloadUUID</key><string>7B1A6A1D-6A0C-4D49-8B09-5A1D7B1A6A1D</string>
<key>PayloadVersion</key><integer>1</integer>
<key>PayloadDisplayName</key><string>TcpShow CA</string>
<key>PayloadCertificateFileName</key><string>TcpShow-CA.cer</string>
<key>PayloadContent</key><data>{data}</data>
</dict></array>
</dict></plist>
"#,
        data = base64(der),
    )
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) & 63] as char);
        out.push(TABLE[(n >> 12) & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn only_our_host_is_the_install_page() {
        let headers = host("127.0.0.1:8888");
        let uri = Uri::from_static("/cert.crt");
        assert_eq!(
            classify(&Method::GET, &uri, &headers, 8888),
            Some(Page::Cert)
        );
        let foreign = Uri::from_static("http://example.com/cert.crt");
        assert_eq!(classify(&Method::GET, &foreign, &headers, 8888), None);
        let other_port = host("127.0.0.1:80");
        let uri = Uri::from_static("/");
        assert_eq!(classify(&Method::GET, &uri, &other_port, 8888), None);
    }

    #[test]
    fn profile_contains_the_certificate() {
        let doc = render(
            Page::Profile,
            "127.0.0.1:8888",
            8888,
            Some(&[0x30, 0x01, 0x00]),
            None,
        );
        let text = String::from_utf8(doc.body).unwrap();
        assert!(text.contains("com.apple.security.root"));
        assert!(text.contains("MAEA"));
        assert_eq!(doc.filename, Some("TcpShow.mobileconfig"));
    }

    fn host(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, HeaderValue::from_str(value).unwrap());
        headers
    }
}
