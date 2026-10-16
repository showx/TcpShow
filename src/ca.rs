use std::fs;
use std::io::Cursor;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};

use anyhow::{anyhow, Context};
use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ClientHello;
use rustls::sign::CertifiedKey;

const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca.key";
const CA_NAME: &str = "TcpShow CA";

pub struct Ca {
    dir: PathBuf,
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_der: CertificateDer<'static>,
    cache: Mutex<std::collections::HashMap<String, Arc<CertifiedKey>>>,
}

pub fn install_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl Ca {
    pub fn load_or_create() -> anyhow::Result<Self> {
        let base = dirs::config_dir().context("找不到配置目录")?;
        Self::load_or_create_in(&base.join("TcpShow"))
    }

    pub fn load_or_create_in(dir: &Path) -> anyhow::Result<Self> {
        install_crypto();
        fs::create_dir_all(dir).with_context(|| format!("无法创建 {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        let cert_path = dir.join(CA_CERT);
        let key_path = dir.join(CA_KEY);
        if cert_path.is_file() && key_path.is_file() {
            match Self::load(dir, &cert_path, &key_path) {
                Ok(ca) => return Ok(ca),
                Err(err) => {
                    eprintln!("TcpShow: 现有 CA 无法读取（{err}），将重新生成。如果之前安装过证书，需要重新点一次「安装证书」。");
                }
            }
        }
        Self::create(dir, &cert_path, &key_path)
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join(CA_CERT)
    }

    pub fn cert_der(&self) -> &[u8] {
        self.ca_der.as_ref()
    }

    pub fn cert_pem(&self) -> Option<String> {
        fs::read_to_string(self.cert_path()).ok()
    }

    pub fn certified(&self, host: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        let host = normalize_host(host);
        if let Some(hit) = self.cache.lock().get(&host) {
            return Ok(Arc::clone(hit));
        }
        let key = self.issue(&host)?;
        self.cache.lock().insert(host, Arc::clone(&key));
        Ok(key)
    }

    pub fn resolve(&self, hello: ClientHello<'_>, fallback: &str) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().unwrap_or(fallback);
        self.certified(name).ok()
    }

    fn load(dir: &Path, cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        let cert_pem = fs::read_to_string(cert_path).context("读取 CA 证书失败")?;
        let key_pem = fs::read_to_string(key_path).context("读取 CA 私钥失败")?;
        let key = load_key_pair(&key_pem)?;
        let params = CertificateParams::from_ca_cert_pem(&cert_pem).context("解析 CA 证书失败")?;
        // rcgen 只能拿 Certificate 当签发者。这里用同一把私钥再签一张同名证书，
        // 叶子证书的颁发者信息和密钥标识仍指向原来的 TcpShow CA。
        let ca_cert = params.self_signed(&key).context("读取 CA 证书失败")?;
        let ca_der = first_cert(&cert_pem)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            ca_cert,
            ca_key: key,
            ca_der,
            cache: Mutex::new(std::collections::HashMap::new()),
        })
    }

    fn create(dir: &Path, cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("生成 CA 私钥失败")?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, CA_NAME);
        name.push(DnType::OrganizationName, "TcpShow");
        params.distinguished_name = name;
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(3650);
        let cert = params.self_signed(&key).context("签发 CA 证书失败")?;
        write_file(cert_path, &cert.pem(), 0o644)?;
        write_file(key_path, &key.serialize_pem(), 0o600)?;
        Self::load(dir, cert_path, key_path)
    }

    fn issue(&self, host: &str) -> anyhow::Result<Arc<CertifiedKey>> {
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, truncate_cn(host));
        name.push(DnType::OrganizationName, "TcpShow");
        params.distinguished_name = name;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        if let Ok(ip) = host.parse::<IpAddr>() {
            params.subject_alt_names = vec![SanType::IpAddress(ip)];
        } else {
            let dns = host
                .try_into()
                .map_err(|err| anyhow!("无法为 {host} 签发证书: {err}"))?;
            params.subject_alt_names = vec![SanType::DnsName(dns)];
        }
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(365);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("生成站点私钥失败")?;
        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .context("签发站点证书失败")?;
        let leaf = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing =
            any_supported_type(&key_der).map_err(|err| anyhow!("站点私钥不可用: {err}"))?;
        Ok(Arc::new(CertifiedKey::new(
            vec![leaf, self.ca_der.clone()],
            signing,
        )))
    }
}

fn load_key_pair(pem: &str) -> anyhow::Result<KeyPair> {
    if let Ok(key) = KeyPair::from_pem(pem) {
        return Ok(key);
    }
    use p256::pkcs8::EncodePrivateKey;
    let secret = p256::SecretKey::from_sec1_pem(pem).context("无法解析 CA 私钥")?;
    let pkcs8 = secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .context("转换 CA 私钥失败")?;
    KeyPair::from_pem(pkcs8.as_str()).context("读取 CA 私钥失败")
}

fn first_cert(pem: &str) -> anyhow::Result<CertificateDer<'static>> {
    let mut cursor = Cursor::new(pem.as_bytes());
    let mut certs = rustls_pemfile::certs(&mut cursor);
    match certs.next() {
        Some(cert) => cert.context("解析 CA 证书失败"),
        None => Err(anyhow!("CA 证书是空的")),
    }
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        if let Some((inner, _)) = rest.split_once(']') {
            return inner.to_string();
        }
    }
    if let Some((name, port)) = host.rsplit_once(':') {
        if !name.is_empty() && !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            return name.to_string();
        }
    }
    host.to_string()
}

fn truncate_cn(host: &str) -> String {
    if host.len() <= 64 {
        return host.to_string();
    }
    let mut end = 64;
    while !host.is_char_boundary(end) {
        end -= 1;
    }
    host[..end].to_string()
}

fn write_file(path: &Path, contents: &str, mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .with_context(|| format!("写入 {} 失败", path.display()))?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_reloads_ca() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create_in(dir.path()).unwrap();
        assert!(ca.certified("example.com").is_ok());
        let again = Ca::load_or_create_in(dir.path()).unwrap();
        assert!(again.cert_path().is_file());
        assert!(again.certified("127.0.0.1").is_ok());
    }

    #[test]
    fn reloads_legacy_sec1_key() {
        let dir = tempfile::tempdir().unwrap();
        Ca::load_or_create_in(dir.path()).unwrap();
        let key_path = dir.path().join("ca.key");
        let pkcs8 = fs::read_to_string(&key_path).unwrap();
        use p256::pkcs8::DecodePrivateKey;
        let secret = p256::SecretKey::from_pkcs8_pem(&pkcs8).unwrap();
        let sec1 = secret.to_sec1_pem(p256::pkcs8::LineEnding::LF).unwrap();
        fs::write(&key_path, sec1.as_bytes()).unwrap();
        let ca = Ca::load_or_create_in(dir.path()).unwrap();
        assert!(ca.certified("example.com").is_ok());
    }
}
