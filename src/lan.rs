use std::net::Ipv4Addr;
use std::process::Command;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

struct Addr {
    name: String,
    ip: Ipv4Addr,
}

struct Cache {
    at: Instant,
    addrs: Vec<Ipv4Addr>,
    preferred: Option<Ipv4Addr>,
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

pub fn preferred_ipv4() -> Option<Ipv4Addr> {
    refresh().preferred
}

pub fn ipv4_addrs() -> Vec<Ipv4Addr> {
    refresh().addrs.clone()
}

pub fn has_virtual_adapter() -> bool {
    refresh().addrs.iter().copied().any(is_fake_ip)
}

fn refresh() -> Cache {
    let mut guard = CACHE.lock();
    if let Some(cache) = guard.as_ref() {
        if cache.at.elapsed() < Duration::from_secs(1) {
            return cache.clone();
        }
    }
    let mut all = Vec::new();
    let mut candidates = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }
            let std::net::IpAddr::V4(ip) = iface.ip() else {
                continue;
            };
            if ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() {
                continue;
            }
            if !all.contains(&ip) {
                all.push(ip);
            }
            if usable_iface(&iface.name)
                && !is_fake_ip(ip)
                && !candidates.iter().any(|item: &Addr| item.ip == ip)
            {
                candidates.push(Addr {
                    name: iface.name,
                    ip,
                });
            }
        }
    }
    let preferred = choose_preferred(&candidates, wifi_device().as_deref());
    let cache = Cache {
        at: Instant::now(),
        addrs: all,
        preferred,
    };
    *guard = Some(cache.clone());
    cache
}

fn choose_preferred(candidates: &[Addr], wifi: Option<&str>) -> Option<Ipv4Addr> {
    if let Some(device) = wifi {
        if let Some(ip) = candidates
            .iter()
            .find(|item| item.name == device && is_lan(item.ip))
            .map(|item| item.ip)
        {
            return Some(ip);
        }
    }
    candidates
        .iter()
        .find(|item| is_lan(item.ip))
        .map(|item| item.ip)
}

fn usable_iface(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    const SKIP: &[&str] = &[
        "utun", "ipsec", "ppp", "awdl", "llw", "bridge", "vmnet", "vboxnet", "docker", "veth",
        "gif", "stf", "anpi",
    ];
    !SKIP.iter().any(|prefix| name.starts_with(prefix))
}

fn is_lan(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
}

fn is_fake_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

fn wifi_device() -> Option<String> {
    let output = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    wifi_device_from_ports(&String::from_utf8_lossy(&output.stdout))
}

fn wifi_device_from_ports(text: &str) -> Option<String> {
    let mut port = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("Hardware Port:") {
            port = Some(name.trim().to_string());
        } else if let Some(device) = line.strip_prefix("Device:") {
            if port.as_deref().is_some_and(is_wifi_port) {
                let device = device.trim();
                if !device.is_empty() {
                    return Some(device.to_string());
                }
            }
            port = None;
        }
    }
    None
}

fn is_wifi_port(name: &str) -> bool {
    name.eq_ignore_ascii_case("Wi-Fi")
        || name.eq_ignore_ascii_case("AirPort")
        || name.contains("无线")
}

impl Clone for Cache {
    fn clone(&self) -> Self {
        Self {
            at: self.at,
            addrs: self.addrs.clone(),
            preferred: self.preferred,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_wifi_over_clash_fake_ip() {
        let candidates = vec![addr("utun1024", "198.18.0.1"), addr("en0", "192.168.2.128")];
        let usable: Vec<_> = candidates
            .into_iter()
            .filter(|item| usable_iface(&item.name) && !is_fake_ip(item.ip))
            .collect();
        assert_eq!(
            choose_preferred(&usable, Some("en0")),
            Some(Ipv4Addr::new(192, 168, 2, 128))
        );
    }

    #[test]
    fn parses_wifi_device() {
        let text = "Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n\nHardware Port: Wi-Fi\nDevice: en0\n";
        assert_eq!(wifi_device_from_ports(text).as_deref(), Some("en0"));
    }

    #[test]
    fn live_address_is_private_lan() {
        let Some(ip) = preferred_ipv4() else {
            return;
        };
        assert!(is_lan(ip), "{ip} 不是手机能访问的局域网地址");
        assert!(!is_fake_ip(ip), "{ip} 是虚拟网卡地址");
    }

    fn addr(name: &str, ip: &str) -> Addr {
        Addr {
            name: name.to_string(),
            ip: ip.parse().unwrap(),
        }
    }
}
