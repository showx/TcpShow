use std::process::Command;

const CA_NAME: &str = "TcpShow CA";

pub fn set(host: &str, port: &str) -> Result<String, String> {
    if !cfg!(target_os = "macos") {
        return Err("系统代理目前只支持 macOS".into());
    }
    let service = active_service()?;
    let cmds = [
        vec!["-setwebproxy", &service, host, port],
        vec!["-setsecurewebproxy", &service, host, port],
        vec!["-setwebproxystate", &service, "on"],
        vec!["-setsecurewebproxystate", &service, "on"],
    ];
    for args in cmds {
        run("networksetup", &args)?;
    }
    Ok(service)
}

pub fn clear(service: &str) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }
    let owned;
    let service = if service.is_empty() {
        owned = active_service()?;
        owned.as_str()
    } else {
        service
    };
    run("networksetup", &["-setwebproxystate", service, "off"])?;
    run("networksetup", &["-setsecurewebproxystate", service, "off"])?;
    Ok(())
}

pub fn trust_cert(path: &str) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("自动信任证书目前只支持 macOS，请手动导入证书".into());
    }
    if cert_trusted() {
        return Ok(());
    }
    let script = format!(
        "do shell script \"security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}\" with administrator privileges",
        shell_quote(path)
    );
    let output = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|err| err.to_string())?;
    if output.status.success() {
        return Ok(());
    }
    let mut message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if message.is_empty() {
        message = String::from_utf8_lossy(&output.stdout).trim().to_string();
    }
    if message.is_empty() {
        message = "系统拒绝了证书安装".into();
    }
    Err(message)
}

pub fn cert_trusted() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    for args in [
        ["dump-trust-settings"].as_slice(),
        ["dump-trust-settings", "-d"].as_slice(),
    ] {
        if let Ok(output) = Command::new("security").args(args).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            let err = String::from_utf8_lossy(&output.stderr);
            if text.contains(CA_NAME) || err.contains(CA_NAME) {
                return true;
            }
        }
    }
    false
}

fn active_service() -> Result<String, String> {
    let route = command_output("route", &["-n", "get", "default"])?;
    if let Some(iface) = iface_from_route(&route) {
        let ports = command_output("networksetup", &["-listallhardwareports"])?;
        if let Some(service) = service_for_device(&ports, &iface) {
            return Ok(service);
        }
    }
    let list = command_output("networksetup", &["-listallnetworkservices"])?;
    fallback_service(&list).ok_or_else(|| "找不到可用的网络服务".into())
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("{program}: {err}"))?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if err.is_empty() {
            format!("{program} 执行失败")
        } else {
            err
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| format!("{program}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} {}", program, args.join(" ")))
    }
}

fn iface_from_route(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("interface:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

fn service_for_device(text: &str, device: &str) -> Option<String> {
    let mut current = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Hardware Port:") {
            current = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Device:") {
            if rest.trim() == device {
                return current.filter(|name| !name.is_empty());
            }
        }
    }
    None
}

fn fallback_service(list: &str) -> Option<String> {
    let mut first = None;
    let mut ethernet = None;
    let mut lan = None;
    for (index, line) in list.lines().enumerate() {
        let line = line.trim();
        if index == 0 || line.is_empty() || line.starts_with('*') || line.starts_with("An asterisk")
        {
            continue;
        }
        if first.is_none() {
            first = Some(line.to_string());
        }
        if line == "Wi-Fi" {
            return Some(line.to_string());
        }
        if line == "Ethernet" {
            ethernet = Some(line.to_string());
        } else if line.contains("LAN") && lan.is_none() {
            lan = Some(line.to_string());
        }
    }
    ethernet.or(lan).or(first)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_route_and_hardware_ports() {
        let route = "destination: default\n  interface: en0\n";
        assert_eq!(iface_from_route(route).as_deref(), Some("en0"));
        let ports = "Hardware Port: Ethernet\nDevice: en1\n\nHardware Port: Wi-Fi\nDevice: en0\n";
        assert_eq!(service_for_device(ports, "en0").as_deref(), Some("Wi-Fi"));
        let list = "An asterisk (*) denotes that a network service is disabled.\n*Thunderbolt Bridge\nEthernet\nWi-Fi\n";
        assert_eq!(fallback_service(list).as_deref(), Some("Wi-Fi"));
    }

    #[test]
    fn quotes_paths() {
        assert_eq!(shell_quote("/tmp/a b.pem"), "'/tmp/a b.pem'");
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }
}
