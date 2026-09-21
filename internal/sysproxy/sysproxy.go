package sysproxy

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

func Set(host, port string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("系统代理目前仅支持 macOS")
	}
	service, err := defaultService()
	if err != nil {
		return err
	}
	cmds := [][]string{
		{"networksetup", "-setwebproxy", service, host, port},
		{"networksetup", "-setsecurewebproxy", service, host, port},
		{"networksetup", "-setwebproxystate", service, "on"},
		{"networksetup", "-setsecurewebproxystate", service, "on"},
	}
	return runAll(cmds)
}

func Clear() error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	service, err := defaultService()
	if err != nil {
		return err
	}
	cmds := [][]string{
		{"networksetup", "-setwebproxystate", service, "off"},
		{"networksetup", "-setsecurewebproxystate", service, "off"},
	}
	return runAll(cmds)
}

func OpenCert(path string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", path).Start()
	case "windows":
		return exec.Command("rundll32", "crypto.dll,CryptExtOpenCER", path).Start()
	default:
		return exec.Command("xdg-open", path).Start()
	}
}

const CAName = "TcpShow CA"

// TrustCert installs the CA as a trusted system root. On macOS this prompts for the admin password.
func TrustCert(certPath string) error {
	if runtime.GOOS != "darwin" {
		return OpenCert(certPath)
	}
	if CertTrusted() {
		return nil
	}
	script := fmt.Sprintf(
		`do shell script "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain %s" with administrator privileges`,
		shellQuote(certPath),
	)
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func CertTrusted() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	for _, args := range [][]string{
		{"security", "dump-trust-settings"},
		{"security", "dump-trust-settings", "-d"},
	} {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err == nil && strings.Contains(string(out), CAName) {
			return true
		}
	}
	return false
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func defaultService() (string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return "", err
	}
	var first string
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		if first == "" {
			first = line
		}
		if line == "Wi-Fi" || line == "Ethernet" || strings.Contains(line, "LAN") {
			return line, nil
		}
	}
	if first == "" {
		return "", fmt.Errorf("找不到网络服务")
	}
	return first, nil
}

func runAll(cmds [][]string) error {
	for _, args := range cmds {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}
