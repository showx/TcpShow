package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	caCertFile = "ca.pem"
	caKeyFile  = "ca.key"
	caName     = "TcpShow CA"
)

// Issuer issues per-host certificates signed by a local CA.
type Issuer struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	dir    string

	mu    sync.Mutex
	cache map[string]tls.Certificate
}

func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "TcpShow")
	return dir, os.MkdirAll(dir, 0o700)
}

func LoadOrCreate() (*Issuer, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		iss, err := load(dir, certPath, keyPath)
		if err == nil {
			return iss, nil
		}
	}
	return create(dir, certPath, keyPath)
}

func (i *Issuer) CertPEMPath() string {
	return filepath.Join(i.dir, caCertFile)
}

func (i *Issuer) Cert(host string) (tls.Certificate, error) {
	host = normalizeHost(host)
	i.mu.Lock()
	defer i.mu.Unlock()
	if c, ok := i.cache[host]; ok {
		return c, nil
	}
	c, err := i.issue(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	i.cache[host] = c
	return c, nil
}

func load(dir, certPath, keyPath string) (*Issuer, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid CA cert")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid CA key")
	}
	caKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &Issuer{caCert: caCert, caKey: caKey, dir: dir, cache: map[string]tls.Certificate{}}, nil
}

func create(dir, certPath, keyPath string) (*Issuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caName,
			Organization: []string{"TcpShow"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return &Issuer{caCert: cert, caKey: key, dir: dir, cache: map[string]tls.Certificate{}}, nil
}

func (i *Issuer) issue(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   truncateCN(host),
			Organization: []string{"TcpShow"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.caCert, &key.PublicKey, i.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.caCert.Raw})
	return tls.X509KeyPair(append(certPEM, caPEM...), keyPEM)
}

func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func truncateCN(s string) string {
	if len(s) <= 64 {
		return s
	}
	return s[:64]
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
