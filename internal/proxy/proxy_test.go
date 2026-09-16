package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/showx/TcpShow/internal/ca"
	"github.com/showx/TcpShow/internal/store"
)

func TestHTTPCapture(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(upstream.Close)

	p, st := startProxy(t)
	client := proxyClient(t, p.Addr(), false)
	resp, err := client.Get(upstream.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ok") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	waitSessions(t, st, 1)
	s := st.Snapshot()[0]
	if s.Method != http.MethodGet || !strings.Contains(s.Path, "/hello") {
		t.Fatalf("session %+v", s)
	}
	if s.Status != 200 {
		t.Fatalf("captured status %d", s.Status)
	}
}

func TestHTTPSCapture(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	t.Cleanup(upstream.Close)

	p, st := startProxy(t)
	client := proxyClient(t, p.Addr(), true)
	resp, err := client.Get(upstream.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "pong" {
		t.Fatalf("body=%s", body)
	}
	waitSessions(t, st, 1)
	s := st.Snapshot()[0]
	if s.Scheme != "https" || s.Status != 200 {
		t.Fatalf("session scheme=%s status=%d err=%s", s.Scheme, s.Status, s.Error)
	}
	if s.RespDisplay != "pong" {
		t.Fatalf("display=%q", s.RespDisplay)
	}
}

func startProxy(t *testing.T) (*Proxy, *store.Store) {
	t.Helper()
	issuer, err := ca.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	st := store.New()
	p := New(issuer, st)
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop() })
	return p, st
}

func proxyClient(t *testing.T, addr string, https bool) *http.Client {
	t.Helper()
	u, err := url.Parse("http://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(u)}
	if https {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: tr, Timeout: 8 * time.Second}
}

func waitSessions(t *testing.T, st *store.Store, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if st.Len() >= n {
			snap := st.Snapshot()
			if snap[len(snap)-1].Status != 0 || snap[len(snap)-1].Error != "" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want %d sessions, got %d", n, st.Len())
}
