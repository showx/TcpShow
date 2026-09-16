package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/showx/TcpShow/internal/ca"
	"github.com/showx/TcpShow/internal/store"
)

var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

type Proxy struct {
	issuer    *ca.Issuer
	store     *store.Store
	transport *http.Transport
	server    *http.Server
	addr      string
	running   atomic.Bool
}

func New(issuer *ca.Issuer, st *store.Store) *Proxy {
	return &Proxy{
		issuer: issuer,
		store:  st,
		transport: &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     false,
			DisableCompression:    true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       60 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 调试抓包：与 Charles 默认行为一致
			},
			DialContext: (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		},
	}
}

func (p *Proxy) Running() bool { return p.running.Load() }

func (p *Proxy) Addr() string { return p.addr }

func (p *Proxy) Start(addr string) error {
	p.server = &http.Server{
		Addr:         addr,
		Handler:      p,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  90 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.addr = ln.Addr().String()
	p.running.Store(true)
	go func() {
		_ = p.server.Serve(ln)
		p.running.Store(false)
	}()
	return nil
}

func (p *Proxy) Stop() error {
	if p.server == nil {
		p.running.Store(false)
		return nil
	}
	err := p.server.Close()
	p.running.Store(false)
	return err
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r, false)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request, mitm bool) {
	sess := p.begin(r, mitm)
	defer p.finish(sess)

	out, err := p.cloneRequest(r, mitm)
	if err != nil {
		sess.Error = err.Error()
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		sess.Error = err.Error()
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	p.captureResponse(sess, resp)

	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(sess.RespBody)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	host := r.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}
	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		serverName = r.Host
	}

	cert, err := p.issuer.Cert(serverName)
	if err != nil {
		_ = clientConn.Close()
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsClient.Handshake(); err != nil {
		_ = clientConn.Close()
		return
	}
	defer tlsClient.Close()

	reader := bufio.NewReader(tlsClient)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = host
		if req.Host == "" {
			req.Host = host
		}
		p.serveMITM(tlsClient, req)
	}
}

func (p *Proxy) serveMITM(client io.Writer, r *http.Request) {
	sess := p.begin(r, true)
	defer p.finish(sess)

	out, err := p.cloneRequest(r, true)
	if err != nil {
		sess.Error = err.Error()
		writePlain(client, http.StatusBadGateway, err.Error())
		return
	}
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		sess.Error = err.Error()
		writePlain(client, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()
	p.captureResponse(sess, resp)

	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	resp.ContentLength = int64(len(sess.RespBody))
	resp.Header.Set("Content-Length", itoa(len(sess.RespBody)))
	resp.Header.Del("Transfer-Encoding")
	resp.Body = io.NopCloser(bytes.NewReader(sess.RespBody))
	_ = resp.Write(client)
}

func (p *Proxy) begin(r *http.Request, mitm bool) *store.Session {
	scheme := r.URL.Scheme
	if scheme == "" {
		if mitm {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	path := r.URL.RequestURI()
	if r.URL.Opaque != "" || !strings.HasPrefix(path, "/") {
		if r.URL.Path == "" {
			path = "/"
		} else {
			path = r.URL.Path
			if r.URL.RawQuery != "" {
				path += "?" + r.URL.RawQuery
			}
		}
	}
	rawURL := scheme + "://" + stripPort(host, scheme) + path
	if r.URL.Scheme != "" && r.URL.Host != "" {
		rawURL = r.URL.String()
	}

	body, _ := store.ReadBody(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	sess := &store.Session{
		Scheme:      scheme,
		Method:      r.Method,
		Host:        stripPort(host, scheme),
		Path:        path,
		URL:         rawURL,
		ReqHeaders:  store.HeadersFrom(r.Header),
		ReqBody:     body,
		ReqDisplay:  store.DecodeForDisplay(r.Header, body),
		ReqSize:     len(body),
		Start:       time.Now(),
		ClientAddr:  r.RemoteAddr,
	}
	if hostHdr := r.Host; hostHdr != "" {
		hasHost := false
		for _, h := range sess.ReqHeaders {
			if strings.EqualFold(h.Name, "Host") {
				hasHost = true
				break
			}
		}
		if !hasHost {
			sess.ReqHeaders = append([]store.Header{{Name: "Host", Value: hostHdr}}, sess.ReqHeaders...)
		}
	}
	p.store.Add(sess)
	return sess
}

func (p *Proxy) captureResponse(sess *store.Session, resp *http.Response) {
	body, _ := store.ReadBody(resp.Body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	sess.Status = resp.StatusCode
	sess.ContentType = resp.Header.Get("Content-Type")
	sess.RespHeaders = store.HeadersFrom(resp.Header)
	sess.RespBody = body
	sess.RespDisplay = store.DecodeForDisplay(resp.Header, body)
	sess.RespSize = len(body)
}

func (p *Proxy) finish(sess *store.Session) {
	sess.Duration = time.Since(sess.Start)
	p.store.Update(sess)
}

func (p *Proxy) cloneRequest(r *http.Request, mitm bool) (*http.Request, error) {
	out := r.Clone(r.Context())
	if mitm || out.URL.Scheme == "" {
		if mitm {
			out.URL.Scheme = "https"
		} else if out.URL.Scheme == "" {
			out.URL.Scheme = "http"
		}
	}
	if out.URL.Host == "" {
		out.URL.Host = r.Host
	}
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	if c := out.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			out.Header.Del(strings.TrimSpace(f))
		}
	}
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	return out, nil
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func writePlain(w io.Writer, status int, msg string) {
	body := msg + "\n"
	_, _ = io.WriteString(w, "HTTP/1.1 "+itoa(status)+" "+http.StatusText(status)+"\r\n")
	_, _ = io.WriteString(w, "Content-Type: text/plain; charset=utf-8\r\n")
	_, _ = io.WriteString(w, "Content-Length: "+itoa(len(body))+"\r\n")
	_, _ = io.WriteString(w, "Connection: close\r\n\r\n")
	_, _ = io.WriteString(w, body)
}

func stripPort(host, scheme string) string {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return h
	}
	return host
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
