package store

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const MaxSessions = 10000
const MaxBody = 2 << 20 // 2MB

type Header struct {
	Name  string
	Value string
}

type Session struct {
	ID           int
	Scheme       string
	Method       string
	Host         string
	Path         string
	URL          string
	Status       int
	ContentType  string
	ReqHeaders   []Header
	RespHeaders  []Header
	ReqBody      []byte
	RespBody     []byte
	ReqDisplay   string
	RespDisplay  string
	ReqSize      int
	RespSize     int
	Start        time.Time
	Duration     time.Duration
	Error        string
	ClientAddr   string
}

func (s *Session) StatusText() string {
	if s.Error != "" && s.Status == 0 {
		return "ERR"
	}
	if s.Status == 0 {
		return "..."
	}
	return fmt.Sprintf("%d", s.Status)
}

func (s *Session) SizeText() string {
	return formatBytes(s.RespSize)
}

func (s *Session) TimeText() string {
	if s.Duration <= 0 {
		return ""
	}
	if s.Duration < time.Second {
		return fmt.Sprintf("%d ms", s.Duration.Milliseconds())
	}
	return fmt.Sprintf("%.1f s", s.Duration.Seconds())
}

func (s *Session) Curl() string {
	var b strings.Builder
	fmt.Fprintf(&b, "curl -k -X %s '%s'", s.Method, escape(s.URL))
	for _, h := range s.ReqHeaders {
		name := strings.ToLower(h.Name)
		if name == "host" || name == "content-length" || name == "transfer-encoding" {
			continue
		}
		fmt.Fprintf(&b, " \\\n  -H '%s: %s'", escape(h.Name), escape(h.Value))
	}
	if len(s.ReqBody) > 0 && s.Method != http.MethodGet && s.Method != http.MethodHead {
		fmt.Fprintf(&b, " \\\n  --data-binary '%s'", escape(string(s.ReqBody)))
	}
	return b.String()
}

func (s *Session) RequestRaw() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\n", s.Method, s.Path)
	for _, h := range s.ReqHeaders {
		fmt.Fprintf(&b, "%s: %s\n", h.Name, h.Value)
	}
	return b.String()
}

func (s *Session) ResponseRaw() string {
	var b strings.Builder
	if s.Error != "" && s.Status == 0 {
		return "Error: " + s.Error
	}
	fmt.Fprintf(&b, "HTTP/1.1 %d\n", s.Status)
	for _, h := range s.RespHeaders {
		fmt.Fprintf(&b, "%s: %s\n", h.Name, h.Value)
	}
	return b.String()
}

type Store struct {
	mu        sync.RWMutex
	sessions  []*Session
	nextID    int
	recording bool
	listeners []func()
}

func New() *Store {
	return &Store{recording: true, nextID: 1}
}

func (s *Store) Recording() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.recording
}

func (s *Store) SetRecording(v bool) {
	s.mu.Lock()
	s.recording = v
	s.mu.Unlock()
}

func (s *Store) OnChange(fn func()) {
	s.mu.Lock()
	s.listeners = append(s.listeners, fn)
	s.mu.Unlock()
}

func (s *Store) Add(sess *Session) {
	if sess == nil {
		return
	}
	s.mu.Lock()
	if !s.recording {
		s.mu.Unlock()
		return
	}
	sess.ID = s.nextID
	s.nextID++
	s.sessions = append(s.sessions, sess)
	if len(s.sessions) > MaxSessions {
		s.sessions = s.sessions[len(s.sessions)-MaxSessions:]
	}
	listeners := append([]func(){}, s.listeners...)
	s.mu.Unlock()
	for _, fn := range listeners {
		fn()
	}
}

func (s *Store) Update(sess *Session) {
	s.mu.Lock()
	listeners := append([]func(){}, s.listeners...)
	s.mu.Unlock()
	for _, fn := range listeners {
		fn()
	}
}

func (s *Store) Clear() {
	s.mu.Lock()
	s.sessions = nil
	listeners := append([]func(){}, s.listeners...)
	s.mu.Unlock()
	for _, fn := range listeners {
		fn()
	}
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *Store) Snapshot() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Session, len(s.sessions))
	copy(out, s.sessions)
	return out
}

func (s *Store) Filtered(q string) []*Session {
	all := s.Snapshot()
	q = strings.TrimSpace(strings.ToLower(q))
	if q == "" {
		return all
	}
	out := make([]*Session, 0, len(all))
	for _, sess := range all {
		if strings.Contains(strings.ToLower(sess.Method+" "+sess.Host+" "+sess.Path+" "+sess.URL+" "+sess.StatusText()), q) {
			out = append(out, sess)
		}
	}
	return out
}

func HeadersFrom(h http.Header) []Header {
	out := make([]Header, 0, len(h))
	for k, vals := range h {
		out = append(out, Header{Name: k, Value: strings.Join(vals, ", ")})
	}
	return out
}

func ReadBody(r io.ReadCloser) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, MaxBody+1))
	if err != nil {
		return data, err
	}
	if len(data) > MaxBody {
		return data[:MaxBody], nil
	}
	return data, nil
}

func DecodeForDisplay(headers http.Header, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	decoded := decodeEncoding(headers.Get("Content-Encoding"), body)
	ct := headers.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.Contains(strings.ToLower(ct), "json") || looksJSON(decoded) {
		var buf bytes.Buffer
		if json.Indent(&buf, bytes.TrimSpace(decoded), "", "  ") == nil {
			return buf.String()
		}
	}
	if utf8.Valid(decoded) && !bytes.Contains(decoded, []byte{0}) {
		return string(decoded)
	}
	n := len(decoded)
	if n > 1024 {
		n = 1024
	}
	return "[binary]\n" + hex.Dump(decoded[:n])
}

func decodeEncoding(enc string, body []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, MaxBody))
		if err != nil {
			return body
		}
		return out
	case "deflate":
		r := flate.NewReader(bytes.NewReader(body))
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, MaxBody))
		if err != nil {
			return body
		}
		return out
	default:
		return body
	}
}

func looksJSON(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 1 && ((b[0] == '{' && b[len(b)-1] == '}') || (b[0] == '[' && b[len(b)-1] == ']'))
}

func formatBytes(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
}

func escape(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}
