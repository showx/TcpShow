package store

import (
	"net/http"
	"strings"
	"testing"
)

func TestDecodeJSON(t *testing.T) {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	got := DecodeForDisplay(h, []byte(`{"a":1}`))
	if !strings.Contains(got, `"a"`) {
		t.Fatalf("got %q", got)
	}
}

func TestFilter(t *testing.T) {
	s := New()
	s.Add(&Session{Method: "GET", Host: "example.com", Path: "/hello", URL: "http://example.com/hello"})
	s.Add(&Session{Method: "POST", Host: "api.test", Path: "/v1", URL: "http://api.test/v1"})
	if n := len(s.Filtered("example")); n != 1 {
		t.Fatalf("filter example: %d", n)
	}
	if n := len(s.Filtered("POST")); n != 1 {
		t.Fatalf("filter POST: %d", n)
	}
}

func TestNoRecord(t *testing.T) {
	s := New()
	s.SetRecording(false)
	s.Add(&Session{Method: "GET", Host: "x"})
	if s.Len() != 0 {
		t.Fatal("should skip when paused")
	}
}
