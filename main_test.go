package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExpandTargets(t *testing.T) {
	cases := []struct {
		target     string
		start, end int
		wantLen    int
		wantFirst  string
		wantLast   string
	}{
		{"5.218.21.x", 0, 244, 245, "5.218.21.0", "5.218.21.244"},
		{"5.218.21.x", 0, 255, 256, "5.218.21.0", "5.218.21.255"},
		{"5.218.21", 0, 255, 256, "5.218.21.0", "5.218.21.255"},
		{"192.168.1.5", 0, 255, 1, "192.168.1.5", "192.168.1.5"},
		{"10.0.0.0/30", 0, 255, 4, "10.0.0.0", "10.0.0.3"},
	}
	for _, c := range cases {
		ips, err := expandTargets(c.target, c.start, c.end)
		if err != nil {
			t.Fatalf("expandTargets(%q): %v", c.target, err)
		}
		if len(ips) != c.wantLen || ips[0] != c.wantFirst || ips[len(ips)-1] != c.wantLast {
			t.Errorf("expandTargets(%q, %d, %d) = %d hosts [%s…%s], want %d [%s…%s]",
				c.target, c.start, c.end, len(ips), ips[0], ips[len(ips)-1], c.wantLen, c.wantFirst, c.wantLast)
		}
	}
	if _, err := expandTargets("5.218.x.x", 0, 255); err != nil {
		t.Errorf("5.218.x.x should be allowed (65536 hosts): %v", err)
	}
	if _, err := expandTargets("10.0.0.0/8", 0, 255); err == nil {
		t.Error("10.0.0.0/8 should be rejected as too large")
	}
}

func TestGrabInfoPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.Write([]byte("<html><head><title>Plain Test Page</title></head></html>"))
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	res := Result{Type: "result", IP: host, Port: port}
	grabInfoScheme(&res, 2*time.Second, false)
	if res.Title != "Plain Test Page" {
		t.Errorf("title = %q, want %q", res.Title, "Plain Test Page")
	}
	if res.Status == "" || !strings.HasPrefix(res.Status, "200") {
		t.Errorf("status = %q, want 200...", res.Status)
	}
	if res.Server != "TestServer/1.0" {
		t.Errorf("server = %q", res.Server)
	}
	if res.TLS != "" {
		t.Errorf("tls CN should be empty for plain HTTP, got %q", res.TLS)
	}
}

func TestGrabInfoTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>TLS Test Page</title></head></html>"))
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)
	res := Result{Type: "result", IP: host, Port: port}
	grabInfoScheme(&res, 2*time.Second, true)
	if res.Title != "TLS Test Page" {
		t.Errorf("title = %q, want %q", res.Title, "TLS Test Page")
	}
	if res.TLS == "" {
		t.Error("expected a certificate common name for the TLS endpoint")
	}
	if res.Status == "" || !strings.HasPrefix(res.Status, "200") {
		t.Errorf("status = %q, want 200...", res.Status)
	}
}
