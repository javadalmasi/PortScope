// PortScope — fast parallel HTTP/HTTPS (80/443) scanner for IP ranges with a web UI.
package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed index.html
var indexHTML []byte

const (
	defaultTimeoutMS   = 800
	defaultConcurrency = 1000
	maxHosts           = 1 << 20 // 1,048,576 hosts per scan
	maxHistory         = 250_000 // result events kept for live-reconnect replay
)

// ---------------------------------------------------------------------------
// API types

type ScanRequest struct {
	Target      string `json:"target"`      // e.g. "5.218.21.x", "5.218.x.x", "10.0.0.0/24"
	Ports       []int  `json:"ports"`       // default [80, 443]
	Start       int    `json:"start"`       // wildcard octet range start (default 0)
	End         int    `json:"end"`         // wildcard octet range end   (default 255)
	TimeoutMS   int    `json:"timeoutMs"`   // per-probe TCP connect timeout
	Concurrency int    `json:"concurrency"` // parallel workers
	GrabBanner  bool   `json:"grabBanner"`  // fetch page title / server header / TLS CN
}

type Result struct {
	Type      string `json:"type"` // "result"
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Scheme    string `json:"scheme"`
	Open      bool   `json:"open"`
	LatencyMS int64  `json:"latencyMs"`
	Status    string `json:"status,omitempty"`
	Title     string `json:"title,omitempty"`
	Server    string `json:"server,omitempty"`
	TLS       string `json:"tls,omitempty"` // certificate common name
}

type startEvt struct {
	Type   string `json:"type"` // "start"
	Target string `json:"target"`
	Hosts  int    `json:"hosts"`
	Checks int    `json:"checks"`
}

type progressEvt struct {
	Type      string  `json:"type"` // "progress"
	Scanned   int64   `json:"scanned"`
	Found     int64   `json:"found"`
	Total     int64   `json:"total"`
	ElapsedMS int64   `json:"elapsedMs"`
	Rate      float64 `json:"rate"`
}

type doneEvt struct {
	Type      string `json:"type"` // "done"
	Scanned   int64  `json:"scanned"`
	Found     int64  `json:"found"`
	ElapsedMS int64  `json:"elapsedMs"`
	Stopped   bool   `json:"stopped"`
}

type errorEvt struct {
	Type    string `json:"type"` // "error"
	Message string `json:"message"`
}

// ---------------------------------------------------------------------------
// Event hub: fan-out to SSE subscribers + replay history on reconnect

type hub struct {
	mu           sync.Mutex
	subs         map[chan []byte]struct{}
	history      [][]byte // start + result events of the current job
	lastProgress []byte
	terminal     []byte // last done/error event
}

func newHub() *hub { return &hub{subs: make(map[chan []byte]struct{})} }

func (h *hub) publish(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	switch v.(type) {
	case startEvt:
		h.history = append(h.history[:0], b)
		h.lastProgress = nil
		h.terminal = nil
	case Result:
		if len(h.history) < maxHistory {
			h.history = append(h.history, b)
		}
	case progressEvt:
		h.lastProgress = b
	case doneEvt, errorEvt:
		h.terminal = b
	}
	for ch := range h.subs {
		select {
		case ch <- b:
		default: // slow subscriber: drop rather than block the scan
		}
	}
	h.mu.Unlock()
}

func (h *hub) subscribe() (snap [][]byte, ch chan []byte) {
	ch = make(chan []byte, 8192)
	h.mu.Lock()
	defer h.mu.Unlock()
	snap = make([][]byte, 0, len(h.history)+2)
	snap = append(snap, h.history...)
	if h.lastProgress != nil {
		snap = append(snap, h.lastProgress)
	}
	if h.terminal != nil {
		snap = append(snap, h.terminal)
	}
	h.subs[ch] = struct{}{}
	return snap, ch
}

func (h *hub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Application

type app struct {
	hub    *hub
	mu     sync.Mutex
	cancel context.CancelFunc
	gen    int64
}

func newApp() *app { return &app{hub: newHub()} }

func (a *app) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ScanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		badRequest(w, "invalid JSON body: "+err.Error())
		return
	}
	if err := normalize(&req); err != nil {
		badRequest(w, err.Error())
		return
	}
	ips, err := expandTargets(req.Target, req.Start, req.End)
	if err != nil {
		badRequest(w, err.Error())
		return
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond

	a.mu.Lock()
	a.gen++
	gen := a.gen
	if a.cancel != nil {
		a.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.mu.Unlock()

	go a.run(ctx, gen, req, ips, req.Ports, timeout)
	writeJSON(w, map[string]any{"ok": true, "hosts": len(ips), "checks": len(ips) * len(req.Ports)})
}

func (a *app) stop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true})
}

func (a *app) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	snap, ch := a.hub.subscribe()
	defer a.hub.unsubscribe(ch)
	for _, b := range snap {
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	fl.Flush()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case b, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-t.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (a *app) run(ctx context.Context, gen int64, req ScanRequest, ips []string, ports []int, timeout time.Duration) {
	total := len(ips) * len(ports)
	a.hub.publish(startEvt{Type: "start", Target: req.Target, Hosts: len(ips), Checks: total})

	type workItem struct {
		ip   string
		port int
	}
	work := make(chan workItem, 8192)
	go func() {
		defer close(work)
		for _, ip := range ips {
			for _, p := range ports {
				select {
				case work <- workItem{ip, p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	var scanned, found atomic.Int64
	begin := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < req.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range work {
				if ctx.Err() != nil {
					return
				}
				res := probe(ctx, it.ip, it.port, timeout, req.GrabBanner)
				scanned.Add(1)
				if res.Open {
					found.Add(1)
					a.hub.publish(res)
				}
			}
		}()
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		tk := time.NewTicker(200 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-tk.C:
				el := time.Since(begin)
				sc := scanned.Load()
				rate := 0.0
				if el > 0 {
					rate = float64(sc) / el.Seconds()
				}
				a.hub.publish(progressEvt{Type: "progress", Scanned: sc, Found: found.Load(),
					Total: int64(total), ElapsedMS: el.Milliseconds(), Rate: rate})
			case <-done:
				return
			}
		}
	}()

	wg.Wait()
	a.hub.publish(doneEvt{Type: "done", Scanned: scanned.Load(), Found: found.Load(),
		ElapsedMS: time.Since(begin).Milliseconds(), Stopped: ctx.Err() != nil})
	a.mu.Lock()
	if a.gen == gen {
		a.cancel = nil
	}
	a.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Probing

func schemeFor(port int) string {
	if port == 443 {
		return "https"
	}
	return "http"
}

func probe(ctx context.Context, ip string, port int, timeout time.Duration, grab bool) Result {
	res := Result{Type: "result", IP: ip, Port: port, Scheme: schemeFor(port)}
	d := net.Dialer{Timeout: timeout}
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return res
	}
	res.LatencyMS = time.Since(t0).Milliseconds()
	conn.Close()
	res.Open = true
	if grab {
		grabInfo(&res, timeout)
	}
	return res
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// grabInfo performs an HTTP(S) GET against an open host and records the status
// line, Server header, page title and (for TLS) the certificate common name.
// Port 443 is probed over TLS; every other port over plain HTTP.
func grabInfo(res *Result, timeout time.Duration) {
	grabInfoScheme(res, timeout, res.Port == 443)
}

func grabInfoScheme(res *Result, timeout time.Duration, isTLS bool) {
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	var cn atomic.Value // string
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	tr := &http.Transport{
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       tlsCfg,
	}
	if isTLS {
		d := &net.Dialer{Timeout: timeout}
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := tls.DialWithDialer(d, network, addr, tlsCfg)
			if err != nil {
				return nil, err
			}
			if certs := c.ConnectionState().PeerCertificates; len(certs) > 0 {
				name := certs[0].Subject.CommonName
				if name == "" && len(certs[0].DNSNames) > 0 {
					name = certs[0].DNSNames[0]
				}
				cn.Store(name)
			}
			return c, nil
		}
	} else {
		tr.DialContext = (&net.Dialer{Timeout: timeout}).DialContext
	}
	client := &http.Client{Transport: tr, Timeout: timeout*2 + time.Second}
	u := scheme + "://" + net.JoinHostPort(res.IP, strconv.Itoa(res.Port)) + "/"
	resp, err := client.Get(u)
	if name, ok := cn.Load().(string); ok {
		res.TLS = name
	}
	if err != nil {
		return
	}
	defer resp.Body.Close()
	res.Status = resp.Status
	res.Server = resp.Header.Get("Server")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if m := titleRe.FindSubmatch(body); m != nil {
		t := strings.Join(strings.Fields(string(m[1])), " ")
		if len(t) > 120 {
			t = t[:120] + "…"
		}
		res.Title = t
	}
}

// ---------------------------------------------------------------------------
// Target expansion

func normalize(req *ScanRequest) error {
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		return errors.New("target is required")
	}
	if len(req.Ports) == 0 {
		req.Ports = []int{80, 443}
	}
	if len(req.Ports) > 32 {
		return errors.New("too many ports (max 32)")
	}
	cleaned := make([]int, 0, len(req.Ports))
	seen := make(map[int]bool, len(req.Ports))
	for _, p := range req.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %d (must be 1-65535)", p)
		}
		if !seen[p] {
			seen[p] = true
			cleaned = append(cleaned, p)
		}
	}
	req.Ports = cleaned
	if req.End == 0 {
		req.End = 255
	}
	if req.Start < 0 || req.Start > 255 || req.End > 255 || req.Start > req.End {
		return errors.New("octet range must satisfy 0 <= start <= end <= 255")
	}
	if req.TimeoutMS <= 0 {
		req.TimeoutMS = defaultTimeoutMS
	}
	if req.TimeoutMS < 50 {
		req.TimeoutMS = 50
	}
	if req.TimeoutMS > 15000 {
		req.TimeoutMS = 15000
	}
	if req.Concurrency <= 0 {
		req.Concurrency = defaultConcurrency
	}
	if req.Concurrency > 5000 {
		req.Concurrency = 5000
	}
	return nil
}

// expandTargets turns "5.218.21.x", "5.218", "5.218.x.x" or "10.0.0.0/24"
// into the full list of host addresses.
func expandTargets(target string, start, end int) ([]string, error) {
	t := strings.TrimSpace(target)
	t = strings.TrimSuffix(t, ".")
	if t == "" {
		return nil, errors.New("target is required")
	}
	if strings.Contains(t, "/") {
		p, err := netip.ParsePrefix(t)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", target, err)
		}
		hostBits := p.Addr().BitLen() - p.Bits()
		if hostBits > 20 {
			return nil, fmt.Errorf("range too large: /%d is %d hosts (max %d)", p.Bits(), 1<<hostBits, maxHosts)
		}
		n := 1 << hostBits
		ips := make([]string, 0, n)
		addr := p.Addr()
		for i := 0; i < n; i++ {
			ips = append(ips, addr.String())
			addr = addr.Next()
		}
		return ips, nil
	}
	parts := strings.Split(t, ".")
	for len(parts) < 4 {
		parts = append(parts, "x")
	}
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid target %q — expected an IPv4 with x wildcards", target)
	}
	type oct struct{ lo, hi int }
	var o [4]oct
	total := 1
	for i, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "x", "X", "*", "?", "":
			lo, hi := start, end
			if lo > hi {
				lo, hi = hi, lo
			}
			o[i] = oct{lo, hi}
			total *= hi - lo + 1
		default:
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("invalid octet %q", p)
			}
			o[i] = oct{n, n}
		}
	}
	if total > maxHosts {
		return nil, fmt.Errorf("range too large: %d hosts (max %d)", total, maxHosts)
	}
	ips := make([]string, 0, total)
	for a := o[0].lo; a <= o[0].hi; a++ {
		for b := o[1].lo; b <= o[1].hi; b++ {
			for c := o[2].lo; c <= o[2].hi; c++ {
				for d := o[3].lo; d <= o[3].hi; d++ {
					ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
				}
			}
		}
	}
	return ips, nil
}

// ---------------------------------------------------------------------------
// Server plumbing

func home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func badRequest(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusBadRequest)
}

func openBrowser(u string) {
	time.Sleep(300 * time.Millisecond)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Run()
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8899", "listen address for the web UI")
	open := flag.Bool("open", true, "open the web UI in the default browser on start")
	flag.Parse()

	raiseFileLimit()

	a := newApp()
	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/api/scan", a.scan)
	mux.HandleFunc("/api/stop", a.stop)
	mux.HandleFunc("/api/stream", a.stream)

	host, port, _ := net.SplitHostPort(*addr)
	if host == "" {
		host = "127.0.0.1"
	}
	u := "http://" + net.JoinHostPort(host, port)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("cannot listen on %s: %v", *addr, err)
	}
	log.Printf("PortScope — IP Range HTTP/HTTPS Scanner -> %s  (Ctrl+C to quit)", u)
	if *open {
		go openBrowser(u)
	}
	if err := http.Serve(ln, mux); err != nil {
		log.Fatal(err)
	}
}
