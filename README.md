# iphttp — IP Range HTTP/HTTPS Scanner (Web UI)

Fast, parallel scanner that checks which hosts in an IP range are serving
HTTP (port 80) or HTTPS (port 443), with a live web dashboard.
Written in Go, standard library only — thousands of concurrent TCP probes,
results streamed to the browser in real time via Server-Sent Events.

## Quick start

```
go build -o iphttp .
./iphttp
```

The UI opens automatically at http://127.0.0.1:8899 (pass `-open=false` to disable).
Run tests with `go test ./...`.

## Usage

1. Type a target — any octet can be an `x` wildcard:
   - `5.218.21.x` — scans `5.218.21.0`–`5.218.21.255`
   - `5.218.21` — same as `5.218.21.x`
   - `5.218.x.x` — scans the whole /16 (65,536 hosts)
   - `10.0.0.0/24` — CIDR notation also works
2. Set the wildcard octet range (default 0–255, e.g. 0–244), the port list
   (default `80, 443`), the per-probe timeout, and the concurrency.
3. Press **Start scan**. Open hosts appear live with HTTP status, page title,
   Server header, TLS certificate CN and latency. Click an IP to open it.
4. Use **Stop** to cancel, **Copy IPs** / **Export CSV** to take results out,
   and the filter box / sortable columns to dig through them.

Port 443 is probed over TLS (self-signed certs accepted); every other port over
plain HTTP. "Fetch page titles & server headers" adds one short HTTP GET per
open host — uncheck it for pure TCP-connect speed.

## Command-line flags

```
-addr string   listen address for the web UI (default "127.0.0.1:8899")
-open          open the browser automatically (default true)
```

Use `-addr 0.0.0.0:8899` to reach the UI from other devices on your LAN.

## HTTP API (for scripting)

- `POST /api/scan` — JSON body:
  `{ "target": "5.218.21.x", "ports": [80, 443], "start": 0, "end": 255,
     "timeoutMs": 800, "concurrency": 1000, "grabBanner": true }`
- `GET /api/stream` — live SSE event stream (`start`, `result`, `progress`, `done`);
  reconnect replays the current job's history
- `POST /api/stop` — stop the running scan

## Notes

- Defaults: 800 ms connect timeout, 1000 concurrent probes (max 5000). The
  file-descriptor limit is raised automatically on macOS/Linux.
- Scans are capped at 1,048,576 hosts per job.
- Only scan networks you own or are explicitly authorized to test.
# PortScope
