# PortScope

Fast, parallel HTTP/HTTPS port scanner for IP ranges with a live web dashboard.

PortScope checks which hosts in an IP range are serving HTTP (port 80) or HTTPS (port 443), with a live web dashboard. Written in Go with the standard library only — thousands of concurrent TCP probes, results streamed to the browser in real time via Server-Sent Events.

> ⚠️ **This tool is for educational and authorized testing purposes only.**
> Only use it on networks you own or have explicit permission to test.
> Using PortScope against systems without authorization is illegal.
> See [Legal Disclaimer](#️-legal-disclaimer--سلب-مسئولیت) below.

## Features

- ⚡ Fast parallel probing — up to 5,000 concurrent workers (1,000 by default)
- 🎯 Flexible targets: wildcard octets (`5.218.21.x`, `5.218.x.x`), partial octets and CIDR notation (`10.0.0.0/24`)
- 📊 Live web dashboard: real-time results, progress and rate via SSE
- 🏷️ Optional banner grabbing: HTTP status, page title, `Server` header, TLS certificate CN
- 📤 Export results: copy IPs or download CSV
- 🔍 Filter box and sortable columns
- 🧪 Pure Go standard library — zero external dependencies
- 🖥️ Cross-platform: macOS, Linux, Windows

## Quick start

```bash
git clone https://github.com/javadalmasi/PortScope.git
cd PortScope
go build -o portscope .
./portscope
```

The web UI opens automatically at `http://127.0.0.1:8899` (pass `-open=false` to disable). Run tests with `go test ./...`.

## Usage

1. Type a target — any octet can be an `x` wildcard:
   - `5.218.21.x` — scans `5.218.21.0`–`5.218.21.255`
   - `5.218.21` — same as `5.218.21.x`
   - `5.218.x.x` — scans the whole /16 (65,536 hosts)
   - `10.0.0.0/24` — CIDR notation also works
2. Set the wildcard octet range (default 0–255), the port list (default `80, 443`), the per-probe timeout, and the concurrency.
3. Press **Start scan**. Open hosts appear live with HTTP status, page title, `Server` header, TLS certificate CN and latency. Click an IP to open it.
4. Use **Stop** to cancel, **Copy IPs** / **Export CSV** to take results out.

Port 443 is probed over TLS (self-signed certs accepted); every other port over plain HTTP. "Fetch page titles & server headers" adds one short HTTP GET per open host — uncheck it for pure TCP-connect speed.

## Command-line flags

```
-addr string   listen address for the web UI (default "127.0.0.1:8899")
-open          open the browser automatically (default true)
```

Use `-addr 0.0.0.0:8899` to reach the UI from other devices on your LAN.

## HTTP API (for scripting)

- `POST /api/scan` — JSON body:
  `{ "target": "5.218.21.x", "ports": [80, 443], "start": 0, "end": 255, "timeoutMs": 800, "concurrency": 1000, "grabBanner": true }`
- `GET /api/stream` — live SSE event stream (`start`, `result`, `progress`, `done`); reconnect replays the current job's history
- `POST /api/stop` — stop the running scan

## Notes

- Defaults: 800 ms connect timeout, 1,000 concurrent probes (max 5,000). The file-descriptor limit is raised automatically on macOS/Linux.
- Scans are capped at 1,048,576 hosts per job.

## ⚠️ Legal Disclaimer — سلب مسئولیت

**English**

PortScope is provided for **educational, research, and authorized security-testing purposes only**. It is intended to help system and network administrators and security professionals audit hosts **they own or are explicitly authorized to assess**.

By downloading, cloning, or using PortScope you agree that:

- You will only use it on networks, hosts, and systems that you own or have **explicit written permission** to test.
- You will **not** use PortScope for any **illegal, unauthorized, or malicious** activity, including unauthorized port scanning, reconnaissance, or intrusion attempts.
- You are solely responsible for complying with all applicable local, state, national, and international laws and regulations. Unauthorized access to computer systems is a crime in most jurisdictions.
- The author and contributors are **not responsible or liable** for any misuse, damage, or legal consequences resulting from the use of this software.

**فارسی**

پروژه PortScope صرفاً برای **یادگیری، پژوهش و تست‌های امنیتی مجاز** نوشته شده است و کاربرد آن **فقط روی شبکه‌ها و سیستم‌هایی مجاز است که مالک آن‌ها هستید یا اجازه کتبی صاحبان آن‌ها را دارید**.

- استفاده از این ابزار برای **موارد غیرقانونی، بدون مجوز یا مخرب مجاز نیست** و مسئولیت هرگونه استفاده نادرست به‌طور کامل بر عهده کاربر است.
- توسعه‌دهنده هیچ مسئولیتی در قبال سوءاستفاده، خسارت یا پیامدهای قانونی ناشی از استفاده از این نرم‌افزار ندارد.

## License

Released under the [MIT License](LICENSE).
