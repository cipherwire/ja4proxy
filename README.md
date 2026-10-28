<div align="center">

```text
       _       __ __                             
      (_)___ _/ // / ____  _________  _  ____  __
     / / __ `/ // /_/ __ \/ ___/ __ \| |/_/ / / /
    / / /_/ /__  __/ /_/ / /  / /_/ />  </ /_/ / 
 __/ /\__,_/  /_/ / .___/_/   \____/_/|_|\__, /  
/___/            /_/                    /____/   
```

### High-performance universal forward proxy with authentic browser TLS (JA4/JA3) and HTTP/2 framing

<p>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-2563eb" alt="Platforms">
  <img src="https://img.shields.io/badge/engine-uTLS%20%2B%20fhttp-4285F4" alt="Engine">
  <img src="https://img.shields.io/badge/protocols-HTTP%20%7C%20HTTPS%20%7C%20SOCKS5-00599C" alt="Protocols">
  <img src="https://img.shields.io/badge/fingerprint-JA4%20%2F%20JA3%20%2F%20Akamai%20H2-6366f1" alt="Fingerprint">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/status-production-22c55e" alt="Status">
</p>

</div>

---

## Table of Contents

- [The Fingerprinting Problem](#the-fingerprinting-problem)
- [How ja4proxy Works](#how-ja4proxy-works)
- [Architecture & Protocol Pipeline](#architecture--protocol-pipeline)
- [Comparative Analysis](#comparative-analysis)
- [Key Specifications](#key-specifications)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Multi-Language Client Integration](#multi-language-client-integration)
  - [Python (requests, httpx, aiohttp)](#python-requests-httpx-aiohttp)
  - [Node.js (axios, undici, fetch)](#nodejs-axios-undici-fetch)
  - [Go (net/http)](#go-nethttp)
  - [Rust (reqwest)](#rust-reqwest)
  - [Scrapy Framework](#scrapy-framework)
- [Dynamic Per-Request Directives](#dynamic-per-request-directives)
  - [Via Proxy Credentials (Tag Routing)](#via-proxy-credentials-tag-routing)
  - [Via Custom Request Headers](#via-custom-request-headers)
- [Residential Proxy Chaining](#residential-proxy-chaining)
- [Supported Browser Presets](#supported-browser-presets)
- [Production Deployment](#production-deployment)
  - [Docker & Docker Compose](#docker--docker-compose)
  - [Systemd Service Unit](#systemd-service-unit)
  - [System-Wide CA Trust Installation](#system-wide-ca-trust-installation)
- [Security & Engineering Boundaries](#security--engineering-boundaries)
- [CLI Reference](#cli-reference)
- [Automated Verification Suite](#automated-verification-suite)
- [License](#license)

---

## The Fingerprinting Problem

Modern anti-bot mitigation platforms (Cloudflare Turnstile / Bot Management, Akamai Edge Workers, Imperva, Datadome, Kasada) no longer rely solely on IP reputation. Instead, automated scrapers and bots are blocked at Layer 7 by inspecting client-side protocol artifacts during the connection handshake:

```text
Layer 7 Defense Hierarchy
├── 1. TLS ClientHello Fingerprinting (JA3 / JA4)
│      ├── Cipher suites order & availability
│      ├── Extension list & GREASE (RFC 8701) injection
│      ├── Elliptic curve groups & signature algorithms
│      └── ALPN (Application-Layer Protocol Negotiation)
├── 2. HTTP/2 Transport Fingerprinting (Akamai HTTP2 Hash)
│      ├── SETTINGS frame parameters (HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS)
│      ├── WINDOW_UPDATE increments
│      ├── Pseudo-header serialization order (:method, :authority, :scheme, :path)
│      └── Priority trees and frame dependency graphs
└── 3. Layer 7 HTTP Header Consistency
       ├── Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform
       └── User-Agent string alignment with actual cryptographic capabilities
```

Standard networking stacks (OpenSSL in Python `urllib3`, Go `crypto/tls`, Node.js `tls`) expose hard-coded, static handshakes that immediately flag requests as non-browser traffic.

### Fingerprint Breakdown: OpenSSL vs. ja4proxy (Chrome 133)

| Component | Standard Python / Node / Go | ja4proxy (Chrome 133 Profile) |
| :--- | :--- | :--- |
| **JA4 Signature** | `t13d030800_...` (Flagged as Bot) | `t13d1516h2_8daaf6152771_d8a2da3f94cd` (Identical to Chrome 133) |
| **GREASE Support** | None (RFC 8701 absent) | Fully randomized GREASE cipher and extension values |
| **HTTP Version** | Often forced to HTTP/1.1 | Native HTTP/2 (RFC 7540) with authentic browser stream frames |
| **Pseudo-Header Order** | Variable or alphabetical | `:method`, `:authority`, `:scheme`, `:path` |
| **H2 SETTINGS** | Default OpenSSL/Go parameters | `1:65536, 2:0, 4:6291456, 6:262144` matching Chromium |

---

## How ja4proxy Works

`ja4proxy` is an in-process, high-concurrency forward proxy. Rather than forwarding raw TCP sockets (which passes through your runtime's detectable OpenSSL handshake), `ja4proxy` terminates client requests locally and re-originates the upstream connection using an in-process uTLS and fhttp engine written in Go.

```text
Any Existing Client Application
(cURL / requests / Scrapy / Playwright / Node / Go / Rust)
                           │
       HTTP CONNECT / Plain HTTP / SOCKS5 binary
                           │
                           ▼
┌────────────────────────────────────────────────────────────────────────┐
│ ja4proxy Runtime (127.0.0.1:8888)                                      │
│                                                                        │
│  [Ingress Sniffer] -> Auto-detects protocol by magic byte:             │
│                       - 0x05 (SOCKS5 RFC 1928)                         │
│                       - CONNECT host:443 (HTTPS Tunnel)                │
│                       - GET / POST / http://... (HTTP Gateway)         │
│                                                                        │
│  [Directive Parser] -> Extracts profile, session, upstream proxy:      │
│                        - Via credential tags: user-profile_chrome133   │
│                        - Via custom headers: X-JA4-Profile             │
│                                                                        │
│  [SSRF Guard] -> Validates target IP against private/loopback CIDRs    │
│                                                                        │
│  [TLS Interceptor] -> Generates dynamic in-memory SAN leaf certs       │
│                                                                        │
│  [Native Zero-GIL FFI] -> Dispatches request into Go uTLS engine       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
              Outbound: Real Chrome 133 JA4 + HTTP/2 Multiplexing
                                    │
                                    ▼
                      Upstream Target (WAF / Protected Host)
```

---

## Architecture & Protocol Pipeline

### 1. Single-Port Protocol Sniffing
`ja4proxy` binds to a single port and inspects the initial byte stream using non-destructive socket inspection:
* Byte `0x05`: Dispatches to the binary SOCKS5 state machine (RFC 1928), negotiating `NO AUTH` or `USERNAME/PASSWORD` before taking target host and port.
* ASCII `CONNECT`: Intercepts HTTPS tunnels, performs an SSL handshake using dynamic per-hostname leaf certificates signed on-the-fly by the local CA, and decrypts request bytes.
* ASCII `GET / POST / HEAD`: Handles standard forward proxy requests or gateway URLs (`http://127.0.0.1:8888/https://example.com`).

### 2. Zero-GIL Native C-Shared FFI
Python manages client I/O asynchronously via `asyncio`. When dispatching outbound HTTP/TLS requests, `ja4proxy` calls into `libutls` through `ctypes`. The Python Global Interpreter Lock (GIL) is released during socket creation, cryptographic handshakes, and body streaming.

### 3. Memory Hygiene & Free Routine
Native C allocations returned by the Go runtime are wrapped in a structured memory protocol. Once response headers and body buffers are consumed in Python, `freeMemory` is explicitly invoked over the C pointer, preventing memory leaks across long-running proxy processes.

---

## Comparative Analysis

| Feature | ja4proxy | curl-impersonate | tls-client (Python) | Puppeteer / Playwright | Squid / Privoxy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Drop-in for Any Language** | Yes (via standard proxy env) | CLI / C only | Python only | Requires browser process | Yes |
| **Zero Code Changes** | Yes (`HTTP_PROXY=...`) | No (must replace curl binary) | No (rewrite to custom client) | No (heavy refactor) | Yes |
| **JA4 / JA3 Fingerprint** | Authentic Browser Preset | Authentic Browser Preset | Authentic Browser Preset | Authentic Browser | Leaks OS OpenSSL |
| **HTTP/2 SETTINGS Impersonation** | Yes | Yes | Yes | Yes | No |
| **RAM per Worker** | ~18 MB | ~15 MB | ~20 MB | ~150 - 300 MB | ~30 MB |
| **SOCKS5 Ingress** | Yes (Auto-detected) | No | No | No | Separate port |
| **Upstream Proxy Chaining** | Dynamic per-request | Static flags | Per-client | Per-browser context | Configuration file |

---

## Key Specifications

- **Listen Protocols**: HTTP Gateway, HTTP CONNECT, SOCKS5 (RFC 1928) on a single port.
- **TLS Engine**: uTLS with randomized GREASE (RFC 8701) and custom extension order permutations.
- **HTTP Engine**: fhttp with browser-matched HTTP/2 SETTINGS framing and pseudo-header ordering.
- **Certificate Authority**: 2048-bit RSA Root CA (`ca.pem`) with automatic in-memory leaf certificate generation and Subject Alternative Name (SAN) caching.
- **Security Boundary**: Pre-flight connection-time SSRF blocking for RFC 1918 private subnets, loopback, and cloud metadata (`169.254.169.254`).
- **Decompression Sync**: Automatic header reconciliation (`Content-Encoding`, `Content-Length`) to prevent client decoder desync.

---

## Installation

### Recommended: Install via PyPI

```bash
pip install ja4proxy
```

Verify your installation:

```bash
ja4proxy --help
```

### Via Docker & Docker Compose

```bash
# Clone the repository
git clone https://github.com/cipherwire/ja4proxy.git
cd ja4proxy

# Start with Docker Compose
docker compose up -d
```

### Via Source

```bash
git clone https://github.com/cipherwire/ja4proxy.git
cd ja4proxy
pip install -e .
```

---

## Quick Start

### 1. Launch the Server

Start ja4proxy with default settings (127.0.0.1:8888, chrome_133 profile):

```bash
ja4proxy start
```

Or configure custom binding, credentials, and browser impersonation:

```bash
ja4proxy start --host 0.0.0.0 --port 8888 --profile chrome_133 --auth username:password
```

Terminal Dashboard Output:

```text
      _       __ __                             
     (_)___ _/ // / ____  _________  _  ____  __
    / / __ `/ // /_/ __ \/ ___/ __ \| |/_/ / / /
   / / /_/ /__  __/ /_/ / /  / /_/ />  </ /_/ / 
__/ /\__,_/  /_/ / .___/_/   \____/_/|_|\__, /  
/___/            /_/                    /____/   
  Universal Browser TLS & JA4 Impersonation Proxy
  Version: 0.5.0  |  Docs: https://ja4proxy.cipherwire.link

========================================================================
 [*] Engine Status:   ONLINE
 [*] HTTP Ingress:    http://0.0.0.0:8888
 [*] SOCKS5 Ingress:  socks5://0.0.0.0:8888 (Auto-detect on same port)
 [*] Active Profile:  chrome_133
 [*] Upstream Proxy:  DIRECT
 [*] Authentication:  Enabled (HTTP Basic / SOCKS5)
 [*] SSRF Guard:      ENFORCED (RFC1918 & Loopback blocked)
 [*] Root CA Path:    ~/.ja4proxy/ca.pem
------------------------------------------------------------------------
 Quick Test Command:
   curl -x http://0.0.0.0:8888 https://tls.peet.ws/api/all
========================================================================
```

### 2. Configuration Options

ja4proxy can be configured via CLI flags or equivalent environment variables:

| CLI Flag | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--host` | `JA4PROXY_HOST` | `127.0.0.1` | Network interface IP to bind. Use `0.0.0.0` for all interfaces. |
| `-p`, `--port` | `JA4PROXY_PORT` | `8888` | Port to listen on (serves HTTP CONNECT, Gateway, and SOCKS5). |
| `--profile` | `JA4PROXY_PROFILE` | `chrome_133` | Default browser preset (e.g. `chrome_133`, `firefox_133`, `safari_16_0`). |
| `--auth` | `JA4PROXY_AUTH` | `None` | Optional `user:pass` authentication for clients. |
| `--upstream-proxy` | `JA4PROXY_UPSTREAM_PROXY` | `None` | Upstream proxy URL to chain (e.g. `socks5://user:pass@host:1080`). |
| `--cert-dir` | `JA4PROXY_CERT_DIR` | `~/.ja4proxy` | Directory to store generated Root CA and leaf certificates. |
| `--allow-private-networks` | `JA4PROXY_ALLOW_PRIVATE_NETWORKS` | `False` | Disable SSRF guard to allow loopback/private IP routing. |
| `-v`, `--verbose` | `JA4PROXY_VERBOSE` | `False` | Enable verbose debug logging. |

### 3. One-Click CA Trust Installation (Zero SSL Errors)

Instead of passing `--cacert` or `-k` into every client command, install the ja4proxy Root CA directly into your OS and Python `certifi` trust stores:

```bash
# Install CA into OS trust store and Python certifi
ja4proxy ca install

# To remove later
ja4proxy ca uninstall
```

Once installed, standard tools (`curl`, Python `requests`, `httpx`, Node.js) verify intercepted connections natively with zero certificate errors.

You can also inspect or export the certificate manually:

```bash
# Export root CA to a specific file
ja4proxy ca --export ./ca.pem
```

### 4. Anti-Bot Diagnostic Healthcheck (`ja4proxy doctor`)

Verify upstream TLS, HTTP/2 Akamai framing, GREASE, post-quantum ML-KEM, and TCP transport consistency in one command:

```bash
ja4proxy doctor
```

Output:

```text
========================================================================
  ja4proxy Diagnostic Healthcheck & Evasion Audit
========================================================================
 [*] TLS JA4 Signature:   t13d1516h2_8daaf6152771_d8a2da3f94cd
 [*] Post-Quantum TLS:    X25519MLKEM768 Hybrid Key Exchange (Active)
 [*] TLS GREASE Ciphers:  RFC 8701 Randomized (Active)
 [*] HTTP/2 Transport:    Akamai Hash 52d84b11737d980a... (Valid h2)
 [*] TCP/IP Hop TTL:      TTL 112 (Clean Transport)
------------------------------------------------------------------------
 Overall Anti-Bot Readiness: EXCELLENT (Cloudflare, Akamai, DataDome compatible)
========================================================================
```

### 5. Verify TLS Handshake Against tls.peet.ws

#### Using HTTP CONNECT:
```bash
curl -x http://127.0.0.1:8888 --cacert ./ca.pem https://tls.peet.ws/api/all
```

#### Using SOCKS5 (Identical Port):
```bash
curl -x socks5h://127.0.0.1:8888 --cacert ./ca.pem https://tls.peet.ws/api/all
```

#### Using Gateway Mode (No CA certificate required):
```bash
curl http://127.0.0.1:8888/https://tls.peet.ws/api/all
```

Verified output from `tls.peet.ws`:
```json
{
  "http_version": "h2",
  "tls": {
    "ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
  }
}
```

---

## Multi-Language Client Integration

### Python (requests, httpx, aiohttp)

#### `requests`
```python
import os
import requests

ca_cert = os.path.expanduser("~/.ja4proxy/ca.pem")
proxies = {
    "http": "http://127.0.0.1:8888",
    "https": "http://127.0.0.1:8888",
}

# Standard requests call immediately adopts Chrome 133 JA4 fingerprint
res = requests.get("https://tls.peet.ws/api/all", proxies=proxies, verify=ca_cert)
print("JA4:", res.json()["tls"]["ja4"])
```

#### `httpx` (Async with SOCKS5)
```python
import asyncio
import os
import httpx

async def main():
    ca_cert = os.path.expanduser("~/.ja4proxy/ca.pem")
    async with httpx.AsyncClient(
        proxy="socks5://127.0.0.1:8888",
        verify=ca_cert,
    ) as client:
        res = await client.get("https://tls.peet.ws/api/all")
        print("JA4:", res.json()["tls"]["ja4"])

asyncio.run(main())
```

---

### Node.js (axios, undici, fetch)

#### `axios`
```javascript
const axios = require('axios');
const fs = require('fs');
const https = require('https');

const ca = fs.readFileSync('./ca.pem');
const httpsAgent = new https.Agent({ ca });

axios.get('https://tls.peet.ws/api/all', {
  proxy: { host: '127.0.0.1', port: 8888 },
  httpsAgent: httpsAgent
}).then(res => {
  console.log('JA4:', res.data.tls.ja4);
});
```

#### Native Node `fetch` (with `undici`)
```javascript
import { fetch, ProxyAgent } from 'undici';
import fs from 'fs';

const client = new ProxyAgent({
  uri: 'http://127.0.0.1:8888',
  requestTls: { ca: fs.readFileSync('./ca.pem') }
});

const res = await fetch('https://tls.peet.ws/api/all', { dispatcher: client });
const json = await res.json();
console.log('JA4:', json.tls.ja4);
```

---

### Go (net/http)

```go
package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func main() {
	caCert, _ := os.ReadFile("ca.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	proxyURL, _ := url.Parse("http://127.0.0.1:8888")
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
```

---

### Rust (reqwest)

```rust
use reqwest::{Certificate, Client, Proxy};
use std::fs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert_bytes = fs::read("ca.pem")?;
    let cert = Certificate::from_pem(&cert_bytes)?;
    
    let proxy = Proxy::all("http://127.0.0.1:8888")?;
    let client = Client::builder()
        .proxy(proxy)
        .add_root_certificate(cert)
        .build()?;

    let res = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("Response: {}", res.text().await?);
    Ok(())
}
```

---

### Scrapy Framework

In your Scrapy project's `settings.py`:

```python
# Enable standard HTTP proxy middleware
DOWNLOADER_MIDDLEWARES = {
    'scrapy.downloadermiddlewares.httpproxy.HttpProxyMiddleware': 750,
}

# Route all traffic through ja4proxy with Safari 18 profile
HTTP_PROXY = "http://user-profile_safari18:nopass@127.0.0.1:8888"
REQUESTS_CA_BUNDLE = "/path/to/ca.pem"
```

---

## Dynamic Per-Request Directives

`ja4proxy` allows you to customize the browser profile, session pool, or upstream routing on a granular per-request basis without restarting the server.

### Via Proxy Credentials (Tag Routing)

Pass directives directly inside the proxy username string formatted as `tag_value`:

```text
Format:
http://[user]-profile_<profile>-session_<id>-proxy_<upstream_url>:[password]@127.0.0.1:8888
```

Examples:

1. **Switch to Safari 18**:
   ```bash
   curl -x "http://user-profile_safari18:pass@127.0.0.1:8888" --cacert ./ca.pem https://tls.peet.ws/api/all
   ```

2. **Maintain a Sticky Session Pool**:
   ```bash
   curl -x "http://user-profile_chrome133-session_worker12:pass@127.0.0.1:8888" --cacert ./ca.pem https://target.com
   ```

3. **Chain Out to an Upstream SOCKS5 Proxy**:
   ```bash
   curl -x "http://user-profile_chrome133-proxy_socks5://resuser:respass@residential.net:1080:pass@127.0.0.1:8888" --cacert ./ca.pem https://target.com
   ```

### Via Custom Request Headers

When connecting via plain HTTP gateway or custom client hooks, pass directives as standard headers:

| Header | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `X-JA4-Profile` | String | Target browser preset | `chrome_133`, `safari_16_0`, `firefox_133` |
| `X-JA4-Session` | String | Persistent session identifier | `client_worker_01` |
| `X-JA4-Upstream-Proxy` | URL | Forwarding proxy endpoint | `http://user:pass@10.0.0.1:8080` |
| `X-JA4-Timeout` | Integer | Connection timeout (seconds) | `30` |

---

## Residential Proxy Chaining

`ja4proxy` acts as a TLS and protocol transformer. You can position `ja4proxy` locally on your server or laptop, while routing the actual egress IP through your existing residential or datacenter proxy network:

```text
Client -> ja4proxy (Applies Chrome 133 JA4 + HTTP/2) -> Upstream Residential IP -> Cloudflare
```

To configure global upstream forwarding at startup:

```bash
ja4proxy start --port 8888 --upstream-proxy "http://username:password@residential-provider.com:8000"
```

Or dynamically per request:

```python
import requests

proxies = {
    # Dynamically inject residential upstream via tag syntax
    "https": "http://user-proxy_http://resuser:respass@gate.io:8000:pass@127.0.0.1:8888"
}

res = requests.get("https://api.ipify.org?format=json", proxies=proxies, verify="ca.pem")
print("Egress IP:", res.json()["ip"])
```

---

## Supported Browser Presets

Run `ja4proxy profiles` to list all supported profiles:

| Profile Identifier | Engine | Platform | Key Protocol Features |
| :--- | :--- | :--- | :--- |
| `chrome_133` (Default) | Chromium 133 | Windows / macOS | GREASE, ALPN h2, PSK, Post-Quantum Kyber key exchange |
| `chrome_131` | Chromium 131 | Windows | GREASE, ALPN h2, ChaCha20, AES-GCM |
| `chrome_124` | Chromium 124 | Windows | GREASE, ALPN h2, TLS 1.3 |
| `chrome_120` | Chromium 120 | Windows | Standard Chromium TLS 1.3 profile |
| `safari_16_0` | WebKit | macOS 13 | WebKit TLS 1.3 profile, Safari extension order & H2 framing |
| `safari_15_6_1` | WebKit | macOS 12 | WebKit TLS 1.3 legacy profile |
| `safari_ios_16_0` | WebKit iOS | iOS 16 | Mobile WebKit TLS profile |
| `firefox_133` | Gecko | Windows / Linux | Mozilla extension permutation, no GREASE, specific ALPN order |
| `firefox_132` | Gecko | Windows | Mozilla TLS 1.3 profile |
| `firefox_120` | Gecko | Linux | Standard Firefox TLS 1.3 profile |
| `opera_90` | Chromium / Opera | Windows | Opera Desktop fingerprint |
| `opera_89` | Chromium / Opera | Windows | Legacy Opera Desktop profile |

---

## Production Deployment

### Docker & Docker Compose

#### `docker-compose.yml`
```yaml
version: '3.8'

services:
  ja4proxy:
    image: ja4proxy:latest
    build:
      context: .
      dockerfile: Dockerfile
    container_name: ja4proxy
    restart: unless-stopped
    ports:
      - "8888:8888"
    volumes:
      - ja4proxy_certs:/root/.ja4proxy
    environment:
      - JA4PROXY_PORT=8888
      - JA4PROXY_PROFILE=chrome_133
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:8888/https://httpbin.org/status/200"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  ja4proxy_certs:
```

Launch with:
```bash
docker compose up -d
```

### Systemd Service Unit

Create `/etc/systemd/system/ja4proxy.service`:

```ini
[Unit]
Description=ja4proxy TLS & HTTP/2 Impersonation Proxy
After=network.target

[Service]
Type=simple
User=proxyuser
WorkingDirectory=/opt/ja4proxy
ExecStart=/usr/local/bin/ja4proxy start --host 0.0.0.0 --port 8888 --profile chrome_133
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ja4proxy
```

### System-Wide CA Trust Installation

To use `ja4proxy` transparently without passing `--cacert` or `verify=...` in your scripts:

#### Debian / Ubuntu
```bash
ja4proxy ca --export /tmp/ja4proxy-ca.crt
sudo cp /tmp/ja4proxy-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

#### macOS
```bash
ja4proxy ca --export /tmp/ja4proxy-ca.crt
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/ja4proxy-ca.crt
```

#### Windows (PowerShell Administrator)
```powershell
ja4proxy ca --export "$env:TEMP\ja4proxy-ca.crt"
certutil -addstore -f "Root" "$env:TEMP\ja4proxy-ca.crt"
```

---

## Security & Engineering Boundaries

1. **Pre-Flight SSRF Protection**:
   `ja4proxy` resolves hostnames prior to outbound dispatch and drops requests resolving to private address spaces (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), and cloud metadata (`169.254.169.254`). Internal forwarding can be enabled with `--allow-private-networks`.

2. **Decompression & Content-Length Sync**:
   The native Go engine decodes gzip/brotli/deflate responses transparently. `ja4proxy` strips stale `Content-Encoding` and `Transfer-Encoding` headers and recalculates accurate `Content-Length` before serving downstream, preventing double-decompression exceptions.

3. **Header Sanitization**:
   Incoming client hop-by-hop headers (`Proxy-Connection`, `Keep-Alive`, `Te`) and automated OpenSSL/Python identifiers are stripped. Canonical browser headers (`User-Agent`, `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`) matching the selected profile are automatically synthesized when missing.

4. **Zero-GIL Execution**:
   Native C FFI functions execute outside Python's GIL. Concurrency scales across available CPU cores and network threads without interpreter bottlenecks.

---

## CLI Reference

```text
Usage: ja4proxy [OPTIONS] COMMAND [ARGS]...

  ja4proxy: High-performance universal forward proxy server with browser TLS (JA4)
  and HTTP/2 impersonation.

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  ca        Inspects or exports the local Root CA certificate.
  profiles  Lists all supported browser profiles for TLS and HTTP/2.
  start     Starts the ja4proxy server.
  test      Performs a direct live handshake against tls.peet.ws.
```

### `ja4proxy start` Flags

| Option | Default | Description |
| :--- | :--- | :--- |
| `--host` | `127.0.0.1` | Network interface to bind |
| `--port` | `8888` | Port to listen for HTTP, HTTPS CONNECT, and SOCKS5 |
| `--profile` | `chrome_133` | Default browser profile |
| `--upstream-proxy` | None | Global upstream forwarding proxy |
| `--auth` | None | Require username:password authentication for clients |
| `--allow-private-networks` | False | Permits forwarding to private/internal IPs |
| `--ca-dir` | `~/.ja4proxy` | Custom directory for CA certificates |

---

## Automated Verification Suite

Run the full automated test suite covering CA generation, SOCKS5 state machines, chunked request decoding, SSRF guards, and live upstream verification against `tls.peet.ws` and `httpbin.org`:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

All 19 unit and live tests execute with zero warnings and zero regressions:
```text
test_ca_creation (test_certs.TestCertificateAuthority) ... ok
test_leaf_cert_generation (test_certs.TestCertificateAuthority) ... ok
test_leaf_cert_ip_address (test_certs.TestCertificateAuthority) ... ok
test_live_handshake_chrome (test_engine.TestNativeEngine) ... ok
test_live_post_httpbin (test_engine.TestNativeEngine) ... ok
test_bad_gateway_mapping_status_502 (test_live_proxy.TestLiveProxy) ... ok
test_chunked_request_upload (test_live_proxy.TestLiveProxy) ... ok
test_client_proxy_authentication (test_live_proxy.TestLiveProxy) ... ok
test_connect_tls_handshake_timeout (test_live_proxy.TestLiveProxy) ... ok
test_gateway_mode_gzip (test_live_proxy.TestLiveProxy) ... ok
test_safari_ios_headers (test_live_proxy.TestLiveProxy) ... ok
test_socks5_ingress_tls_peet (test_live_proxy.TestLiveProxy) ... ok
test_ssrf_protection_blocked (test_live_proxy.TestLiveProxy) ... ok
test_ssrf_restricted_addresses (test_live_proxy.TestLiveProxy) ... ok
test_extract_directives_from_headers (test_parser.TestParser) ... ok
test_extract_directives_priority_header_over_auth (test_parser.TestParser) ... ok
test_parse_credentials_empty (test_parser.TestParser) ... ok
test_parse_credentials_proxy_with_hyphens (test_parser.TestParser) ... ok
test_parse_credentials_tags (test_parser.TestParser) ... ok

----------------------------------------------------------------------
Ran 19 tests in 6.421s

OK
```

---

## License

[MIT](file:///D:/what%20to%20make/LICENSE) License. Designed and engineered by `cipherwire` / `hainahola`.
