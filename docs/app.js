/* ja4proxy Modern Documentation Engine & Interactive AI Copilot
   Standard: Mintlify / Stripe / Nextra Architecture
   Zero build steps. Pure vanilla JavaScript.
*/

document.addEventListener("DOMContentLoaded", () => {
  initRouter();
  initSearch();
  initGlobalCopyButtons();
});

// Comprehensive Documentation Pages Database
const DOC_PAGES = {
  introduction: {
    category: "Getting Started",
    title: "Introduction to ja4proxy",
    description: "Production-grade universal forward proxy designed to defeat Layer 7 bot detection by emulating authentic browser TLS ClientHello signatures and HTTP/2 framing.",
    content: `
      <h2>The Fingerprinting Problem</h2>
      <p>
        Modern anti-bot mitigation platforms (Cloudflare Turnstile, Akamai Edge Workers, Datadome, Kasada, and AWS WAF) inspect client-side cryptographic protocol artifacts during the connection handshake rather than relying solely on IP address reputation.
      </p>

      <div class="callout warning">
        <div class="callout-title">Bot Detection Hierarchy</div>
        Standard networking libraries (OpenSSL in Python <code>urllib3</code>, Go standard <code>crypto/tls</code>, Node.js <code>tls</code>) expose static cipher sequences and missing GREASE values that immediately reveal automated scripts.
      </div>

      <h2>How ja4proxy Solves This</h2>
      <p>
        <code>ja4proxy</code> operates as an in-process, dual-transport forward proxy. Instead of forwarding raw TCP bytes, it terminates client requests locally and re-originates the upstream connection using an in-process native Go engine (<code>bogdanfinn/tls-client</code> v1.16.0) compiled with BoringSSL and uTLS.
      </p>

      <h2>Key Technical Capabilities</h2>
      <ul>
        <li><strong>Byte-Identical JA4 / JA3 Signatures:</strong> Exact cipher suite order, elliptic curves, signature algorithms, and randomized GREASE (RFC 8701) injection.</li>
        <li><strong>Canonical HTTP/2 Frame Sequencing:</strong> Sends authentic browser <code>headerOrder</code> sequences and HTTP/2 SETTINGS frames.</li>
        <li><strong>Zero-GIL Native Execution:</strong> Releases Python Global Interpreter Lock during cryptographic operations for high concurrency.</li>
        <li><strong>Connection-Time SSRF Pinning:</strong> Prevents DNS rebinding and private network exfiltration at socket connection time.</li>
      </ul>
    `,
    toc: [
      { id: "fingerprinting-problem", text: "The Fingerprinting Problem" },
      { id: "how-ja4proxy-solves-this", text: "How ja4proxy Solves This" },
      { id: "key-technical-capabilities", text: "Key Technical Capabilities" }
    ],
    prev: null,
    next: { id: "quickstart", title: "Quickstart Guide" }
  },

  quickstart: {
    category: "Getting Started",
    title: "Quickstart Guide",
    description: "Install ja4proxy via pip and start routing browser-impersonated traffic in less than 30 seconds.",
    content: `
      <h2>1. Installation</h2>
      <p>Install the precompiled universal package directly from PyPI:</p>
      
      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">bash</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code>pip install ja4proxy</code></pre>
      </div>

      <h2>2. Start the Proxy Daemon</h2>
      <p>Launch the server listening on local port 8888 with default Chrome 133 TLS impersonation:</p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">bash</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code># Default start (127.0.0.1:8888, Chrome 133)
ja4proxy start

# Or with custom binding, profile, and credentials
ja4proxy start --host 0.0.0.0 --port 8888 --profile chrome_133 --auth username:password</code></pre>
      </div>

      <div class="callout tip">
        <div class="callout-title">Environment Variable Configuration</div>
        All CLI options can be configured via environment variables (<code>JA4PROXY_HOST</code>, <code>JA4PROXY_PORT</code>, <code>JA4PROXY_PROFILE</code>, <code>JA4PROXY_AUTH</code>), making it seamless for Docker and Systemd deployments.
      </div>

      <h2>3. Configuration Reference</h2>
      <table class="param-table">
        <thead>
          <tr>
            <th>Flag</th>
            <th>Env Variable</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="param-name">--host</td>
            <td><code>JA4PROXY_HOST</code></td>
            <td>127.0.0.1</td>
            <td>Network interface to bind. Use 0.0.0.0 for external network access.</td>
          </tr>
          <tr>
            <td class="param-name">-p, --port</td>
            <td><code>JA4PROXY_PORT</code></td>
            <td>8888</td>
            <td>Listening port for HTTP CONNECT, Gateway, and SOCKS5.</td>
          </tr>
          <tr>
            <td class="param-name">--profile</td>
            <td><code>JA4PROXY_PROFILE</code></td>
            <td>chrome_133</td>
            <td>Default browser impersonation signature preset.</td>
          </tr>
          <tr>
            <td class="param-name">--auth</td>
            <td><code>JA4PROXY_AUTH</code></td>
            <td>None</td>
            <td>Require username:password authentication for client connections.</td>
          </tr>
          <tr>
            <td class="param-name">--upstream-proxy</td>
            <td><code>JA4PROXY_UPSTREAM_PROXY</code></td>
            <td>None</td>
            <td>Upstream proxy URL to chain (e.g. socks5://user:pass@host:1080).</td>
          </tr>
        </tbody>
      </table>

      <h2>4. Route Traffic with cURL</h2>
      <p>Verify your negotiated TLS fingerprint against public inspection endpoints:</p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <div class="code-tabs">
            <button class="code-tab-btn active" data-tab-code="curl-socks">SOCKS5 Mode</button>
            <button class="code-tab-btn" data-tab-code="curl-gate">Gateway Mode</button>
            <button class="code-tab-btn" data-tab-code="curl-connect">HTTP CONNECT</button>
          </div>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre" data-block="curl-socks"><code>curl -x socks5h://127.0.0.1:8888 https://tls.peet.ws/api/all</code></pre>
        <pre class="code-pre" data-block="curl-gate" style="display:none;"><code>curl http://127.0.0.1:8888/https://tls.peet.ws/api/all</code></pre>
        <pre class="code-pre" data-block="curl-connect" style="display:none;"><code>curl -x http://127.0.0.1:8888 https://tls.peet.ws/api/all -k</code></pre>
      </div>
    `,
    toc: [
      { id: "1-installation", text: "1. Installation" },
      { id: "2-start-the-proxy-daemon", text: "2. Start the Proxy Daemon" },
      { id: "3-configuration-reference", text: "3. Configuration Reference" },
      { id: "4-route-traffic-with-curl", text: "4. Route Traffic with cURL" }
    ],
    prev: { id: "introduction", title: "Introduction" },
    next: { id: "architecture", title: "Architecture" }
  },

  architecture: {
    category: "Getting Started",
    title: "Two-Tier Native Architecture",
    description: "Deep dive into the separation of concerns between Python AsyncIO socket handling and the compiled Go uTLS engine.",
    content: `
      <h2>System Topology</h2>
      <p>
        <code>ja4proxy</code> implements a production-grade two-tier engine pattern. Python provides protocol detection and asynchronous network management, while the compiled C-shared library executes BoringSSL cryptography outside Python Global Interpreter Lock (Zero-GIL).
      </p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">ascii diagram</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code>+-----------------------------------------------------------------------------+
|               CLIENT APPLICATIONS (Requests / Scrapy / AI Agents)           |
+-----------------------------------------------------------------------------+
                                      |
         +----------------------------+---------------------------+
         | SOCKS5 Ingress (RFC 1928)  | HTTP CONNECT (CA Intercept)| Transparent Gateway
         v                            v                           v
+-----------------------------------------------------------------------------+
|                   TIER 1: PYTHON ASYNCIO INGRESS ENGINE                     |
|                                                                             |
|  * Async SSRF Guard with 120s TTL Singleflight DNS Cache                    |
|  * Thread-Pool Offloaded RSA Leaf Generation (0.00ms Event Loop Stall)      |
|  * Client Auth Engine (RFC 1928 0x02 user/pass + HTTP 407 Basic challenge)  |
|  * 10.0s Stalled TLS Handshake Timeout Guard + 15.0s Keep-Alive Idle Guard  |
+-----------------------------------------------------------------------------+
                                      |
                     [ Zero-GIL Ctypes Pointer Bridge ]
                                      |
+-----------------------------------------------------------------------------+
|         TIER 2: BOGDANFINN TLS-CLIENT v1.16.0 NATIVE ENGINE (Go/C)          |
|                                                                             |
|  * BoringSSL / uTLS Raw ClientHello Generation (JA4 Byte-Identical Match)   |
|  * Canonical Browser Header Order Serialization (headerOrder frame mapping) |
|  * Strict C-Heap Memory Hygiene (FreeMemory Calls Prevent Memory Leaks)     |
+-----------------------------------------------------------------------------+</code></pre>
      </div>

      <h2>Wire Contract Payload</h2>
      <p>Every inbound request is converted into an in-memory JSON contract passed directly across the Ctypes boundary:</p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">json - native payload schema</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code>{
  "sessionId": "tmp_a8f9c1b4",
  "tlsClientIdentifier": "chrome_133",
  "requestUrl": "https://target.com/api",
  "requestMethod": "GET",
  "requestHeaders": {
    "host": "target.com",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
  },
  "headerOrder": [
    "host",
    "connection",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "accept"
  ],
  "timeoutSeconds": 30,
  "followRedirects": false
}</code></pre>
      </div>
    `,
    toc: [
      { id: "system-topology", text: "System Topology" },
      { id: "wire-contract-payload", text: "Wire Contract Payload" }
    ],
    prev: { id: "quickstart", title: "Quickstart Guide" },
    next: { id: "socks5", title: "SOCKS5 Ingress" }
  },

  socks5: {
    category: "Ingress Protocols",
    title: "SOCKS5 Proxy (RFC 1928)",
    description: "Binary SOCKS5 protocol support with remote DNS resolution, client authentication, and per-request directive routing.",
    content: `
      <h2>Protocol Overview</h2>
      <p>
        The proxy natively handles RFC 1928 binary SOCKS5 handshakes on the same listening port as HTTP traffic. When the first byte of an incoming TCP connection is <code>0x05</code>, the server transitions into the SOCKS5 state machine.
      </p>

      <h2>Remote DNS Resolution (socks5h)</h2>
      <p>
        Always use the <code>socks5h://</code> scheme instead of <code>socks5://</code> in tools like cURL. This instructs the client to delegate hostname resolution to <code>ja4proxy</code>, ensuring that destination hostnames pass through the proxy SSRF guard and DNS pinning cache.
      </p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">bash</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code># Remote DNS resolution delegates target lookup to ja4proxy
curl -x socks5h://127.0.0.1:8888 https://tls.peet.ws/api/all</code></pre>
      </div>

      <h2>Authentication Handshake (Method 0x02)</h2>
      <p>
        When configured with <code>--auth username:password</code>, the server advertises method <code>0x02</code> (Username/Password authentication) and rejects unauthorized clients with method <code>0xFF</code> (No acceptable methods).
      </p>
    `,
    toc: [
      { id: "protocol-overview", text: "Protocol Overview" },
      { id: "remote-dns-resolution-socks5h", text: "Remote DNS Resolution (socks5h)" },
      { id: "authentication-handshake-method-0x02", text: "Authentication Handshake" }
    ],
    prev: { id: "architecture", title: "Architecture" },
    next: { id: "http-connect", title: "HTTP CONNECT Tunnel" }
  },

  "http-connect": {
    category: "Ingress Protocols",
    title: "HTTP CONNECT Tunneling",
    description: "Dynamic TLS interception with local Root CA signing and asynchronous thread-pool leaf certificate caching.",
    content: `
      <h2>How CONNECT Works</h2>
      <p>
        Standard HTTP forward proxy clients initiate TLS connections by issuing an <code>HTTP CONNECT host:443 HTTP/1.1</code> request. <code>ja4proxy</code> responds with <code>HTTP/1.1 200 Connection Established</code> and performs an in-process TLS server handshake using a dynamically generated certificate for the requested hostname.
      </p>

      <h2>Non-Blocking Leaf Certificate Generation</h2>
      <p>
        Generating 2048-bit RSA keys blocks synchronous CPU cycles for 50-100ms. In <code>ja4proxy</code>, leaf key generation is offloaded to the thread pool executor (<code>get_ssl_context_for_host_async</code>) before acknowledging the client, keeping the AsyncIO event loop stall at <strong>0.00ms</strong>.
      </p>

      <div class="callout note">
        <div class="callout-title">Cache Bounding</div>
        Generated SSL contexts are cached in an LRU memory table bounded at 1000 contexts to prevent memory bloat over extended proxy lifespans.
      </div>
    `,
    toc: [
      { id: "how-connect-works", text: "How CONNECT Works" },
      { id: "non-blocking-leaf-certificate-generation", text: "Non-Blocking Leaf Generation" }
    ],
    prev: { id: "socks5", title: "SOCKS5 Ingress" },
    next: { id: "gateway", title: "Transparent Gateway" }
  },

  gateway: {
    category: "Ingress Protocols",
    title: "Transparent Gateway Mode",
    description: "Direct request proxying without requiring local certificate installation or HTTPS interception trust.",
    content: `
      <h2>Direct Gateway Routing</h2>
      <p>
        If your environment cannot install custom CA root certificates, <code>ja4proxy</code> supports plain HTTP gateway forwarding. Simply prepend the proxy address to the target URL:
      </p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">bash</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code># Plain HTTP gateway request (no CA cert required on client)
curl http://127.0.0.1:8888/https://tls.peet.ws/api/all</code></pre>
      </div>

      <h2>Automatic Decompression Sync</h2>
      <p>
        Upstream responses encoded with <code>gzip</code>, <code>brotli</code>, or <code>deflate</code> are decompressed in native memory by the Go engine. <code>ja4proxy</code> automatically strips obsolete <code>Content-Encoding</code> headers and synchronizes <code>Content-Length</code> before serving downstream to prevent client parser crashes.
      </p>
    `,
    toc: [
      { id: "direct-gateway-routing", text: "Direct Gateway Routing" },
      { id: "automatic-decompression-sync", text: "Automatic Decompression Sync" }
    ],
    prev: { id: "http-connect", title: "HTTP CONNECT Tunnel" },
    next: { id: "directives", title: "Proxy Directives & Tagging" }
  },

  directives: {
    category: "Proxy Directives",
    title: "Dynamic Per-Request Directives",
    description: "Route and customize browser fingerprints per request using credential tags or HTTP headers.",
    content: `
      <h2>Tag-Based Routing Syntax</h2>
      <p>
        Configure browser profiles, sticky sessions, timeouts, and upstream proxies on a per-request basis without modifying proxy daemon configuration. Tags are appended directly to the proxy username:
      </p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">credential syntax</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code>username-profile_{id}-session_{tag}-proxy_{url}-timeout_{sec}:password</code></pre>
      </div>

      <table class="param-table">
        <thead>
          <tr>
            <th>Tag Component</th>
            <th>Example</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="param-name">profile_{id}</td>
            <td class="param-type">profile_firefox133</td>
            <td>Switches the browser TLS signature and header order.</td>
          </tr>
          <tr>
            <td class="param-name">session_{tag}</td>
            <td class="param-type">session_worker12</td>
            <td>Maintains sticky cookies, HTTP/2 connection pooling, and state.</td>
          </tr>
          <tr>
            <td class="param-name">proxy_{url}</td>
            <td class="param-type">proxy_http_gate.io_8000</td>
            <td>Chains through an upstream residential or datacenter proxy.</td>
          </tr>
          <tr>
            <td class="param-name">timeout_{sec}</td>
            <td class="param-type">timeout_45</td>
            <td>Overrides request timeout in seconds.</td>
          </tr>
        </tbody>
      </table>

      <h2>Equivalent HTTP Headers</h2>
      <p>When sending plain HTTP or CONNECT requests, directives can also be supplied via headers:</p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">http headers</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code>x-ja4-profile: firefox_133
x-ja4-session: worker_01
x-ja4-timeout: 30
x-ja4-proxy: http://resuser:respass@res-gate.io:8000</code></pre>
      </div>
    `,
    toc: [
      { id: "tag-based-routing-syntax", text: "Tag-Based Routing Syntax" },
      { id: "equivalent-http-headers", text: "Equivalent HTTP Headers" }
    ],
    prev: { id: "gateway", title: "Transparent Gateway" },
    next: { id: "profiles", title: "Supported Profiles" }
  },

  profiles: {
    category: "Signature Engine",
    title: "Supported Browser Profiles",
    description: "Catalog of pre-configured browser signatures verified against native engine v1.16.0.",
    content: `
      <h2>Profile Registry</h2>
      <p>
        The table below lists verified profiles in the native engine registry. Unknown profiles fall back to the engine default to prevent silent crashes:
      </p>

      <table class="param-table">
        <thead>
          <tr>
            <th>Profile</th>
            <th>Platform</th>
            <th>Published JA4</th>
            <th>HTTP/2 ALPN</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="param-name">chrome_133 (Default)</td>
            <td>Windows 10 / 11</td>
            <td class="param-type">t13d1516h2_8daaf6152771_d8a2da3f94cd</td>
            <td>h2, http/1.1</td>
          </tr>
          <tr>
            <td class="param-name">chrome_131</td>
            <td>Windows 10 / 11</td>
            <td class="param-type">t13d1516h2_8daaf6152771_d8a2da3f94cd</td>
            <td>h2, http/1.1</td>
          </tr>
          <tr>
            <td class="param-name">firefox_133</td>
            <td>Windows 10 / 11</td>
            <td class="param-type">t13d190900_2b7376ec483d_454d193d56eb</td>
            <td>h2, http/1.1</td>
          </tr>
          <tr>
            <td class="param-name">safari_16_0</td>
            <td>macOS Monterey</td>
            <td class="param-type">t13d1715h2_4987e56a7d25_214f4e756c7d</td>
            <td>h2, http/1.1</td>
          </tr>
          <tr>
            <td class="param-name">safari_ios_18_0</td>
            <td>Apple iPhone iOS 18.0</td>
            <td class="param-type">t13d1815h2_9e2f47385901_299a9dc2e811</td>
            <td>h2, http/1.1</td>
          </tr>
          <tr>
            <td class="param-name">okhttp4_android_13</td>
            <td>Android 13 Mobile</td>
            <td class="param-type">t13d0806h2_3b5074b1b95f_25d08b3e811a</td>
            <td>h2, http/1.1</td>
          </tr>
        </tbody>
      </table>
    `,
    toc: [
      { id: "profile-registry", text: "Profile Registry" }
    ],
    prev: { id: "directives", title: "Proxy Directives & Tagging" },
    next: { id: "python-httpx", title: "Python (HTTPX)" }
  },

  "python-httpx": {
    category: "Client Integrations",
    title: "Python Integration (HTTPX)",
    description: "Asynchronous Python HTTP client integration with connection pooling and per-request profile tags.",
    content: `
      <h2>HTTPX Async Example</h2>
      <p>Route async requests through ja4proxy with custom profile tagging:</p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">python</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code>import asyncio
import httpx

async def main():
    # Route through SOCKS5 with Firefox 133 fingerprint and session 'worker1'
    proxy_url = "socks5://scraper-profile_firefox133-session_worker1:pass@127.0.0.1:8888"

    async with httpx.AsyncClient(proxies={"all://": proxy_url}, verify=False) as client:
        response = await client.get("https://tls.peet.ws/api/all")
        data = response.json()
        print("Status Code:", response.status_code)
        print("Negotiated JA4:", data.get("tls", {}).get("ja4"))

if __name__ == "__main__":
    asyncio.run(main())</code></pre>
      </div>
    `,
    toc: [
      { id: "httpx-async-example", text: "HTTPX Async Example" }
    ],
    prev: { id: "profiles", title: "Supported Profiles" },
    next: { id: "python-requests", title: "Python (Requests)" }
  },

  "python-requests": {
    category: "Client Integrations",
    title: "Python Integration (Requests)",
    description: "Synchronous integration using the standard requests library.",
    content: `
      <h2>Requests Sync Example</h2>
      <p>Configure HTTP proxy routing with custom headers:</p>

      <div class="code-block-wrapper">
        <div class="code-header">
          <span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-dim);">python</span>
          <button class="copy-code-btn">COPY</button>
        </div>
        <pre class="code-pre"><code>import requests

proxies = {
    "http": "http://127.0.0.1:8888",
    "https": "http://127.0.0.1:8888",
}

headers = {
    "x-ja4-profile": "safari_16_0",
    "x-ja4-session": "bot_session_42"
}

resp = requests.get("https://tls.peet.ws/api/all", proxies=proxies, headers=headers, verify=False)
print("Negotiated JA4:", resp.json().get("tls", {}).get("ja4"))</code></pre>
      </div>
    `,
    toc: [
      { id: "requests-sync-example", text: "Requests Sync Example" }
    ],
    prev: { id: "python-httpx", title: "Python (HTTPX)" },
    next: { id: "cli", title: "CLI Reference" }
  },

  cli: {
    category: "Reference",
    title: "Command-Line Interface (CLI)",
    description: "Complete command and option reference for the ja4proxy executable.",
    content: `
      <h2>Commands Overview</h2>
      <table class="param-table">
        <thead>
          <tr>
            <th>Command</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="param-name">ja4proxy start</td>
            <td>Launches the forward proxy server.</td>
          </tr>
          <tr>
            <td class="param-name">ja4proxy doctor</td>
            <td>Runs a 5-layer anti-bot evasion diagnostic against tls.peet.ws.</td>
          </tr>
          <tr>
            <td class="param-name">ja4proxy ca</td>
            <td>Inspects, exports, or installs the Root CA into OS and Python certifi stores.</td>
          </tr>
          <tr>
            <td class="param-name">ja4proxy profiles</td>
            <td>Lists all supported browser profiles.</td>
          </tr>
          <tr>
            <td class="param-name">ja4proxy test</td>
            <td>Performs a live handshake test against tls.peet.ws.</td>
          </tr>
        </tbody>
      </table>

      <h2>Flags for 'ja4proxy start'</h2>
      <table class="param-table">
        <thead>
          <tr>
            <th>Flag</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="param-name">--port, -p</td>
            <td class="param-type">8888</td>
            <td>Port to listen for HTTP and SOCKS5 connections.</td>
          </tr>
          <tr>
            <td class="param-name">--profile</td>
            <td class="param-type">chrome_133</td>
            <td>Default browser impersonation profile.</td>
          </tr>
          <tr>
            <td class="param-name">--auth</td>
            <td class="param-type">None</td>
            <td>Require username:password authentication from clients.</td>
          </tr>
          <tr>
            <td class="param-name">--upstream-proxy</td>
            <td class="param-type">None</td>
            <td>Default upstream proxy URL for chained routing.</td>
          </tr>
          <tr>
            <td class="param-name">--allow-private-networks</td>
            <td class="param-type">False</td>
            <td>Permits forwarding to loopback and private IP addresses.</td>
          </tr>
        </tbody>
      </table>
    `,
    toc: [
      { id: "commands-overview", text: "Commands Overview" },
      { id: "flags-for-ja4proxy-start", text: "Flags for 'ja4proxy start'" }
    ],
    prev: { id: "python-requests", title: "Python (Requests)" },
    next: { id: "security", title: "Security & Guardrails" }
  },

  security: {
    category: "Reference",
    title: "Security & Guardrails",
    description: "Watertight SSRF defenses, client authentication rules, and resource bounds.",
    content: `
      <h2>Connection-Time SSRF Pinning</h2>
      <p>
        To prevent TOCTOU DNS rebinding vulnerabilities, <code>ja4proxy</code> inspects target IP addresses before socket creation. Requests targeting private address spaces are dropped immediately:
      </p>

      <ul>
        <li><strong>Loopback:</strong> <code>127.0.0.0/8</code>, <code>::1</code>, <code>[::1]</code></li>
        <li><strong>RFC 1918 Private:</strong> <code>10.0.0.0/8</code>, <code>172.16.0.0/12</code>, <code>192.168.0.0/16</code></li>
        <li><strong>Carrier-Grade NAT:</strong> <code>100.64.0.0/10</code> (RFC 6598)</li>
        <li><strong>IPv6-Mapped IPv4:</strong> <code>::ffff:127.0.0.1</code></li>
        <li><strong>Host Default:</strong> <code>0.0.0.0/8</code></li>
      </ul>

      <h2>Stalled Handshake Protection</h2>
      <p>
        A 10.0s timeout is enforced on client TLS handshakes (<code>loop.start_tls</code>). If a client initiates CONNECT or SOCKS5 and stalls without transmitting the ClientHello, the socket is cleanly terminated to prevent resource starvation.
      </p>
    `,
    toc: [
      { id: "connection-time-ssrf-pinning", text: "Connection-Time SSRF Pinning" },
      { id: "stalled-handshake-protection", text: "Stalled Handshake Protection" }
    ],
    prev: { id: "cli", title: "CLI Reference" },
    next: null
  }
};

// 1. Client-Side Router
function initRouter() {
  function renderPage(pageId) {
    const page = DOC_PAGES[pageId] || DOC_PAGES["introduction"];
    const canvas = document.getElementById("main-canvas");
    if (!canvas) return;

    // 1. Update Breadcrumbs
    const bcCat = document.getElementById("bc-category");
    const bcPage = document.getElementById("bc-page");
    if (bcCat) bcCat.innerText = page.category;
    if (bcPage) bcPage.innerText = page.title;

    // 2. Update Page Header
    const titleEl = document.getElementById("page-title");
    const descEl = document.getElementById("page-desc");
    if (titleEl) titleEl.innerText = page.title;
    if (descEl) descEl.innerText = page.description;

    // 3. Render Markdown Body
    const bodyEl = document.getElementById("page-body");
    if (bodyEl) bodyEl.innerHTML = page.content;

    // 4. Update Pagination
    const paginEl = document.getElementById("page-pagination");
    if (paginEl) {
      let html = "";
      if (page.prev) {
        html += `
          <a href="#${page.prev.id}" class="pagination-card">
            <span class="pagination-dir">Previous</span>
            <span class="pagination-title">&larr; ${page.prev.title}</span>
          </a>
        `;
      } else {
        html += `<div></div>`;
      }

      if (page.next) {
        html += `
          <a href="#${page.next.id}" class="pagination-card" style="text-align:right;">
            <span class="pagination-dir">Next</span>
            <span class="pagination-title">${page.next.title} &rarr;</span>
          </a>
        `;
      }
      paginEl.innerHTML = html;
    }

    // 5. Update Right TOC
    const tocEl = document.getElementById("toc-list");
    if (tocEl) {
      tocEl.innerHTML = "";
      page.toc.forEach((item) => {
        const li = document.createElement("li");
        li.className = "toc-item";
        li.innerHTML = `<a href="#${item.id}" class="toc-link">${item.text}</a>`;
        tocEl.appendChild(li);
      });
    }

    // 6. Update Sidebar Active State
    document.querySelectorAll(".nav-item-link").forEach((link) => {
      if (link.getAttribute("data-page") === pageId) {
        link.classList.add("active");
      } else {
        link.classList.remove("active");
      }
    });

    // 7. Rebind Interactive Elements
    initPageInteractivity();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  // Handle URL hash changes
  function onHashChange() {
    const raw = window.location.hash.replace("#", "").trim();
    if (DOC_PAGES[raw]) {
      renderPage(raw);
    } else {
      // Check if it's an anchor on the current page
      const el = document.getElementById(raw);
      if (el) {
        el.scrollIntoView({ behavior: "smooth" });
      } else {
        renderPage("introduction");
      }
    }
  }

  window.addEventListener("hashchange", onHashChange);

  // Bind Sidebar links
  document.querySelectorAll(".nav-item-link").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const targetPage = link.getAttribute("data-page");
      window.location.hash = targetPage;
    });
  });

  // Initial load
  onHashChange();
}

// 2. Interactive Code Blocks & Tabs inside Pages
function initPageInteractivity() {
  document.querySelectorAll(".code-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const parent = btn.closest(".code-block-wrapper");
      const targetBlock = btn.getAttribute("data-tab-code");

      parent.querySelectorAll(".code-tab-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      parent.querySelectorAll(".code-pre").forEach((pre) => {
        if (pre.getAttribute("data-block") === targetBlock) {
          pre.style.display = "";
        } else {
          pre.style.display = "none";
        }
      });
    });
  });

  initGlobalCopyButtons();
}

// 3. Global Copy Buttons
function initGlobalCopyButtons() {
  document.querySelectorAll(".copy-code-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const wrapper = btn.closest(".code-block-wrapper");
      let visibleCode = wrapper ? wrapper.querySelector(".code-pre:not([style*='display: none']) code, .code-pre:not([style*='display: none'])") : null;
      if (!visibleCode && wrapper) visibleCode = wrapper.querySelector("code");

      const text = visibleCode ? visibleCode.innerText.trim() : "";
      if (text) {
        navigator.clipboard.writeText(text).then(() => {
          const original = btn.innerText;
          btn.innerText = "COPIED";
          btn.classList.add("copied");
          setTimeout(() => {
            btn.innerText = original;
            btn.classList.remove("copied");
          }, 2000);
        });
      }
    });
  });
}

// 4. Global Spotlight Search (Ctrl+K / Cmd+K)
function initSearch() {
  const modal = document.getElementById("spotlight-modal");
  const input = document.getElementById("spotlight-input");
  const results = document.getElementById("spotlight-results");
  const trigger = document.getElementById("header-search-trigger");

  if (!modal || !input || !results) return;

  function open() {
    modal.classList.add("open");
    input.value = "";
    filter("");
    input.focus();
  }

  function close() {
    modal.classList.remove("open");
  }

  function filter(q) {
    results.innerHTML = "";
    const list = Object.keys(DOC_PAGES).map((key) => ({
      id: key,
      title: DOC_PAGES[key].title,
      cat: DOC_PAGES[key].category
    }));

    const matches = list.filter((item) =>
      !q || item.title.toLowerCase().includes(q) || item.cat.toLowerCase().includes(q)
    );

    if (matches.length === 0) {
      results.innerHTML = `<div style="padding:1rem;color:var(--text-dim);font-size:0.85rem;">No matching documentation topics found.</div>`;
      return;
    }

    matches.forEach((item) => {
      const el = document.createElement("div");
      el.className = "spotlight-item";
      el.innerHTML = `<span class="spotlight-item-title">${item.title}</span><span class="spotlight-item-category">${item.cat}</span>`;
      el.addEventListener("click", () => {
        close();
        window.location.hash = item.id;
      });
      results.appendChild(el);
    });
  }

  if (trigger) trigger.addEventListener("click", open);

  input.addEventListener("input", (e) => filter(e.target.value.toLowerCase().trim()));

  modal.addEventListener("click", (e) => {
    if (e.target === modal) close();
  });

  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      open();
    } else if (e.key === "Escape" && modal.classList.contains("open")) {
      close();
    }
  });
}


