import asyncio
import json
import ssl
import struct
import tempfile
import unittest

from ja4proxy.profiles import get_default_headers
from ja4proxy.server import ProxyServer, is_ssrf_restricted


class TestLiveProxy(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.server = ProxyServer(
            host="127.0.0.1",
            port=0,
            default_profile="chrome_133",
            cert_dir=self.temp_dir,
            allow_private_networks=False,
        )
        await self.server.start()
        self.port = self.server.port

    async def asyncTearDown(self):
        await self.server.close()

    async def test_ssrf_restricted_addresses(self):
        """Validates watertight SSRF detection for IPv4, IPv6, CGNAT, and hostnames."""
        # Loopback and local addresses
        self.assertTrue(await is_ssrf_restricted("127.0.0.1"))
        self.assertTrue(await is_ssrf_restricted("127.0.0.1:8888"))
        self.assertTrue(await is_ssrf_restricted("::1"))
        self.assertTrue(await is_ssrf_restricted("[::1]:9999"))
        self.assertTrue(await is_ssrf_restricted("0.0.0.0"))
        self.assertTrue(await is_ssrf_restricted("0.0.0.0:80"))
        self.assertTrue(await is_ssrf_restricted("::ffff:127.0.0.1"))
        self.assertTrue(await is_ssrf_restricted("localhost"))
        self.assertTrue(await is_ssrf_restricted("localhost:8080"))

        # Private RFC 1918 subnets
        self.assertTrue(await is_ssrf_restricted("10.0.0.1"))
        self.assertTrue(await is_ssrf_restricted("172.16.5.10"))
        self.assertTrue(await is_ssrf_restricted("192.168.1.1"))

        # CGNAT & Cloud Metadata
        self.assertTrue(await is_ssrf_restricted("100.64.0.1"))
        self.assertTrue(await is_ssrf_restricted("169.254.169.254"))

        # Legitimate external hosts
        self.assertFalse(await is_ssrf_restricted("1.1.1.1"))
        self.assertFalse(await is_ssrf_restricted("tls.peet.ws"))

    def test_safari_ios_headers(self):
        """Validates that iOS profiles synthesize authentic iPhone mobile headers."""
        headers_18 = get_default_headers("safari_ios_18_0")
        self.assertIn("iPhone", headers_18["user-agent"])
        self.assertIn("Version/18.0", headers_18["user-agent"])

        headers_17 = get_default_headers("safari_ios_17_0")
        self.assertIn("iPhone", headers_17["user-agent"])
        self.assertIn("Version/17.0", headers_17["user-agent"])

    async def test_gateway_mode_gzip(self):
        """Tests that gzipped upstream responses are properly un-encoded to avoid client crashes."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        target_url = "https://httpbin.org/gzip"
        req = (
            f"GET /{target_url} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode("utf-8"))
        await writer.drain()

        # Read response
        status_line = await reader.readline()
        if b"502" in status_line or b"429" in status_line or b"503" in status_line:
            writer.close()
            await writer.wait_closed()
            self.skipTest(f"tls.peet.ws public service returned transient error: {status_line.decode('utf-8', errors='replace').strip()}")
        self.assertIn(b"200 OK", status_line)

        headers = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            k, v = line.decode().split(":", 1)
            headers[k.strip().lower()] = v.strip()

        # Content-Encoding must be stripped since body is decompressed
        self.assertNotIn("content-encoding", headers)

        body = await reader.read()
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data.get("gzipped"))

        writer.close()
        await writer.wait_closed()

    async def test_chunked_request_upload(self):
        """Tests uploading a chunked request payload."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        target_url = "https://httpbin.org/anything"
        req = (
            f"POST /{target_url} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Type: text/plain\r\n"
            f"Connection: close\r\n\r\n"
            f"5\r\nhello\r\n"
            f"6\r\n world\r\n"
            f"0\r\n\r\n"
        )
        writer.write(req.encode("utf-8"))
        await writer.drain()

        status_line = await reader.readline()
        if b"502" in status_line or b"429" in status_line or b"503" in status_line:
            writer.close()
            await writer.wait_closed()
            self.skipTest(f"tls.peet.ws public service returned transient error: {status_line.decode('utf-8', errors='replace').strip()}")
        self.assertIn(b"200 OK", status_line)

        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break

        body = await reader.read()
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("data"), "hello world")

        writer.close()
        await writer.wait_closed()

    async def test_ssrf_protection_blocked(self):
        """Tests that requests to private IP ranges are blocked by default."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        req = (
            f"GET /http://127.0.0.1:80/secret HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode("utf-8"))
        await writer.drain()

        status_line = await reader.readline()
        self.assertIn(b"403 Forbidden", status_line)

        writer.close()
        await writer.wait_closed()

    async def test_bad_gateway_mapping_status_502(self):
        """Tests that unresolvable upstream host returns a complete 502 response with body and headers."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        req = (
            f"GET /https://invalid-unresolvable-domain-9999.test/ HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.port}\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(req.encode("utf-8"))
        await writer.drain()

        status_line = await reader.readline()
        self.assertIn(b"502 Bad Gateway", status_line)

        headers = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            k, v = line.decode().split(":", 1)
            headers[k.strip().lower()] = v.strip()

        # Headers must be cleanly written without crash
        self.assertIn("content-length", headers)
        self.assertIn("content-type", headers)

        body = await reader.read()
        self.assertTrue(len(body) > 0)
        self.assertTrue(
            any(
                term in body.lower()
                for term in (b"lookup", b"failed", b"dial", b"host", b"bad gateway", b"resolve")
            )
        )

        writer.close()
        await writer.wait_closed()

    async def test_socks5_ingress_tls_peet(self):
        """Tests connecting to the proxy via binary SOCKS5 (RFC 1928) on the same port."""
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)

        # 1. SOCKS5 greeting: VER 5, 1 auth method (0 = No Auth)
        writer.write(b"\x05\x01\x00")
        await writer.drain()

        resp = await reader.read(2)
        self.assertEqual(resp, b"\x05\x00")

        # 2. SOCKS5 request: VER 5, CMD 1 (CONNECT), RSV 0, ATYP 3 (Domain), Domain: tls.peet.ws, Port: 443
        domain = b"tls.peet.ws"
        req = b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack("!H", 443)
        writer.write(req)
        await writer.drain()

        # 3. Read SOCKS5 reply (10 bytes)
        reply = await reader.read(10)
        self.assertEqual(reply[:2], b"\x05\x00")  # Rep 0 = Success

        # 4. Upgrade SOCKS5 stream to TLS with our proxy CA
        client_ssl = ssl.create_default_context()
        client_ssl.load_verify_locations(self.server.ca.ca_cert_path)

        loop = asyncio.get_running_loop()
        new_transport = await loop.start_tls(
            writer.transport,
            writer.transport.get_protocol(),
            client_ssl,
            server_side=False,
            server_hostname="tls.peet.ws",
        )
        writer._transport = new_transport

        # 5. Send HTTP GET over the intercepted TLS tunnel with capitalized Connection: close
        writer.write(b"GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nConnection: close\r\n\r\n")
        await writer.drain()

        status_line = await reader.readline()
        if b"502" in status_line or b"429" in status_line or b"503" in status_line:
            writer.close()
            await writer.wait_closed()
            self.skipTest(f"tls.peet.ws public service returned transient error: {status_line.decode('utf-8', errors='replace').strip()}")
        self.assertIn(b"200 OK", status_line)

        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break

        # Must close without hanging due to fixed case-insensitive Connection: close handling
        body = await reader.read()
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data.get("tls", {}).get("ja4", "").startswith("t13"))

        writer.close()
        await writer.wait_closed()

    async def test_client_proxy_authentication(self):
        """Tests that configuring proxy authentication blocks unauthorized clients with HTTP 407."""
        auth_server = ProxyServer(
            host="127.0.0.1",
            port=0,
            auth="proxyuser:secretpass",
            cert_dir=self.temp_dir,
            allow_private_networks=True,
        )
        await auth_server.start()

        try:
            # 1. Unauthorized request without credentials -> 407
            reader, writer = await asyncio.open_connection("127.0.0.1", auth_server.port)
            req = (
                f"GET /http://127.0.0.1:{auth_server.port}/test HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{auth_server.port}\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(req.encode("utf-8"))
            await writer.drain()

            status_line = await reader.readline()
            self.assertIn(b"407 Proxy Authentication Required", status_line)
            writer.close()
            await writer.wait_closed()

            # 2. Authorized request with valid credentials -> 200 / processed
            reader, writer = await asyncio.open_connection("127.0.0.1", auth_server.port)
            auth_token = "proxyuser:secretpass".encode("utf-8")
            import base64
            auth_header = base64.b64encode(auth_token).decode("utf-8")

            req_auth = (
                f"GET /https://httpbin.org/status/200 HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{auth_server.port}\r\n"
                f"Proxy-Authorization: Basic {auth_header}\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(req_auth.encode("utf-8"))
            await writer.drain()

            status_line = await reader.readline()
            self.assertIn(b"200 OK", status_line)
            writer.close()
            await writer.wait_closed()
        finally:
            await auth_server.close()

    async def test_connect_tls_handshake_timeout(self):
        """Tests that a client stalling during TLS handshake is cleanly terminated by timeout."""
        server = ProxyServer(
            host="127.0.0.1",
            port=0,
            tls_handshake_timeout=0.5,
            cert_dir=self.temp_dir,
            allow_private_networks=True,
        )
        await server.start()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
            connect_req = (
                f"CONNECT tls.peet.ws:443 HTTP/1.1\r\n"
                f"Host: tls.peet.ws:443\r\n\r\n"
            )
            writer.write(connect_req.encode("utf-8"))
            await writer.drain()

            status_line = await reader.readline()
            self.assertIn(b"200 Connection Established", status_line)
            # Drain empty line after headers
            await reader.readline()

            # Client stalls without sending ClientHello; proxy should close on handshake timeout
            data = await asyncio.wait_for(reader.read(100), timeout=2.0)
            self.assertEqual(data, b"")
            writer.close()
            await writer.wait_closed()
        finally:
            await server.close()


if __name__ == "__main__":
    unittest.main()
