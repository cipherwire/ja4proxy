import asyncio
import base64
import http.client
import ipaddress
import logging
import socket
import ssl
import struct
import time
import urllib.parse
from typing import Any

from ja4proxy.certs import CertificateAuthority
from ja4proxy.engine.bridge import NativeEngine
from ja4proxy.parser import (
    Directive,
    extract_base_username,
    extract_directives,
    parse_credentials,
)

logger = logging.getLogger("ja4proxy")

DEFAULT_IDLE_TIMEOUT: float = 15.0
DEFAULT_TLS_HANDSHAKE_TIMEOUT: float = 10.0
_DNS_CACHE_TTL: float = 120.0
_DNS_CACHE: dict[str, tuple[bool, float]] = {}
_DNS_LOCKS: dict[str, asyncio.Lock] = {}

EXTRA_RESTRICTED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT (RFC 6598)
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking (RFC 2544)
]


def extract_host_port(authority: str, default_port: int = 80) -> tuple[str, int]:
    """Parses host and port correctly handling bracketed IPv6 and raw hosts."""
    h = authority.strip()
    if h.startswith("["):
        end = h.find("]")
        if end != -1:
            clean_host = h[1:end]
            rest = h[end + 1 :]
            port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
            return clean_host, port
    if ":" in h:
        parts = h.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0], int(parts[1])
    return h, default_port


def is_ip_restricted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks if an IP belongs to private, loopback, link-local, multicast, or reserved ranges."""
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    if any(ip in net for net in EXTRA_RESTRICTED_NETWORKS):
        return True

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_ip_restricted(ip.ipv4_mapped)

    return False


async def is_ssrf_restricted(
    host: str, loop: asyncio.AbstractEventLoop | None = None
) -> bool:
    """
    Watertight non-blocking SSRF inspection with singleflight in-flight deduplication.
    Validates bare IPv4, bracketed IPv6, bare IPv6, localhost hostnames,
    and asynchronously resolves domain names via the event loop threadpool
    with an in-memory TTL cache to prevent connection latency stalls.
    """
    clean_host, _ = extract_host_port(host)
    clean_lower = clean_host.lower()

    if (
        clean_lower in ("localhost", "localhost.localdomain")
        or clean_lower.endswith(".localhost")
        or clean_lower.endswith(".local")
        or clean_lower.endswith(".internal")
    ):
        return True

    # 1. Test if target is already an IP address
    try:
        ip = ipaddress.ip_address(clean_lower)
        return is_ip_restricted(ip)
    except ValueError:
        pass

    now = time.monotonic()
    if clean_lower in _DNS_CACHE:
        is_restricted, expiry = _DNS_CACHE[clean_lower]
        if now < expiry:
            return is_restricted

    # Singleflight in-flight deduplication
    if clean_lower not in _DNS_LOCKS:
        _DNS_LOCKS[clean_lower] = asyncio.Lock()
    lock = _DNS_LOCKS[clean_lower]

    async with lock:
        now = time.monotonic()
        if clean_lower in _DNS_CACHE:
            is_restricted, expiry = _DNS_CACHE[clean_lower]
            if now < expiry:
                return is_restricted

        ev_loop = loop or asyncio.get_running_loop()
        try:
            addr_infos = await ev_loop.getaddrinfo(clean_host, None)
            is_restricted = False
            for addr_info in addr_infos:
                resolved_ip_str = addr_info[4][0]
                try:
                    resolved_ip = ipaddress.ip_address(resolved_ip_str)
                    if is_ip_restricted(resolved_ip):
                        is_restricted = True
                        break
                except ValueError:
                    pass

            if len(_DNS_CACHE) >= 5000:
                oldest = next(iter(_DNS_CACHE))
                del _DNS_CACHE[oldest]

            _DNS_CACHE[clean_lower] = (is_restricted, now + _DNS_CACHE_TTL)
            return is_restricted
        except (socket.gaierror, OSError):
            pass

    return False


class ProxyServer:
    """
    High-performance universal proxy server.
    Auto-detects on a single port:
    1. HTTP CONNECT tunnels (intercepts HTTPS with dynamic local leaf certificates)
    2. Transparent HTTP Gateway requests (forwards upstream via uTLS without needing certificates)
    3. Binary SOCKS5 connections (RFC 1928, supporting domain resolution & proxy auth directives)
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8888,
        default_profile: str = "chrome_133",
        cert_dir: str | None = None,
        allow_private_networks: bool = False,
        upstream_proxy: str | None = None,
        auth: str | None = None,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
        tls_handshake_timeout: float = DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    ):
        self.host = host
        self.port = port
        self.default_profile = default_profile
        self.allow_private_networks = allow_private_networks
        self.upstream_proxy = upstream_proxy
        self.auth = auth
        if auth:
            if ":" in auth:
                self.auth_user, self.auth_pass = auth.split(":", 1)
            else:
                self.auth_user, self.auth_pass = auth, ""
        else:
            self.auth_user, self.auth_pass = None, None

        self.idle_timeout = idle_timeout
        self.tls_handshake_timeout = tls_handshake_timeout
        self.ca = CertificateAuthority(cert_dir)
        self.engine = NativeEngine.get_instance()
        self._server: asyncio.Server | None = None
        self._closing = False
        self._active_tasks: set[asyncio.Task] = set()
        self._pending_session_tasks: set[asyncio.Task] = set()

    def _check_auth(self, username: str, password: str) -> bool:
        """Validates credentials against configured auth requirements."""
        if not self.auth:
            return True
        base_user = extract_base_username(username)
        return base_user == self.auth_user and password == self.auth_pass

    async def start(self) -> None:
        """Starts the proxy server listening for connections."""
        self._server = await asyncio.start_server(
            self._handle_client_wrapper, self.host, self.port
        )
        if self._server and self._server.sockets:
            self.port = self._server.sockets[0].getsockname()[1]
        logger.info(
            f"ja4proxy server listening on {self.host}:{self.port} (default profile: {self.default_profile})"
        )

    async def serve_forever(self) -> None:
        """Starts the server and serves indefinitely."""
        await self.start()
        if self._server:
            async with self._server:
                await self._server.serve_forever()

    async def close(self) -> None:
        """Stops the proxy server and cancels active connection tasks."""
        self._closing = True
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for task in list(self._active_tasks):
            if not task.done():
                task.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
        if self._pending_session_tasks:
            await asyncio.gather(*self._pending_session_tasks, return_exceptions=True)

    def _handle_client_wrapper(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Auto-detects SOCKS5 vs HTTP/CONNECT on the first incoming byte."""
        try:
            first_byte = await reader.read(1)
            if not first_byte:
                writer.close()
                return

            if first_byte == b"\x05":
                # SOCKS5 protocol
                await self._handle_socks5(reader, writer)
            else:
                # HTTP / CONNECT protocol
                rest_of_line = await reader.readline()
                req_line = (first_byte + rest_of_line).decode(
                    "utf-8", errors="replace"
                ).strip()
                parts = req_line.split(" ")
                if len(parts) < 2:
                    writer.close()
                    return

                method = parts[0].upper()
                target_uri = parts[1]

                if method == "CONNECT":
                    await self._handle_connect(reader, writer, target_uri)
                else:
                    await self._handle_plain_http(
                        reader, writer, method, target_uri
                    )
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug(f"Client connection error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_headers_and_body(
        self, reader: asyncio.StreamReader
    ) -> tuple[dict[str, str], bytes]:
        """Reads HTTP headers and handles both Content-Length and chunked bodies."""
        headers: dict[str, str] = {}
        while True:
            header_line = await reader.readline()
            if not header_line or header_line in (b"\r\n", b"\n"):
                break
            decoded = header_line.decode("utf-8", errors="replace").strip()
            if ":" in decoded:
                key, val = decoded.split(":", 1)
                headers[key.strip()] = val.strip()

        body = b""
        lower_headers = {k.lower(): v for k, v in headers.items()}

        # Handle Transfer-Encoding: chunked
        if lower_headers.get("transfer-encoding", "").lower() == "chunked":
            chunks = []
            while True:
                size_line = await reader.readline()
                if not size_line:
                    break
                size_str = size_line.strip().split(b";")[0]
                if not size_str:
                    continue
                try:
                    chunk_size = int(size_str, 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    await reader.readline()  # Terminal CRLF
                    break
                chunk_data = await reader.readexactly(chunk_size)
                chunks.append(chunk_data)
                await reader.readline()  # Trailing CRLF after chunk data
            body = b"".join(chunks)
        elif "content-length" in lower_headers:
            try:
                content_len = int(lower_headers["content-length"])
                if content_len > 0:
                    body = await reader.readexactly(content_len)
            except (ValueError, asyncio.IncompleteReadError):
                pass

        return headers, body

    async def _handle_socks5(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handles binary SOCKS5 negotiation (RFC 1928) with directive extraction and authentication."""
        # 1. Read authentication methods
        nmethods_byte = await reader.read(1)
        if not nmethods_byte:
            return
        nmethods = nmethods_byte[0]
        methods = await reader.read(nmethods)

        directive = Directive()
        if self.auth:
            if b"\x02" not in methods:
                writer.write(b"\x05\xFF")  # No acceptable authentication methods
                await writer.drain()
                return

            writer.write(b"\x05\x02")  # Require username/password
            await writer.drain()

            ver = await reader.read(1)
            if ver != b"\x01":
                return
            ulen = (await reader.read(1))[0]
            uname = (await reader.read(ulen)).decode("utf-8", errors="replace")
            plen = (await reader.read(1))[0]
            password = (await reader.read(plen)).decode("utf-8", errors="replace")

            if not self._check_auth(uname, password):
                writer.write(b"\x01\x01")  # Authentication failure
                await writer.drain()
                return

            directive = parse_credentials(uname)
            writer.write(b"\x01\x00")  # Authentication success
            await writer.drain()
        else:
            if b"\x02" in methods:
                writer.write(b"\x05\x02")
                await writer.drain()

                ver = await reader.read(1)
                if ver != b"\x01":
                    return
                ulen = (await reader.read(1))[0]
                uname = (await reader.read(ulen)).decode("utf-8", errors="replace")
                plen = (await reader.read(1))[0]
                await reader.read(plen)

                directive = parse_credentials(uname)
                writer.write(b"\x01\x00")
                await writer.drain()
            else:
                writer.write(b"\x05\x00")
                await writer.drain()

        # 2. Read SOCKS5 request: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR DST.PORT
        req_hdr = await reader.read(4)
        if len(req_hdr) < 4 or req_hdr[0] != 5 or req_hdr[1] != 1:  # CMD 1 = CONNECT
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # Command not supported
            await writer.drain()
            return

        atyp = req_hdr[3]
        target_host = ""
        if atyp == 1:  # IPv4
            ip_bytes = await reader.read(4)
            target_host = str(ipaddress.IPv4Address(ip_bytes))
        elif atyp == 3:  # Domain name
            domain_len = (await reader.read(1))[0]
            target_host = (await reader.read(domain_len)).decode("utf-8", errors="replace")
        elif atyp == 4:  # IPv6
            ip_bytes = await reader.read(16)
            target_host = str(ipaddress.IPv6Address(ip_bytes))
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        port_bytes = await reader.read(2)
        target_port = struct.unpack("!H", port_bytes)[0]
        target_authority = f"{target_host}:{target_port}"

        # Asynchronous SSRF Protection
        if not self.allow_private_networks and await is_ssrf_restricted(target_host):
            writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")  # Connection not allowed
            await writer.drain()
            return

        # Prepare SSL context before acknowledging SOCKS5 to ensure server is ready for TLS ClientHello
        if target_port == 443:
            ssl_ctx = await self.ca.get_ssl_context_for_host_async(target_host)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            loop = asyncio.get_running_loop()
            transport = writer.transport
            protocol = transport.get_protocol()
            if hasattr(protocol, "_over_ssl"):
                protocol._over_ssl = True
            try:
                new_transport = await asyncio.wait_for(
                    loop.start_tls(transport, protocol, ssl_ctx, server_side=True),
                    timeout=self.tls_handshake_timeout,
                )
            except (asyncio.TimeoutError, Exception) as exc:
                logger.debug(f"SOCKS5 TLS handshake failed or timed out for {target_host}: {exc}")
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return
            writer._transport = new_transport

            try:
                await self._run_tls_http_loop(reader, writer, target_authority, directive)
            finally:
                writer.close()
        else:
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            try:
                await self._run_plain_http_loop(reader, writer, target_authority, directive)
            finally:
                writer.close()

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_authority: str,
    ) -> None:
        """Handles HTTP CONNECT tunneling with dynamic local TLS interception."""
        # Drain client CONNECT headers
        headers: dict[str, str] = {}
        while True:
            h_line = await reader.readline()
            if not h_line or h_line in (b"\r\n", b"\n"):
                break
            decoded = h_line.decode("utf-8", errors="replace").strip()
            if ":" in decoded:
                k, v = decoded.split(":", 1)
                headers[k.strip()] = v.strip()

        # Enforce client proxy authentication if configured
        if self.auth:
            authorized = False
            auth_hdr = {k.lower(): v for k, v in headers.items()}.get("proxy-authorization", "")
            if auth_hdr.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth_hdr[6:].strip()).decode("utf-8")
                    user, pwd = decoded.split(":", 1) if ":" in decoded else (decoded, "")
                    if self._check_auth(user, pwd):
                        authorized = True
                except Exception:
                    pass
            if not authorized:
                writer.write(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"ja4proxy\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

        clean_host, target_port = extract_host_port(target_authority, default_port=443)

        # Asynchronous SSRF Protection
        if not self.allow_private_networks and await is_ssrf_restricted(clean_host):
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\nRestricted target address")
            await writer.drain()
            return

        directive, _ = extract_directives(headers)

        if target_port == 443:
            ssl_ctx = await self.ca.get_ssl_context_for_host_async(clean_host)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            loop = asyncio.get_running_loop()
            transport = writer.transport
            protocol = transport.get_protocol()
            if hasattr(protocol, "_over_ssl"):
                protocol._over_ssl = True
            try:
                new_transport = await asyncio.wait_for(
                    loop.start_tls(transport, protocol, ssl_ctx, server_side=True),
                    timeout=self.tls_handshake_timeout,
                )
            except (asyncio.TimeoutError, Exception) as exc:
                logger.debug(f"CONNECT TLS handshake failed or timed out for {clean_host}: {exc}")
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return
            writer._transport = new_transport

            try:
                await self._run_tls_http_loop(reader, writer, target_authority, directive)
            finally:
                writer.close()
        else:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            try:
                await self._run_plain_http_loop(reader, writer, target_authority, directive)
            finally:
                writer.close()

    async def _run_tls_http_loop(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_authority: str,
        initial_directive: Directive,
    ) -> None:
        """HTTP keep-alive loop over intercepted TLS."""
        used_sessions: set[str] = set()

        try:
            while not reader.at_eof() and not self._closing:
                try:
                    req_line_bytes = await asyncio.wait_for(
                        reader.readline(), timeout=self.idle_timeout
                    )
                except asyncio.TimeoutError:
                    break

                if not req_line_bytes:
                    break
                req_line = req_line_bytes.decode("utf-8", errors="replace").strip()
                if not req_line:
                    continue
                parts = req_line.split(" ")
                if len(parts) < 2:
                    break

                method = parts[0].upper()
                path = parts[1]
                http_version = parts[2].upper() if len(parts) > 2 else "HTTP/1.1"

                headers, body = await self._read_headers_and_body(reader)
                target_url = f"https://{target_authority}{path}"

                req_directive, clean_headers = extract_directives(headers)

                # Directive priority: per-request header > initial auth directive > server default
                profile_to_use = (
                    req_directive.profile
                    or initial_directive.profile
                    or self.default_profile
                )
                proxy_to_use = (
                    req_directive.upstream_proxy
                    or initial_directive.upstream_proxy
                    or self.upstream_proxy
                    or ""
                )
                session_to_use = (
                    req_directive.session_id
                    or initial_directive.session_id
                    or "ja4_default"
                )
                timeout_to_use = (
                    req_directive.timeout
                    if req_directive.timeout is not None
                    else (
                        initial_directive.timeout
                        if initial_directive.timeout is not None
                        else 30
                    )
                )
                insecure_to_use = (
                    req_directive.insecure_skip_verify
                    or initial_directive.insecure_skip_verify
                )

                if session_to_use != "ja4_default":
                    used_sessions.add(session_to_use)

                upstream_resp = await self.engine.request(
                    method=method,
                    url=target_url,
                    headers=clean_headers,
                    body=body if body else None,
                    profile=profile_to_use,
                    proxy_url=proxy_to_use,
                    timeout_seconds=timeout_to_use,
                    insecure_skip_verify=insecure_to_use,
                    session_id=session_to_use,
                )

                await self._write_response(writer, upstream_resp)

                # Case-insensitive connection header inspection
                lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
                conn_val = lower_headers.get("connection", "")
                if conn_val == "close":
                    break
                if http_version == "HTTP/1.0" and conn_val != "keep-alive":
                    break
        finally:
            # Clean up ephemeral or single-connection sessions
            for s_id in used_sessions:
                if s_id.startswith("tmp_") or s_id.startswith("ephemeral_"):
                    task = asyncio.create_task(self.engine.destroy_session(s_id))
                    self._pending_session_tasks.add(task)
                    task.add_done_callback(self._pending_session_tasks.discard)

    async def _run_plain_http_loop(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_authority: str,
        directive: Directive,
    ) -> None:
        """HTTP keep-alive loop over plain HTTP."""
        used_sessions: set[str] = set()

        try:
            while not reader.at_eof() and not self._closing:
                try:
                    req_line_bytes = await asyncio.wait_for(
                        reader.readline(), timeout=self.idle_timeout
                    )
                except asyncio.TimeoutError:
                    break

                if not req_line_bytes:
                    break
                req_line = req_line_bytes.decode("utf-8", errors="replace").strip()
                if not req_line:
                    continue
                parts = req_line.split(" ")
                if len(parts) < 2:
                    break

                method = parts[0].upper()
                path = parts[1]
                http_version = parts[2].upper() if len(parts) > 2 else "HTTP/1.1"

                headers, body = await self._read_headers_and_body(reader)
                target_url = f"http://{target_authority}{path}"

                req_directive, clean_headers = extract_directives(headers)
                profile_to_use = (
                    req_directive.profile
                    or directive.profile
                    or self.default_profile
                )
                proxy_to_use = (
                    req_directive.upstream_proxy
                    or directive.upstream_proxy
                    or self.upstream_proxy
                    or ""
                )
                session_to_use = (
                    req_directive.session_id
                    or directive.session_id
                    or "ja4_default"
                )
                timeout_to_use = (
                    req_directive.timeout
                    if req_directive.timeout is not None
                    else (
                        directive.timeout
                        if directive.timeout is not None
                        else 30
                    )
                )
                insecure_to_use = (
                    req_directive.insecure_skip_verify
                    or directive.insecure_skip_verify
                )

                if session_to_use != "ja4_default":
                    used_sessions.add(session_to_use)

                upstream_resp = await self.engine.request(
                    method=method,
                    url=target_url,
                    headers=clean_headers,
                    body=body if body else None,
                    profile=profile_to_use,
                    proxy_url=proxy_to_use,
                    timeout_seconds=timeout_to_use,
                    insecure_skip_verify=insecure_to_use,
                    session_id=session_to_use,
                )

                await self._write_response(writer, upstream_resp)

                lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
                conn_val = lower_headers.get("connection", "")
                if conn_val == "close":
                    break
                if http_version == "HTTP/1.0" and conn_val != "keep-alive":
                    break
        finally:
            for s_id in used_sessions:
                if s_id.startswith("tmp_") or s_id.startswith("ephemeral_"):
                    task = asyncio.create_task(self.engine.destroy_session(s_id))
                    self._pending_session_tasks.add(task)
                    task.add_done_callback(self._pending_session_tasks.discard)

    async def _handle_plain_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target_uri: str,
    ) -> None:
        """Handles plain HTTP gateway requests."""
        headers, body = await self._read_headers_and_body(reader)

        # Enforce client proxy authentication if configured
        if self.auth:
            authorized = False
            auth_hdr = {k.lower(): v for k, v in headers.items()}.get("proxy-authorization", "")
            if auth_hdr.lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth_hdr[6:].strip()).decode("utf-8")
                    user, pwd = decoded.split(":", 1) if ":" in decoded else (decoded, "")
                    if self._check_auth(user, pwd):
                        authorized = True
                except Exception:
                    pass
            if not authorized:
                writer.write(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Proxy-Authenticate: Basic realm=\"ja4proxy\"\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                return

        if target_uri.startswith("/http://") or target_uri.startswith("/https://"):
            target_url = target_uri[1:]
        elif target_uri.startswith("http://") or target_uri.startswith("https://"):
            target_url = target_uri
        elif "host" in {k.lower(): v for k, v in headers.items()}:
            host_hdr = {k.lower(): v for k, v in headers.items()}["host"]
            target_url = f"http://{host_hdr}{target_uri}"
        else:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\nMissing target host")
            await writer.drain()
            return

        parsed = urllib.parse.urlparse(target_url)
        clean_host = parsed.hostname or ""

        # Asynchronous SSRF Protection
        if not self.allow_private_networks and await is_ssrf_restricted(clean_host):
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\nRestricted target address")
            await writer.drain()
            return

        directive, clean_headers = extract_directives(headers)
        profile_to_use = directive.profile or self.default_profile
        proxy_to_use = directive.upstream_proxy or self.upstream_proxy or ""
        session_to_use = directive.session_id or "ja4_default"
        timeout_to_use = directive.timeout if directive.timeout is not None else 30

        upstream_resp = await self.engine.request(
            method=method,
            url=target_url,
            headers=clean_headers,
            body=body if body else None,
            profile=profile_to_use,
            proxy_url=proxy_to_use,
            timeout_seconds=timeout_to_use,
            insecure_skip_verify=directive.insecure_skip_verify,
            session_id=session_to_use,
        )

        await self._write_response(writer, upstream_resp)

    async def _write_response(
        self, writer: asyncio.StreamWriter, resp: dict[str, Any]
    ) -> None:
        """
        Formats and writes HTTP response to client.
        Safely falls back on None headers to prevent crash, handles RFC 7230 status 204/304,
        maps invalid/zero status codes to 502 Bad Gateway with readable diagnostic body,
        and guarantees true Content-Length without compression desync.
        """
        status_code = resp.get("status", 200)
        if not (100 <= status_code <= 599):
            status_code = 502

        status_text = http.client.responses.get(
            status_code, "Bad Gateway" if status_code == 502 else f"Status {status_code}"
        )
        body_bytes = resp.get("body", b"")

        status_line = f"HTTP/1.1 {status_code} {status_text}\r\n"
        writer.write(status_line.encode("utf-8"))

        raw_headers = resp.get("headers") or {}

        # RFC 7230: 204 No Content and 304 Not Modified must not include body or Content-Length
        if status_code in (204, 304):
            writer.write(b"\r\n")
            await writer.drain()
            return

        # Strip hop-by-hop headers AND Content-Encoding since body is decompressed
        stripped_headers = {
            "transfer-encoding",
            "connection",
            "proxy-connection",
            "proxy-authenticate",
            "content-encoding",
            "content-length",
        }

        has_content_type = False
        for key, vals in raw_headers.items():
            k_lower = key.lower()
            if k_lower in stripped_headers:
                continue
            if k_lower == "content-type":
                has_content_type = True
            if isinstance(vals, list):
                for v in vals:
                    writer.write(f"{key}: {v}\r\n".encode("utf-8"))
            else:
                writer.write(f"{key}: {vals}\r\n".encode("utf-8"))

        if not has_content_type and status_code >= 400:
            writer.write(b"Content-Type: text/plain; charset=utf-8\r\n")

        # Explicitly set true uncompressed Content-Length
        writer.write(f"Content-Length: {len(body_bytes)}\r\n".encode("utf-8"))
        writer.write(b"\r\n")

        if body_bytes:
            writer.write(body_bytes)
        await writer.drain()
