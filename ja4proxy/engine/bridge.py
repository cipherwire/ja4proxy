import asyncio
import base64
import ctypes
import json
import re
import threading
from typing import Any

from ja4proxy.engine.loader import resolve_native_library
from ja4proxy.profiles import (
    get_canonical_header_order,
    get_default_headers,
    normalize_profile,
)

# Well-known automation client signatures. When a client supplies one of these as
# User-Agent the canonical profile header replaces it, keeping the HTTP layer
# consistent with the impersonated TLS fingerprint (README: Header Sanitization).
_AUTOMATION_UA_PREFIXES = (
    "curl/",
    "wget/",
    "python-requests/",
    "python-urllib/",
    "python-httpx",
    "aiohttp/",
    "go-http-client",
    "java/",
    "apache-httpclient",
    "okhttp/",
    "scrapy",
    "libwww-perl",
    "axios/",
    "undici",
    "node-fetch",
)


class EngineError(Exception):
    """Raised when the native uTLS engine fails to execute a request."""


class NativeEngine:
    """In-process bridge to the Go uTLS / fhttp shared library via ctypes."""

    _instance: "NativeEngine | None" = None
    _init_lock = threading.Lock()

    def __init__(self, lib_path: str | None = None):
        path = lib_path or resolve_native_library()
        self.lib = ctypes.cdll.LoadLibrary(path)

        # Set up C function signatures
        self.lib.request.argtypes = [ctypes.c_char_p]
        self.lib.request.restype = ctypes.c_char_p

        self.lib.freeMemory.argtypes = [ctypes.c_char_p]
        self.lib.freeMemory.restype = None

        self.lib.destroySession.argtypes = [ctypes.c_char_p]
        self.lib.destroySession.restype = ctypes.c_char_p

        # The Go library bakes the TLS profile and verification mode into the client
        # it caches per session id, so every (session, profile, insecure) combination
        # maps to a distinct native session key. Aliases let destroy_session() tear
        # down every native session a logical session id created.
        self._alias_lock = threading.Lock()
        self._session_aliases: dict[str, set[str]] = {}

    @staticmethod
    def effective_session_id(session_id: str, profile: str, insecure_skip_verify: bool) -> str:
        """Native session key for a logical session under a specific TLS profile."""
        suffix = f"{profile}|insecure" if insecure_skip_verify else profile
        return f"{session_id}|{suffix}"

    def _register_alias(self, client_id: str, effective_id: str) -> None:
        with self._alias_lock:
            self._session_aliases.setdefault(client_id, set()).add(effective_id)

    @classmethod
    def get_instance(cls) -> "NativeEngine":
        if cls._instance is None:
            with cls._init_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _execute_sync(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Synchronously invokes the C function and frees the Go-allocated memory."""
        payload_bytes = json.dumps(payload).encode("utf-8")
        resp_ptr = self.lib.request(payload_bytes)

        if not resp_ptr:
            raise EngineError("Native engine returned null pointer")

        resp_id = None
        try:
            raw_bytes = ctypes.string_at(resp_ptr)
            decoded = raw_bytes.decode("utf-8", errors="replace")
            try:
                resp_obj = json.loads(decoded)
            except Exception:
                resp_obj = None
            if isinstance(resp_obj, dict):
                resp_id = resp_obj.get("id")
            else:
                # Recover the allocation id even when the payload is not valid JSON
                # so the Go-side buffer can still be released.
                m = re.search(rb'"id"\s*:\s*"([^"]+)"', raw_bytes)
                if m:
                    resp_id = m.group(1).decode("ascii", errors="ignore")
            if resp_obj is None:
                raise EngineError(f"Failed to parse native engine response: {decoded[:200]}")
            return resp_obj
        finally:
            if resp_id:
                try:
                    self.lib.freeMemory(resp_id.encode("utf-8"))
                except Exception:
                    pass

    async def execute_async(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Asynchronously executes request in threadpool, releasing Python GIL."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._execute_sync, payload)

    def destroy_session_sync(self, session_id: str) -> bool:
        """Destroys every native session allocated for a logical session id."""
        with self._alias_lock:
            targets = self._session_aliases.pop(session_id, None)
        targets = targets or {session_id}

        all_ok = True
        for target in targets:
            payload = json.dumps({"sessionId": target}).encode("utf-8")
            resp_ptr = self.lib.destroySession(payload)
            if not resp_ptr:
                all_ok = False
                continue

            resp_id = None
            try:
                raw_bytes = ctypes.string_at(resp_ptr)
                resp_obj = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                if isinstance(resp_obj, dict):
                    resp_id = resp_obj.get("id")
                    all_ok = all_ok and bool(resp_obj.get("success", False))
                else:
                    all_ok = False
            except Exception:
                all_ok = False
            finally:
                if resp_id:
                    try:
                        self.lib.freeMemory(resp_id.encode("utf-8"))
                    except Exception:
                        pass
        return all_ok

    async def destroy_session(self, session_id: str) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.destroy_session_sync, session_id)

    async def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        profile: str = "chrome_133",
        proxy_url: str = "",
        timeout_seconds: int = 30,
        follow_redirects: bool = False,
        insecure_skip_verify: bool = False,
        session_id: str = "ja4_default",
    ) -> dict[str, Any]:
        """
        Dispatches an HTTP request through the native uTLS engine.
        Merges canonical browser headers to ensure the target never sees automated client signatures.
        """
        prof = normalize_profile(profile)
        is_byte_req = False
        encoded_body = ""
        if body:
            encoded_body = base64.b64encode(body).decode("utf-8")
            is_byte_req = True

        # The Go engine bakes the TLS profile and verification mode into the client
        # cached per session id, so a logical session must key its native sessions by
        # (profile, insecure) or profile switches would be silently ignored.
        effective_session = self.effective_session_id(session_id, prof, insecure_skip_verify)
        self._register_alias(session_id, effective_session)

        # Start with default browser headers for the profile
        merged_headers: dict[str, str] = get_default_headers(prof)

        # Overlay client headers (case-insensitive merge)
        if headers:
            for k, v in headers.items():
                if v is not None:
                    merged_headers[k.lower()] = str(v)

        # Strip well-known automation User-Agents so the HTTP layer stays consistent
        # with the impersonated TLS fingerprint; explicit custom browser UAs pass through.
        ua = merged_headers.get("user-agent", "")
        if ua.strip().lower().startswith(_AUTOMATION_UA_PREFIXES):
            default_ua = get_default_headers(prof).get("user-agent")
            if default_ua:
                merged_headers["user-agent"] = default_ua

        header_order = get_canonical_header_order(prof, merged_headers)

        payload = {
            "sessionId": effective_session,
            "tlsClientIdentifier": prof,
            "requestMethod": method.upper(),
            "requestUrl": url,
            "requestBody": encoded_body,
            "isByteRequest": is_byte_req,
            "isByteResponse": True,
            "headers": merged_headers,
            "headerOrder": header_order,
            "requestCookies": [],
            "proxyUrl": proxy_url,
            "timeoutSeconds": timeout_seconds,
            "followRedirects": follow_redirects,
            "insecureSkipVerify": insecure_skip_verify,
            "forceHttp1": False,
            "withProtocolRacing": False,
            "disableHttp3": True,
            "withRandomTLSExtensionOrder": False,
        }

        raw = await self.execute_async(payload)

        status_code = raw.get("status", 0)
        raw_headers = raw.get("headers") or {}
        used_protocol = raw.get("usedProtocol", "")
        if used_protocol.startswith("HTTP/2"):
            used_protocol = "h2"
        raw_body = raw.get("body", "")

        # Handle native engine failure (status 0) -> 502 Bad Gateway
        if status_code == 0:
            status_code = 502
            error_msg = (
                raw.get("errorMessage")
                or (raw_body if isinstance(raw_body, str) else "")
                or "Bad Gateway: upstream connection failed"
            )
            body_bytes = (
                error_msg.encode("utf-8")
                if isinstance(error_msg, str)
                else error_msg
            )
        else:
            # Decode response body for real HTTP responses
            body_bytes = b""
            if isinstance(raw_body, str) and raw_body:
                if raw_body.startswith("data:") and "," in raw_body:
                    raw_body = raw_body.split(",", 1)[1]
                try:
                    body_bytes = base64.b64decode(raw_body)
                except Exception:
                    body_bytes = raw_body.encode("utf-8")

        return {
            "status": status_code,
            "headers": raw_headers,
            "body": body_bytes,
            "protocol": used_protocol,
            "target": raw.get("target", url),
        }
