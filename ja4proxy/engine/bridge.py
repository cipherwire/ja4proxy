import asyncio
import base64
import ctypes
import json
import threading
from typing import Any

from ja4proxy.engine.loader import resolve_native_library
from ja4proxy.profiles import get_default_headers, normalize_profile


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
            resp_obj = json.loads(decoded)
            if isinstance(resp_obj, dict):
                resp_id = resp_obj.get("id")
            return resp_obj
        except Exception as e:
            raise EngineError(f"Failed to parse native engine response: {e}") from e
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
        """Destroys an allocated session in the Go engine to release memory and cookies."""
        payload = json.dumps({"sessionId": session_id}).encode("utf-8")
        resp_ptr = self.lib.destroySession(payload)
        if not resp_ptr:
            return False

        resp_id = None
        try:
            raw_bytes = ctypes.string_at(resp_ptr)
            resp_obj = json.loads(raw_bytes.decode("utf-8", errors="replace"))
            if isinstance(resp_obj, dict):
                resp_id = resp_obj.get("id")
                return bool(resp_obj.get("success", False))
            return False
        except Exception:
            return False
        finally:
            if resp_id:
                try:
                    self.lib.freeMemory(resp_id.encode("utf-8"))
                except Exception:
                    pass

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

        # Start with default browser headers for the profile
        merged_headers: dict[str, str] = get_default_headers(prof)

        # Overlay client headers (case-insensitive merge)
        if headers:
            for k, v in headers.items():
                if v is not None:
                    merged_headers[k.lower()] = str(v)

        payload = {
            "sessionId": session_id,
            "tlsClientIdentifier": prof,
            "requestMethod": method.upper(),
            "requestUrl": url,
            "requestBody": encoded_body,
            "isByteRequest": is_byte_req,
            "isByteResponse": True,
            "headers": merged_headers,
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
