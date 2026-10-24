import base64
from dataclasses import dataclass
import re
from typing import Any

from ja4proxy.profiles import normalize_profile


@dataclass
class Directive:
    """Parsed execution directives for an intercepted request."""

    profile: str | None = None
    session_id: str | None = None
    upstream_proxy: str | None = None
    timeout: int | None = None
    insecure_skip_verify: bool = False


def parse_credentials(username: str) -> Directive:
    """
    Parses directives from username tags without truncating hyphens in URLs.
    Supports formats:
      user-profile_safari16-proxy_http://user:p-a-s-s@res-gate.io:8000-session_xyz
      user-chrome133
    """
    directive = Directive()
    if not username:
        return directive

    tag_pattern = re.compile(r"(?:^|[-])(profile_|session_|proxy_|timeout_|insecure_)")
    matches = list(tag_pattern.finditer(username))

    if matches:
        for i, m in enumerate(matches):
            key = m.group(1).rstrip("_")
            val_start = m.end()
            if i + 1 < len(matches):
                val_end = matches[i + 1].start()
                val = username[val_start:val_end]
            else:
                val = username[val_start:]
            if val.endswith("-"):
                val = val[:-1]

            if key == "profile":
                directive.profile = normalize_profile(val)
            elif key == "session":
                directive.session_id = val
            elif key == "proxy":
                directive.upstream_proxy = val
            elif key == "timeout":
                try:
                    directive.timeout = int(val)
                except ValueError:
                    pass
            elif key == "insecure":
                directive.insecure_skip_verify = val.lower() in ("1", "true", "yes")
    else:
        # Fallback for simple shorthand like user-chrome133
        parts = username.split("-")
        for part in parts:
            if any(
                part.startswith(b) for b in ("chrome", "safari", "firefox", "opera")
            ):
                directive.profile = normalize_profile(part)

    return directive


def extract_directives(
    headers: dict[str, str], username: str | None = None
) -> tuple[Directive, dict[str, str]]:
    """
    Extracts proxy directives from headers and credentials,
    and returns (Directive, sanitized_headers).
    Header directives take precedence over username tags.
    """
    directive = parse_credentials(username or "")

    lower_map: dict[str, str] = {k.lower(): k for k in headers.keys()}

    # Extract auth header if username was not passed explicitly
    if not username and "proxy-authorization" in lower_map:
        val = headers[lower_map["proxy-authorization"]].strip()
        if val.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(val[6:].strip()).decode("utf-8")
                user = decoded.split(":", 1)[0]
                dir_from_auth = parse_credentials(user)
                if dir_from_auth.profile is not None:
                    directive.profile = dir_from_auth.profile
                if dir_from_auth.session_id is not None:
                    directive.session_id = dir_from_auth.session_id
                if dir_from_auth.upstream_proxy is not None:
                    directive.upstream_proxy = dir_from_auth.upstream_proxy
                if dir_from_auth.timeout is not None:
                    directive.timeout = dir_from_auth.timeout
                if dir_from_auth.insecure_skip_verify:
                    directive.insecure_skip_verify = True
            except Exception:
                pass

    # Request headers override any credential directive
    if "x-ja4-profile" in lower_map:
        directive.profile = normalize_profile(headers[lower_map["x-ja4-profile"]])

    if "x-ja4-session" in lower_map:
        directive.session_id = headers[lower_map["x-ja4-session"]]

    if "x-ja4-upstream-proxy" in lower_map:
        directive.upstream_proxy = headers[lower_map["x-ja4-upstream-proxy"]]

    if "x-ja4-timeout" in lower_map:
        try:
            directive.timeout = int(headers[lower_map["x-ja4-timeout"]])
        except ValueError:
            pass

    if "x-ja4-insecure" in lower_map:
        directive.insecure_skip_verify = headers[lower_map["x-ja4-insecure"]].lower() in (
            "1",
            "true",
            "yes",
        )

    # Build clean sanitized headers (strip proxy directives and internal controls)
    sanitized: dict[str, str] = {}
    drop_prefixes = ("x-ja4-",)
    drop_headers = {"proxy-authorization", "proxy-connection"}

    for k, v in headers.items():
        lc = k.lower()
        if lc in drop_headers or any(lc.startswith(p) for p in drop_prefixes):
            continue
        sanitized[k] = v

    return directive, sanitized
