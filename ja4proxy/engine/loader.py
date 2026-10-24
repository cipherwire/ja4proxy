import ctypes
import hashlib
import os
import platform
import sys
import threading
import urllib.request

OWNER = "bogdanfinn"
REPO = "tls-client"
DEFAULT_VERSION = "1.16.0"

RELEASE_DOWNLOAD_URL = (
    f"https://github.com/{OWNER}/{REPO}/releases/download/v{DEFAULT_VERSION}/{{asset}}"
)

ASSET_SHA256: dict[str, str] = {
    "tls-client-xgo-1.16.0-darwin-amd64.dylib": "9cb5fd24bceb74cedd4372bdbdf013058c650fa6f8df2a1336918d8ee54128d8",
    "tls-client-xgo-1.16.0-darwin-arm64.dylib": "f3a6f5ffadc4a7f5184d9880380e522fbaf6890c623eae1ac0805071f42f5aaa",
    "tls-client-xgo-1.16.0-linux-386.so": "5ea81308e53e236dae73b35bd4a09af1201191c32713ea2968b85bbcfe94b616",
    "tls-client-xgo-1.16.0-linux-amd64.so": "75f19133e3cb9b16ab3d2dfe3376c7590aab2fe6f2294debac661bfd63dca6a3",
    "tls-client-xgo-1.16.0-linux-arm-5.so": "02cca934f2fc15db658e2d94ed472691224656b696c6531ffec2d0aad2997b2f",
    "tls-client-xgo-1.16.0-linux-arm-6.so": "5c991eca511de6d0ea04f12100c89a7750696213e246226e4050d88bf7e9136b",
    "tls-client-xgo-1.16.0-linux-arm-7.so": "ee9125b4580bf3e1515304e6faeb4ce30eb88f47c5158349a14d38b25448c358",
    "tls-client-xgo-1.16.0-linux-arm64.so": "91f88d35fa64284c811373003d2a26caa3145eaeefd1c0e9576f10724a914332",
    "tls-client-xgo-1.16.0-windows-386.dll": "f41099111446ec3252166b640156a2213d387511e4e80e849ce8b8a0871be47f",
    "tls-client-xgo-1.16.0-windows-amd64.dll": "33d9b5a4a1a902bae57494186ddce91af32fb67326d94ea04776447a81c15934",
}

_loader_lock = threading.Lock()


def get_system_platform() -> tuple[str, str]:
    """Detects system OS and CPU architecture."""
    system_os = platform.system().lower()
    machine = platform.machine().lower()

    if system_os == "darwin":
        return "darwin", ("arm64" if machine == "arm64" else "amd64")

    if system_os in ("windows", "win32", "cygwin"):
        return "windows", ("amd64" if ctypes.sizeof(ctypes.c_voidp) == 8 else "386")

    sys_os = "linux"
    if machine in ("aarch64", "arm64"):
        return sys_os, "arm64"
    if machine in ("x86_64", "amd64"):
        return sys_os, "amd64"
    if machine in ("i386", "i486", "i586", "i686", "x86"):
        return sys_os, "386"
    return sys_os, "amd64"


def get_asset_filename() -> str:
    """Builds the asset filename for the current platform."""
    sys_os, arch = get_system_platform()
    ext = "dll" if sys_os == "windows" else ("dylib" if sys_os == "darwin" else "so")
    return f"tls-client-xgo-{DEFAULT_VERSION}-{sys_os}-{arch}.{ext}"


def get_cache_directory() -> str:
    """Returns the persistent directory for storing native binaries."""
    env_dir = os.getenv("JA4PROXY_CACHE_DIR")
    if env_dir:
        os.makedirs(env_dir, exist_ok=True)
        return env_dir

    if sys.platform == "win32":
        base = os.getenv("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
        cache_dir = os.path.join(base, "ja4proxy")
    else:
        xdg = os.getenv("XDG_CACHE_HOME") or os.path.join(
            os.path.expanduser("~"), ".cache"
        )
        cache_dir = os.path.join(xdg, "ja4proxy")

    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


def _compute_sha256(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_native_library() -> str:
    """
    Finds or downloads the native Go shared library.
    Resolves in order:
    1. JA4PROXY_LIB_PATH env var
    2. Local ja4proxy cache directory
    3. Existing horaa-tls cache directory (fallback reuse)
    4. Direct download from GitHub releases with SHA-256 verification
    """
    with _loader_lock:
        custom_path = os.getenv("JA4PROXY_LIB_PATH")
        if custom_path and os.path.exists(custom_path):
            return custom_path

        asset_name = get_asset_filename()
        cache_dir = get_cache_directory()
        target_path = os.path.join(cache_dir, asset_name)

        if os.path.exists(target_path):
            expected_hash = ASSET_SHA256.get(asset_name)
            if expected_hash:
                actual_hash = _compute_sha256(target_path)
                if actual_hash == expected_hash:
                    return target_path

        # Check existing horaa-tls cache location
        if sys.platform == "win32":
            local_appdata = os.getenv("LOCALAPPDATA") or ""
            horaa_path = os.path.join(local_appdata, "horaa-tls", asset_name)
            if os.path.exists(horaa_path):
                expected_hash = ASSET_SHA256.get(asset_name)
                if not expected_hash or _compute_sha256(horaa_path) == expected_hash:
                    return horaa_path
        else:
            xdg = os.getenv("XDG_CACHE_HOME") or os.path.join(
                os.path.expanduser("~"), ".cache"
            )
            horaa_path = os.path.join(xdg, "horaa-tls", asset_name)
            if os.path.exists(horaa_path):
                expected_hash = ASSET_SHA256.get(asset_name)
                if not expected_hash or _compute_sha256(horaa_path) == expected_hash:
                    return horaa_path

        # Download from GitHub release
        download_url = RELEASE_DOWNLOAD_URL.format(asset=asset_name)
        temp_path = target_path + ".tmp"
        try:
            req = urllib.request.Request(
                download_url, headers={"User-Agent": "ja4proxy/0.1.0"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp, open(
                temp_path, "wb"
            ) as out:
                for chunk in iter(lambda: resp.read(65536), b""):
                    out.write(chunk)

            expected_hash = ASSET_SHA256.get(asset_name)
            if expected_hash:
                actual_hash = _compute_sha256(temp_path)
                if actual_hash != expected_hash:
                    raise RuntimeError(
                        f"SHA-256 mismatch for {asset_name}: expected {expected_hash}, got {actual_hash}"
                    )

            os.replace(temp_path, target_path)
            return target_path
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
