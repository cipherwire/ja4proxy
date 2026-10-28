"""ja4proxy: High-performance universal proxy server with browser TLS (JA4) and HTTP/2 impersonation."""

__version__ = "0.7.0"
__author__ = "cipherwire"

from ja4proxy.certs import (
    CertificateAuthority,
    get_ca_bundle_path,
    get_ca_cert_path,
    inject_trust,
    install_ca,
    uninstall_ca,
)
from ja4proxy.engine.bridge import NativeEngine
from ja4proxy.server import ProxyServer

__all__ = [
    "ProxyServer",
    "NativeEngine",
    "CertificateAuthority",
    "get_ca_cert_path",
    "get_ca_bundle_path",
    "inject_trust",
    "install_ca",
    "uninstall_ca",
    "__version__",
]
