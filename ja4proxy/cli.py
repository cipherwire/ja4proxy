import asyncio
import logging
import os
import shutil
import sys

import click

from ja4proxy import __version__
from ja4proxy.certs import CertificateAuthority
from ja4proxy.engine.bridge import NativeEngine
from ja4proxy.profiles import SUPPORTED_PROFILES, normalize_profile
from ja4proxy.server import ProxyServer


@click.group()
@click.version_option(__version__, prog_name="ja4proxy")
def main() -> None:
    """ja4proxy: High-performance universal proxy server with browser TLS (JA4) and HTTP/2 impersonation."""
    pass


@main.command()
@click.option("--host", default="127.0.0.1", help="Binding IP address.")
@click.option("--port", "-p", default=8888, type=int, help="Port to listen on.")
@click.option(
    "--profile",
    default="chrome_133",
    help="Default browser profile (e.g. chrome_133, safari_16_0, firefox_133).",
)
@click.option(
    "--upstream-proxy",
    default=None,
    help="Default upstream proxy URL (e.g. socks5://user:pass@host:1080).",
)
@click.option(
    "--auth",
    default=None,
    help="Require username:password authentication for client connections.",
)
@click.option(
    "--cert-dir", default=None, help="Directory to store CA and leaf certificates."
)
@click.option(
    "--allow-private-networks",
    is_flag=True,
    help="Allow forwarding requests to private and loopback IP ranges.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose debug logging.")
def start(
    host: str,
    port: int,
    profile: str,
    upstream_proxy: str | None,
    auth: str | None,
    cert_dir: str | None,
    allow_private_networks: bool,
    verbose: bool,
) -> None:
    """Starts the ja4proxy server."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    prof = normalize_profile(profile)
    server = ProxyServer(
        host=host,
        port=port,
        default_profile=prof,
        cert_dir=cert_dir,
        allow_private_networks=allow_private_networks,
        upstream_proxy=upstream_proxy,
        auth=auth,
    )

    ca_path = server.ca.ca_cert_path
    click.echo(
        f"[*] ja4proxy v{__version__} starting on http://{host}:{port}"
    )
    click.echo(f"[*] Default Profile: {prof}")
    click.echo(f"[*] Protocols Supported: HTTP CONNECT, HTTP Gateway, SOCKS5 (Auto-detect)")
    click.echo(f"[*] CA Certificate: {ca_path}")
    click.echo(
        "[*] Ready for HTTP and SOCKS5 clients (Python requests, Node axios, cURL, etc.)"
    )

    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        click.echo("\n[*] Shutting down ja4proxy...")


@main.command(name="profiles")
def list_profiles() -> None:
    """Lists all supported browser profiles for TLS and HTTP/2 emulation."""
    click.echo("Supported Browser Profiles:")
    for prof in SUPPORTED_PROFILES:
        click.echo(f"  - {prof}")


@main.command(name="ca")
@click.option(
    "--export",
    "-e",
    "export_path",
    default=None,
    help="Export root CA certificate (ca.pem) to specified path.",
)
def manage_ca(export_path: str | None) -> None:
    """Inspects or exports the local Root CA certificate."""
    ca = CertificateAuthority()
    click.echo(f"Root CA Certificate: {ca.ca_cert_path}")
    click.echo(f"Root CA Private Key: {ca.ca_key_path}")

    if export_path:
        dest = os.path.abspath(export_path)
        shutil.copyfile(ca.ca_cert_path, dest)
        click.echo(f"Exported CA to: {dest}")


@main.command(name="test")
@click.option(
    "--profile",
    default="chrome_133",
    help="Browser profile to test against tls.peet.ws.",
)
def test_handshake(profile: str) -> None:
    """Performs a direct live handshake against tls.peet.ws to inspect upstream JA4."""
    import json

    prof = normalize_profile(profile)
    click.echo(f"Testing upstream handshake for profile: {prof}...")

    async def _test():
        engine = NativeEngine.get_instance()
        res = await engine.request(
            method="GET",
            url="https://tls.peet.ws/api/all",
            profile=prof,
            timeout_seconds=15,
        )
        return res

    try:
        res = asyncio.run(_test())
        click.echo(f"Status Code: {res['status']}")
        click.echo(f"Negotiated Protocol: {res['protocol']}")

        body = json.loads(res["body"].decode("utf-8", errors="replace"))
        tls_info = body.get("tls", {})
        click.echo(f"Remote Peer JA4: {tls_info.get('ja4')}")
        click.echo(f"Remote Peer JA3: {tls_info.get('ja3')}")
        click.echo(f"HTTP Version: {body.get('http_version')}")
    except Exception as e:
        click.echo(f"Error executing test: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
