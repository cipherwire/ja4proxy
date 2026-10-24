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

ASCII_BANNER = r"""
      _       __ __                             
     (_)___ _/ // / ____  _________  _  ____  __
    / / __ `/ // /_/ __ \/ ___/ __ \| |/_/ / / /
   / / /_/ /__  __/ /_/ / /  / /_/ />  </ /_/ / 
__/ /\__,_/  /_/ / .___/_/   \____/_/|_|\__, /  
/___/            /_/                    /____/   
"""


def render_banner() -> str:
    banner_art = click.style(ASCII_BANNER.strip("\r\n"), fg="cyan", bold=True)
    tagline = click.style(
        "  Universal Browser TLS & JA4 Impersonation Proxy",
        fg="white",
        bold=True,
    )
    meta = click.style(
        f"  Version: {__version__}  |  Docs: https://ja4proxy.cipherwire.link",
        fg="bright_black",
    )
    return f"{banner_art}\n{tagline}\n{meta}\n"


class BannerGroup(click.Group):
    """Custom Click Group that renders the cyberpunk ASCII banner on help."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        formatter.write(render_banner() + "\n")
        super().format_help(ctx, formatter)


@click.group(cls=BannerGroup, no_args_is_help=True)
@click.version_option(__version__, prog_name="ja4proxy")
def main() -> None:
    """High-performance universal forward proxy with authentic browser TLS and HTTP/2 framing."""
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
    sep = click.style("=" * 72, fg="cyan")
    divider = click.style("-" * 72, fg="bright_black")

    click.echo(render_banner())
    click.echo(sep)
    click.echo(
        f" {click.style('[*] Engine Status:', fg='bright_white', bold=True)}   "
        f"{click.style('ONLINE', fg='green', bold=True)}"
    )
    click.echo(
        f" {click.style('[*] HTTP Ingress:', fg='bright_white', bold=True)}    "
        f"{click.style(f'http://{host}:{port}', fg='cyan', underline=True)}"
    )
    click.echo(
        f" {click.style('[*] SOCKS5 Ingress:', fg='bright_white', bold=True)}  "
        f"{click.style(f'socks5://{host}:{port}', fg='cyan', underline=True)} "
        f"{click.style('(Auto-detect on same port)', fg='bright_black')}"
    )
    click.echo(
        f" {click.style('[*] Active Profile:', fg='bright_white', bold=True)}  "
        f"{click.style(prof, fg='yellow', bold=True)}"
    )
    upstream_desc = upstream_proxy if upstream_proxy else "DIRECT"
    click.echo(
        f" {click.style('[*] Upstream Proxy:', fg='bright_white', bold=True)}  "
        f"{click.style(upstream_desc, fg='bright_white')}"
    )
    auth_desc = "Enabled (HTTP Basic / SOCKS5)" if auth else "None (Open)"
    click.echo(
        f" {click.style('[*] Authentication:', fg='bright_white', bold=True)}  "
        f"{click.style(auth_desc, fg='bright_white')}"
    )
    ssrf_status = (
        click.style("PERMISSIVE (--allow-private-networks)", fg="yellow")
        if allow_private_networks
        else click.style("ENFORCED (RFC1918 & Loopback blocked)", fg="green")
    )
    click.echo(
        f" {click.style('[*] SSRF Guard:', fg='bright_white', bold=True)}      "
        f"{ssrf_status}"
    )
    click.echo(
        f" {click.style('[*] Root CA Path:', fg='bright_white', bold=True)}    "
        f"{click.style(ca_path, fg='bright_black')}"
    )
    click.echo(divider)
    click.echo(
        f" {click.style('Quick Test Command:', fg='bright_white', bold=True)}"
    )
    click.echo(
        f"   {click.style(f'curl -x http://{host}:{port} https://tls.peet.ws/api/all', fg='yellow')}"
    )
    click.echo(sep)
    click.echo("")

    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        click.echo(click.style("\n[*] Shutting down ja4proxy...", fg="yellow"))


@main.command(name="profiles")
def list_profiles() -> None:
    """Lists all supported browser profiles for TLS and HTTP/2 emulation."""
    click.echo(render_banner())
    click.echo(click.style("Available Browser Profiles (JA4 / TLS / HTTP/2):", fg="bright_white", bold=True))
    click.echo("")

    chrome_profs = [p for p in SUPPORTED_PROFILES if p.startswith("chrome")]
    safari_profs = [p for p in SUPPORTED_PROFILES if p.startswith("safari")]
    firefox_profs = [p for p in SUPPORTED_PROFILES if p.startswith("firefox")]

    click.echo(click.style("  Google Chrome / Chromium:", fg="cyan", bold=True))
    for p in chrome_profs:
        tag = click.style(" (Default)", fg="green", bold=True) if p == "chrome_133" else ""
        click.echo(f"    - {p}{tag}")

    click.echo("")
    click.echo(click.style("  Apple Safari & iOS WebKit:", fg="cyan", bold=True))
    for p in safari_profs:
        click.echo(f"    - {p}")

    click.echo("")
    click.echo(click.style("  Mozilla Firefox:", fg="cyan", bold=True))
    for p in firefox_profs:
        click.echo(f"    - {p}")
    click.echo("")


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
    click.echo(render_banner())
    sep = click.style("-" * 72, fg="bright_black")
    click.echo(sep)
    click.echo(f" {click.style('Root CA Certificate:', fg='bright_white', bold=True)} {ca.ca_cert_path}")
    click.echo(f" {click.style('Root CA Private Key:', fg='bright_white', bold=True)} {ca.ca_key_path}")
    click.echo(sep)

    if export_path:
        dest = os.path.abspath(export_path)
        shutil.copyfile(ca.ca_cert_path, dest)
        click.echo(click.style(f"[+] Successfully exported CA to: {dest}", fg="green", bold=True))


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
    click.echo(render_banner())
    click.echo(f"[*] Testing upstream TLS handshake with profile: {click.style(prof, fg='yellow', bold=True)}...")

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
        sep = click.style("-" * 72, fg="bright_black")
        click.echo(sep)
        status_color = "green" if res["status"] == 200 else "red"
        click.echo(f" {click.style('Status Code:', fg='bright_white', bold=True)}        {click.style(str(res['status']), fg=status_color, bold=True)}")
        click.echo(f" {click.style('Negotiated Protocol:', fg='bright_white', bold=True)} {click.style(res['protocol'], fg='cyan')}")

        body = json.loads(res["body"].decode("utf-8", errors="replace"))
        tls_info = body.get("tls", {})
        click.echo(f" {click.style('Remote Peer JA4:', fg='bright_white', bold=True)}     {click.style(str(tls_info.get('ja4')), fg='yellow', bold=True)}")
        click.echo(f" {click.style('Remote Peer JA3:', fg='bright_white', bold=True)}     {tls_info.get('ja3')}")
        click.echo(f" {click.style('HTTP Version:', fg='bright_white', bold=True)}        {body.get('http_version')}")
        click.echo(sep)
    except Exception as e:
        click.echo(click.style(f"Error executing test: {e}", fg="red", bold=True), err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
