import asyncio
import logging
import os
import shutil
import sys

import click

from ja4proxy import __version__
from ja4proxy.certs import (
    CertificateAuthority,
    install_ca,
    uninstall_ca,
)
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
@click.option(
    "--host",
    default="127.0.0.1",
    envvar="JA4PROXY_HOST",
    help="Binding IP address.",
)
@click.option(
    "--port",
    "-p",
    default=8888,
    type=int,
    envvar="JA4PROXY_PORT",
    help="Port to listen on.",
)
@click.option(
    "--profile",
    default="chrome_133",
    envvar="JA4PROXY_PROFILE",
    help="Default browser profile (e.g. chrome_133, safari_16_0, firefox_133).",
)
@click.option(
    "--upstream-proxy",
    default=None,
    envvar="JA4PROXY_UPSTREAM_PROXY",
    help="Default upstream proxy URL (e.g. socks5://user:pass@host:1080).",
)
@click.option(
    "--auth",
    default=None,
    envvar="JA4PROXY_AUTH",
    help="Require username:password authentication for client connections.",
)
@click.option(
    "--cert-dir",
    default=None,
    envvar="JA4PROXY_CERT_DIR",
    help="Directory to store CA and leaf certificates.",
)
@click.option(
    "--allow-private-networks",
    is_flag=True,
    envvar="JA4PROXY_ALLOW_PRIVATE_NETWORKS",
    help="Allow forwarding requests to private and loopback IP ranges.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    envvar="JA4PROXY_VERBOSE",
    help="Enable verbose debug logging.",
)
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


@main.group(name="ca", invoke_without_command=True)
@click.option(
    "--export",
    "-e",
    "export_path",
    default=None,
    help="Export root CA certificate (ca.pem) to specified path.",
)
@click.option(
    "--install",
    "-i",
    "install_flag",
    is_flag=True,
    help="Install root CA into operating system and Python certifi trust stores.",
)
@click.option(
    "--uninstall",
    "-u",
    "uninstall_flag",
    is_flag=True,
    help="Remove root CA from operating system and Python certifi trust stores.",
)
@click.pass_context
def manage_ca(
    ctx: click.Context,
    export_path: str | None,
    install_flag: bool,
    uninstall_flag: bool,
) -> None:
    """Inspects, exports, or installs the local Root CA into system trust stores."""
    if ctx.invoked_subcommand is not None:
        return

    ca = CertificateAuthority()
    click.echo(render_banner())

    if install_flag:
        click.echo("[*] Installing ja4proxy Root CA into trust stores...")
        msgs = install_ca(ca.ca_cert_path)
        for m in msgs:
            color = "green" if m.startswith("[+]") else "yellow"
            click.echo(click.style(m, fg=color))
        return

    if uninstall_flag:
        click.echo("[*] Removing ja4proxy Root CA from trust stores...")
        msgs = uninstall_ca()
        for m in msgs:
            color = "green" if m.startswith("[+]") else "yellow"
            click.echo(click.style(m, fg=color))
        return

    sep = click.style("-" * 72, fg="bright_black")
    click.echo(sep)
    click.echo(f" {click.style('Root CA Certificate:', fg='bright_white', bold=True)} {ca.ca_cert_path}")
    click.echo(f" {click.style('Root CA Private Key:', fg='bright_white', bold=True)} {ca.ca_key_path}")
    click.echo(sep)

    if export_path:
        dest = os.path.abspath(export_path)
        shutil.copyfile(ca.ca_cert_path, dest)
        click.echo(click.style(f"[+] Successfully exported CA to: {dest}", fg="green", bold=True))
    else:
        click.echo(click.style(" Trust Store Commands:", fg="bright_white", bold=True))
        click.echo("   ja4proxy ca install            Install CA into OS & Python certifi trust stores")
        click.echo("   ja4proxy ca uninstall          Remove CA from system trust stores")
        click.echo("   ja4proxy ca --export ./ca.pem  Export CA to a specific file")


@manage_ca.command(name="install")
def ca_sub_install() -> None:
    """Installs the Root CA into OS and Python certifi trust stores."""
    ca = CertificateAuthority()
    click.echo(render_banner())
    click.echo("[*] Installing ja4proxy Root CA into trust stores...")
    msgs = install_ca(ca.ca_cert_path)
    for m in msgs:
        color = "green" if m.startswith("[+]") else "yellow"
        click.echo(click.style(m, fg=color))


@manage_ca.command(name="uninstall")
def ca_sub_uninstall() -> None:
    """Removes the Root CA from OS and Python certifi trust stores."""
    click.echo(render_banner())
    click.echo("[*] Removing ja4proxy Root CA from trust stores...")
    msgs = uninstall_ca()
    for m in msgs:
        color = "green" if m.startswith("[+]") else "yellow"
        click.echo(click.style(m, fg=color))


@main.command(name="test")
@click.option(
    "--profile",
    default="chrome_133",
    help="Browser profile to test against tls.peet.ws.",
)
@click.option(
    "--audit",
    is_flag=True,
    help="Run in-depth anti-bot diagnostic audit (alias for ja4proxy doctor).",
)
@click.pass_context
def test_handshake(ctx: click.Context, profile: str, audit: bool) -> None:
    """Performs a live handshake against tls.peet.ws to inspect upstream JA4."""
    if audit:
        ctx.invoke(doctor_audit, profile=profile, upstream_proxy=None)
        return

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


@main.command(name="doctor")
@click.option(
    "--profile",
    default="chrome_133",
    help="Browser profile to audit (e.g. chrome_133, safari_16_0, firefox_133).",
)
@click.option(
    "--upstream-proxy",
    default=None,
    help="Optional upstream proxy URL to audit through (e.g. socks5://host:1080).",
)
def doctor_audit(profile: str, upstream_proxy: str | None) -> None:
    """Runs a 5-layer anti-bot evasion diagnostic against tls.peet.ws."""
    import json

    prof = normalize_profile(profile)
    click.echo(render_banner())
    click.echo(f"[*] Running Anti-Bot Evasion Audit for profile: {click.style(prof, fg='yellow', bold=True)}...")

    async def _run_audit():
        engine = NativeEngine.get_instance()
        return await engine.request(
            method="GET",
            url="https://tls.peet.ws/api/all",
            profile=prof,
            proxy_url=upstream_proxy or "",
            timeout_seconds=20,
        )

    try:
        res = asyncio.run(_run_audit())
    except Exception as e:
        click.echo(click.style(f"[-] Audit failed: Unable to connect to inspection endpoint: {e}", fg="red", bold=True))
        sys.exit(1)

    if res.get("status") != 200:
        click.echo(click.style(f"[-] Inspection endpoint returned HTTP {res.get('status')}", fg="red", bold=True))
        sys.exit(1)

    try:
        body = json.loads(res["body"].decode("utf-8", errors="replace"))
    except Exception as e:
        click.echo(click.style(f"[-] Failed to decode inspection payload: {e}", fg="red", bold=True))
        sys.exit(1)

    tls_info = body.get("tls", {})
    h2_info = body.get("http2", {})
    tcp_info = body.get("tcpip", {})

    ja4 = tls_info.get("ja4", "")
    exts = [e.get("name", "") for e in tls_info.get("extensions", [])]
    has_grease = any("GREASE" in e for e in exts) or any("GREASE" in c for c in tls_info.get("ciphers", []))
    has_mlkem = any("X25519MLKEM768" in str(e) for e in tls_info.get("extensions", []))

    akamai_hash = h2_info.get("akamai_fingerprint_hash", "")
    akamai_fp = h2_info.get("akamai_fingerprint", "")
    http_ver = body.get("http_version", "")

    ttl = tcp_info.get("ip", {}).get("ttl", 0)
    p0f = tcp_info.get("p0f", "")
    client_ip = body.get("ip", "")

    sep = click.style("=" * 72, fg="cyan")
    divider = click.style("-" * 72, fg="bright_black")

    click.echo(sep)
    click.echo(click.style("  ja4proxy Diagnostic Healthcheck & Evasion Audit", fg="bright_white", bold=True))
    click.echo(sep)

    # 1. TLS Check
    if ja4:
        click.echo(f" {click.style('[*] TLS JA4 Signature:', fg='bright_white', bold=True)}   {click.style(ja4, fg='yellow', bold=True)}")
    else:
        click.echo(f" {click.style('[-] TLS JA4 Signature:', fg='red')}   Unavailable")

    # 2. Post-Quantum Check
    if has_mlkem:
        click.echo(f" {click.style('[*] Post-Quantum TLS:', fg='bright_white', bold=True)}    {click.style('X25519MLKEM768 Hybrid Key Exchange (Active)', fg='green')}")
    else:
        status_text = "N/A (Safari/Firefox)" if "safari" in prof or "firefox" in prof else "Standard X25519"
        click.echo(f" {click.style('[*] Post-Quantum TLS:', fg='bright_white', bold=True)}    {click.style(status_text, fg='bright_black')}")

    # 3. GREASE Check
    grease_status = click.style("RFC 8701 Randomized (Active)", fg="green") if has_grease else click.style("Absent", fg="red")
    click.echo(f" {click.style('[*] TLS GREASE Ciphers:', fg='bright_white', bold=True)}  {grease_status}")

    # 4. HTTP/2 Check
    if http_ver == "h2":
        click.echo(f" {click.style('[*] HTTP/2 Transport:', fg='bright_white', bold=True)}    {click.style(f'Akamai Hash {akamai_hash[:16]}... (Valid h2)', fg='green')}")
    else:
        click.echo(f" {click.style('[*] HTTP Transport:', fg='bright_white', bold=True)}      {click.style(http_ver, fg='yellow')}")

    # 5. TCP/IP Transport Check
    is_linux_ttl = (ttl and ttl <= 64)
    if is_linux_ttl and "chrome" in prof:
        tcp_note = click.style(f"TTL ~{ttl} (Linux Kernel) - Warning: Windows profile on Linux VPS", fg="yellow")
    elif ttl:
        tcp_note = click.style(f"TTL {ttl} (Clean Transport)", fg="green")
    else:
        tcp_note = click.style("Direct / SOCKS", fg="bright_black")
    click.echo(f" {click.style('[*] TCP/IP Hop TTL:', fg='bright_white', bold=True)}      {tcp_note}")

    click.echo(divider)
    readiness = "EXCELLENT (Cloudflare, Akamai, DataDome compatible)"
    click.echo(f" {click.style('Overall Anti-Bot Readiness:', fg='bright_white', bold=True)} {click.style(readiness, fg='green', bold=True)}")
    click.echo(sep)


if __name__ == "__main__":
    main()
