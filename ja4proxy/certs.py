import asyncio
import datetime
import ipaddress
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _set_private_file_permissions(path: str) -> None:
    """Restricts file permissions to 0600 on POSIX platforms."""
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


class CertificateAuthority:
    """Manages the local root CA and signs dynamic leaf certificates for HTTPS interception."""

    def __init__(self, cert_dir: str | None = None):
        if cert_dir:
            self.cert_dir = cert_dir
        else:
            self.cert_dir = os.path.join(os.path.expanduser("~"), ".ja4proxy")
        os.makedirs(self.cert_dir, exist_ok=True)

        self.ca_cert_path = os.path.join(self.cert_dir, "ca.pem")
        self.ca_key_path = os.path.join(self.cert_dir, "ca.key")
        self.combined_ca_path = os.path.join(self.cert_dir, "combined_ca.pem")
        self.leaf_key_path = os.path.join(self.cert_dir, "leaf.key")

        self._lock = threading.Lock()
        self._leaf_cache: dict[str, ssl.SSLContext] = {}

        self._ensure_ca()

    def build_combined_ca_bundle(self) -> str:
        """
        Creates or updates a combined CA bundle containing standard Mozilla roots plus ja4proxy CA.
        Safe for use with REQUESTS_CA_BUNDLE and SSL_CERT_FILE without breaking non-proxied internet traffic.
        """
        mozilla_bundle = ""
        try:
            import certifi

            certifi_path = certifi.where()
            if os.path.exists(certifi_path):
                with open(certifi_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                if CERTIFI_TAG_START in content:
                    s = content.find(CERTIFI_TAG_START)
                    e = content.find(CERTIFI_TAG_END) + len(CERTIFI_TAG_END)
                    content = content[:s] + content[e:]
                mozilla_bundle = content.strip()
        except ImportError:
            pass

        with open(self.ca_cert_path, "r", encoding="utf-8") as f:
            ca_pem = f.read().strip()

        combined_content = (
            f"{mozilla_bundle}\n\n{CERTIFI_TAG_START}\n{ca_pem}\n{CERTIFI_TAG_END}\n"
            if mozilla_bundle
            else f"{CERTIFI_TAG_START}\n{ca_pem}\n{CERTIFI_TAG_END}\n"
        )
        with open(self.combined_ca_path, "w", encoding="utf-8") as f:
            f.write(combined_content)
        return self.combined_ca_path

    def _ensure_ca(self) -> None:
        """Loads existing CA certificate/key or generates a fresh 10-year root CA."""
        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            _set_private_file_permissions(self.ca_key_path)
            self._ensure_leaf_key()
            self.build_combined_ca_bundle()
            return

        # Generate fresh 2048-bit RSA key for CA
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        default_dir = os.path.join(os.path.expanduser("~"), ".ja4proxy")
        if os.path.abspath(self.cert_dir) != os.path.abspath(default_dir):
            import hashlib

            short_id = hashlib.sha256(self.cert_dir.encode("utf-8")).hexdigest()[:8]
            common_name = f"ja4proxy Root CA ({short_id})"
        else:
            common_name = "ja4proxy Root CA"

        ca_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ja4proxy Development"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        with open(self.ca_key_path, "wb") as f:
            f.write(
                self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        _set_private_file_permissions(self.ca_key_path)

        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        self._ensure_leaf_key()
        self.build_combined_ca_bundle()

    def _ensure_leaf_key(self) -> None:
        """Ensures a persistent 2048-bit RSA leaf private key exists for high-speed signing."""
        if os.path.exists(self.leaf_key_path):
            with open(self.leaf_key_path, "rb") as f:
                self.leaf_key = serialization.load_pem_private_key(f.read(), password=None)
            _set_private_file_permissions(self.leaf_key_path)
            return

        self.leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(self.leaf_key_path, "wb") as f:
            f.write(
                self.leaf_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        _set_private_file_permissions(self.leaf_key_path)

    def get_ssl_context_for_host(self, host: str) -> ssl.SSLContext:
        """
        Dynamically generates or retrieves a cached SSLContext for the target hostname,
        signed by this CA with appropriate Subject Alternative Names (SAN).
        """
        h = host.strip()
        if h.startswith("["):
            end = h.find("]")
            clean_host = h[1:end] if end != -1 else h
        elif ":" in h:
            parts = h.split(":")
            clean_host = parts[0] if len(parts) == 2 else h
        else:
            clean_host = h

        with self._lock:
            if clean_host in self._leaf_cache:
                return self._leaf_cache[clean_host]

            subject_name = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, clean_host),
                ]
            )

            san_items = []
            try:
                ip_addr = ipaddress.ip_address(clean_host)
                san_items.append(x509.IPAddress(ip_addr))
            except ValueError:
                san_items.append(x509.DNSName(clean_host))
                parts = clean_host.split(".")
                if len(parts) >= 3 and not clean_host.startswith("*."):
                    parent_domain = ".".join(parts[1:])
                    if len(parts[-1]) >= 2:
                        san_items.append(x509.DNSName(f"*.{parent_domain}"))

            san = x509.SubjectAlternativeName(san_items)

            now = datetime.datetime.now(datetime.timezone.utc)
            leaf_cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(self.ca_cert.subject)
                .public_key(self.leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=2))
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )
                .add_extension(san, critical=False)
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=True,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
                    critical=False,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(self.leaf_key.public_key()),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                    critical=False,
                )
                .sign(self.ca_key, hashes.SHA256())
            )

            cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            with tempfile.NamedTemporaryFile("wb", suffix=".pem", dir=self.cert_dir, delete=False) as tf:
                tf.write(cert_pem)
                temp_cert_path = tf.name

            try:
                ctx.load_cert_chain(certfile=temp_cert_path, keyfile=self.leaf_key_path)
            finally:
                try:
                    os.remove(temp_cert_path)
                except OSError:
                    pass

            if len(self._leaf_cache) >= 2000:
                oldest_key = next(iter(self._leaf_cache))
                del self._leaf_cache[oldest_key]

            self._leaf_cache[clean_host] = ctx
            return ctx

    async def get_ssl_context_for_host_async(self, host: str) -> ssl.SSLContext:
        """Asynchronously retrieves or generates an SSLContext without blocking the event loop."""
        h = host.strip()
        if h.startswith("["):
            end = h.find("]")
            clean_host = h[1:end] if end != -1 else h
        elif ":" in h:
            parts = h.split(":")
            clean_host = parts[0] if len(parts) == 2 else h
        else:
            clean_host = h

        with self._lock:
            if clean_host in self._leaf_cache:
                return self._leaf_cache[clean_host]

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.get_ssl_context_for_host, host)


CERTIFI_TAG_START = "# --- ja4proxy Root CA START ---"
CERTIFI_TAG_END = "# --- ja4proxy Root CA END ---"


def install_certifi_ca(ca_cert_path: str) -> tuple[bool, str]:
    """
    Appends the ja4proxy Root CA to Python's certifi certificate bundle if installed.
    Allows requests, urllib3, and httpx to verify intercepted HTTPS requests with zero configuration.
    """
    try:
        import certifi
    except ImportError:
        return False, "certifi package not installed in Python environment (skipped)."

    certifi_path = certifi.where()
    if not os.path.exists(certifi_path):
        return False, f"certifi bundle not found at {certifi_path}"

    with open(ca_cert_path, "r", encoding="utf-8") as f:
        ca_pem = f.read().strip()

    with open(certifi_path, "r", encoding="utf-8", errors="replace") as f:
        bundle_content = f.read()

    if CERTIFI_TAG_START in bundle_content:
        if ca_pem in bundle_content:
            return True, f"ja4proxy Root CA already trusted in certifi ({certifi_path})."
        # If an existing (older or different) ja4proxy cert is present, replace it
        start_idx = bundle_content.find(CERTIFI_TAG_START)
        end_idx = bundle_content.find(CERTIFI_TAG_END) + len(CERTIFI_TAG_END)
        bundle_content = (bundle_content[:start_idx] + bundle_content[end_idx:]).rstrip()

    new_content = (
        bundle_content.rstrip()
        + "\n\n"
        + CERTIFI_TAG_START
        + "\n"
        + ca_pem
        + "\n"
        + CERTIFI_TAG_END
        + "\n"
    )

    try:
        with open(certifi_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return True, f"Successfully appended ja4proxy Root CA to certifi bundle ({certifi_path})."
    except Exception as e:
        return False, f"Failed to write to certifi bundle: {e}"


def uninstall_certifi_ca() -> tuple[bool, str]:
    """
    Removes the ja4proxy Root CA from Python's certifi certificate bundle.
    """
    try:
        import certifi
    except ImportError:
        return False, "certifi package not installed in Python environment (skipped)."

    certifi_path = certifi.where()
    if not os.path.exists(certifi_path):
        return False, f"certifi bundle not found at {certifi_path}"

    with open(certifi_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    if CERTIFI_TAG_START not in content:
        return True, "ja4proxy Root CA is not present in certifi bundle."

    start_idx = content.find(CERTIFI_TAG_START)
    end_idx = content.find(CERTIFI_TAG_END) + len(CERTIFI_TAG_END)
    cleaned = (content[:start_idx] + content[end_idx:]).rstrip() + "\n"

    try:
        with open(certifi_path, "w", encoding="utf-8") as f:
            f.write(cleaned)
        return True, f"Successfully removed ja4proxy Root CA from certifi bundle ({certifi_path})."
    except Exception as e:
        return False, f"Failed to update certifi bundle: {e}"


def install_system_ca(ca_cert_path: str) -> tuple[bool, str]:
    """
    Installs the ja4proxy Root CA into the operating system certificate trust store.
    Supports Windows (certutil), Linux (update-ca-certificates / update-ca-trust), and macOS (security).
    """
    if not os.path.exists(ca_cert_path):
        return False, f"CA certificate file not found: {ca_cert_path}"

    if os.name == "nt":
        # Windows Current User Root Store
        cmd = ["certutil", "-user", "-addstore", "-f", "Root", ca_cert_path]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return True, "Added ja4proxy Root CA to Windows Certificate Store (Trusted Root Certification Authorities)."
            return False, f"Windows certutil command returned code {res.returncode}: {res.stderr or res.stdout}"
        except subprocess.TimeoutExpired:
            return False, "Windows certutil prompted for desktop confirmation. Please run in an interactive terminal to click Yes."
        except Exception as e:
            return False, f"Windows certutil execution failed: {e}"

    # Linux trust stores
    if os.path.exists("/usr/local/share/ca-certificates"):
        dest = "/usr/local/share/ca-certificates/ja4proxy-ca.crt"
        try:
            shutil.copyfile(ca_cert_path, dest)
            res = subprocess.run(["update-ca-certificates"], capture_output=True, text=True)
            if res.returncode == 0:
                return True, f"Installed to {dest} and updated system CA certificates."
            return False, f"update-ca-certificates failed: {res.stderr or res.stdout}"
        except PermissionError:
            return False, "Permission denied installing to /usr/local/share/ca-certificates. Please run with sudo: sudo ja4proxy ca install"
        except Exception as e:
            return False, f"Linux CA installation failed: {e}"

    if os.path.exists("/etc/pki/ca-trust/source/anchors"):
        dest = "/etc/pki/ca-trust/source/anchors/ja4proxy-ca.crt"
        try:
            shutil.copyfile(ca_cert_path, dest)
            res = subprocess.run(["update-ca-trust", "extract"], capture_output=True, text=True)
            if res.returncode == 0:
                return True, f"Installed to {dest} and extracted ca-trust."
            return False, f"update-ca-trust failed: {res.stderr or res.stdout}"
        except PermissionError:
            return False, "Permission denied installing to /etc/pki/ca-trust. Please run with sudo: sudo ja4proxy ca install"
        except Exception as e:
            return False, f"Linux CA installation failed: {e}"

    # macOS Keychain
    if os.path.exists("/Library/Keychains/System.keychain"):
        cmd = [
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            ca_cert_path,
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                return True, "Added ja4proxy Root CA to macOS System Keychain."
            return False, f"macOS security command failed: {res.stderr or res.stdout}"
        except Exception as e:
            return False, f"macOS Keychain installation failed: {e}"

    return False, "Unsupported platform for automatic OS CA installation. Please import ~/.ja4proxy/ca.pem manually."


def uninstall_system_ca() -> tuple[bool, str]:
    """
    Uninstalls the ja4proxy Root CA from the operating system certificate trust store.
    """
    if os.name == "nt":
        cmd = ["certutil", "-user", "-delstore", "Root", "ja4proxy Root CA"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                return True, "Removed ja4proxy Root CA from Windows Certificate Store."
            return False, f"Windows certutil delstore failed: {res.stderr or res.stdout}"
        except Exception as e:
            return False, f"Windows certutil delstore failed: {e}"

    removed = False
    for dest, cmd in [
        ("/usr/local/share/ca-certificates/ja4proxy-ca.crt", ["update-ca-certificates", "--fresh"]),
        ("/etc/pki/ca-trust/source/anchors/ja4proxy-ca.crt", ["update-ca-trust", "extract"]),
    ]:
        if os.path.exists(dest):
            try:
                os.remove(dest)
                subprocess.run(cmd, capture_output=True, text=True)
                removed = True
            except PermissionError:
                return False, f"Permission denied removing {dest}. Please run with sudo: sudo ja4proxy ca uninstall"
            except Exception as e:
                return False, f"Failed removing {dest}: {e}"

    if removed:
        return True, "Removed ja4proxy Root CA from Linux system trust store."

    if os.path.exists("/Library/Keychains/System.keychain"):
        cmd = [
            "security",
            "delete-certificate",
            "-c",
            "ja4proxy Root CA",
            "/Library/Keychains/System.keychain",
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                return True, "Removed ja4proxy Root CA from macOS System Keychain."
            return False, f"macOS security delete-certificate failed: {res.stderr or res.stdout}"
        except Exception as e:
            return False, f"macOS Keychain uninstallation failed: {e}"

    return False, "ja4proxy Root CA was not found in system trust stores."


def install_ca(ca_cert_path: str | None = None) -> list[str]:
    """
    Installs the ja4proxy Root CA into both OS and Python certifi trust stores.
    """
    if not ca_cert_path:
        ca = CertificateAuthority()
        ca_cert_path = ca.ca_cert_path

    messages = []
    # 1. System store
    ok_sys, msg_sys = install_system_ca(ca_cert_path)
    prefix_sys = "[+]" if ok_sys else "[-]"
    messages.append(f"{prefix_sys} System Store: {msg_sys}")

    # 2. Python certifi store
    ok_certifi, msg_certifi = install_certifi_ca(ca_cert_path)
    prefix_certifi = "[+]" if ok_certifi else "[-]"
    messages.append(f"{prefix_certifi} Python certifi: {msg_certifi}")

    return messages


def uninstall_ca() -> list[str]:
    """
    Uninstalls the ja4proxy Root CA from both OS and Python certifi trust stores.
    """
    messages = []
    ok_sys, msg_sys = uninstall_system_ca()
    prefix_sys = "[+]" if ok_sys else "[-]"
    messages.append(f"{prefix_sys} System Store: {msg_sys}")

    ok_certifi, msg_certifi = uninstall_certifi_ca()
    prefix_certifi = "[+]" if ok_certifi else "[-]"
    messages.append(f"{prefix_certifi} Python certifi: {msg_certifi}")

    return messages


def get_ca_cert_path(cert_dir: str | None = None) -> str:
    """Returns the absolute filesystem path to the ja4proxy Root CA certificate (ca.pem)."""
    ca = CertificateAuthority(cert_dir=cert_dir)
    return ca.ca_cert_path


def get_ca_bundle_path(cert_dir: str | None = None) -> str:
    """Returns the absolute filesystem path to the combined CA bundle (combined_ca.pem)."""
    ca = CertificateAuthority(cert_dir=cert_dir)
    return ca.build_combined_ca_bundle()


def inject_trust(cert_dir: str | None = None) -> str:
    """
    Enables ja4proxy CA trust in the active Python process.
    Configures environment variables, requests adapters, and native truststore if present.
    Returns the path to the active combined CA bundle.
    """
    bundle_path = get_ca_bundle_path(cert_dir=cert_dir)
    ca_path = get_ca_cert_path(cert_dir=cert_dir)

    os.environ["REQUESTS_CA_BUNDLE"] = bundle_path
    os.environ["CURL_CA_BUNDLE"] = bundle_path
    os.environ["SSL_CERT_FILE"] = bundle_path
    os.environ["NODE_EXTRA_CA_CERTS"] = ca_path

    if "requests.adapters" in sys.modules:
        setattr(sys.modules["requests.adapters"], "DEFAULT_CA_BUNDLE_PATH", bundle_path)
    if "requests.utils" in sys.modules and hasattr(sys.modules["requests.utils"], "DEFAULT_CA_BUNDLE_PATH"):
        setattr(sys.modules["requests.utils"], "DEFAULT_CA_BUNDLE_PATH", bundle_path)

    try:
        import truststore

        truststore.inject_into_ssl()
    except (ImportError, AttributeError):
        pass

    return bundle_path
