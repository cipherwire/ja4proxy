import datetime
import ipaddress
import os
import ssl
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

        self._lock = threading.Lock()
        self._leaf_cache: dict[str, ssl.SSLContext] = {}

        self._ensure_ca()

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
            return

        # Generate fresh 2048-bit RSA key for CA
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ja4proxy Development"),
                x509.NameAttribute(NameOID.COMMON_NAME, "ja4proxy Root CA"),
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

            leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            subject_name = x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, clean_host),
                ]
            )

            try:
                ip_addr = ipaddress.ip_address(clean_host)
                san = x509.SubjectAlternativeName([x509.IPAddress(ip_addr)])
            except ValueError:
                san = x509.SubjectAlternativeName([x509.DNSName(clean_host)])

            now = datetime.datetime.now(datetime.timezone.utc)
            leaf_cert = (
                x509.CertificateBuilder()
                .subject_name(subject_name)
                .issuer_name(self.ca_cert.subject)
                .public_key(leaf_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )
                .add_extension(san, critical=False)
                .sign(self.ca_key, hashes.SHA256())
            )

            cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
            key_pem = leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            leaf_cert_path = os.path.join(self.cert_dir, f"_leaf_{clean_host}.pem")
            leaf_key_path = os.path.join(self.cert_dir, f"_leaf_{clean_host}.key")
            with open(leaf_cert_path, "wb") as f:
                f.write(cert_pem)
            with open(leaf_key_path, "wb") as f:
                f.write(key_pem)
            _set_private_file_permissions(leaf_key_path)

            try:
                ctx.load_cert_chain(certfile=leaf_cert_path, keyfile=leaf_key_path)
            finally:
                try:
                    os.remove(leaf_cert_path)
                    os.remove(leaf_key_path)
                except OSError:
                    pass

            self._leaf_cache[clean_host] = ctx
            return ctx
