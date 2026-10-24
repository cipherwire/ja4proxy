import os
import shutil
import tempfile
import unittest

from ja4proxy.certs import CertificateAuthority


class TestCertificateAuthority(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.ca = CertificateAuthority(cert_dir=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ca_creation(self):
        self.assertTrue(os.path.exists(self.ca.ca_cert_path))
        self.assertTrue(os.path.exists(self.ca.ca_key_path))
        self.assertEqual(self.ca.ca_cert.issuer, self.ca.ca_cert.subject)

    def test_leaf_cert_generation(self):
        ctx1 = self.ca.get_ssl_context_for_host("tls.peet.ws")
        self.assertIsNotNone(ctx1)

        # Verify caching works and returns identical context
        ctx2 = self.ca.get_ssl_context_for_host("tls.peet.ws")
        self.assertIs(ctx1, ctx2)

    def test_leaf_cert_ip_address(self):
        ctx = self.ca.get_ssl_context_for_host("127.0.0.1")
        self.assertIsNotNone(ctx)


if __name__ == "__main__":
    unittest.main()
