import base64
import unittest

from ja4proxy.parser import extract_directives, parse_credentials


class TestParser(unittest.TestCase):
    def test_parse_credentials_empty(self):
        d = parse_credentials("")
        self.assertIsNone(d.profile)
        self.assertIsNone(d.session_id)
        self.assertIsNone(d.upstream_proxy)
        self.assertIsNone(d.timeout)

    def test_parse_credentials_tags(self):
        d = parse_credentials("user-profile_safari16-session_9921-timeout_45")
        self.assertEqual(d.profile, "safari_16_0")
        self.assertEqual(d.session_id, "9921")
        self.assertEqual(d.timeout, 45)

    def test_parse_credentials_proxy_with_hyphens(self):
        d = parse_credentials(
            "user-profile_firefox133-proxy_http://my-user:p-a-s-s@res-gate.io:8000-session_worker-01"
        )
        self.assertEqual(d.profile, "firefox_133")
        self.assertEqual(d.upstream_proxy, "http://my-user:p-a-s-s@res-gate.io:8000")
        self.assertEqual(d.session_id, "worker-01")

    def test_extract_directives_from_headers(self):
        headers = {
            "Host": "api.example.com",
            "X-JA4-Profile": "firefox",
            "X-JA4-Session": "session_foo",
            "Proxy-Connection": "keep-alive",
            "User-Agent": "test-agent",
        }
        d, clean = extract_directives(headers)
        self.assertEqual(d.profile, "firefox_133")
        self.assertEqual(d.session_id, "session_foo")
        self.assertNotIn("X-JA4-Profile", clean)
        self.assertNotIn("Proxy-Connection", clean)
        self.assertIn("User-Agent", clean)

    def test_extract_directives_priority_header_over_auth(self):
        raw_auth = base64.b64encode(
            b"user-profile_safari16-session_888:secret"
        ).decode()
        headers = {
            "Host": "example.com",
            "Proxy-Authorization": f"Basic {raw_auth}",
            "X-JA4-Profile": "chrome_133",
        }
        d, clean = extract_directives(headers)
        # Explicit header must win over auth credentials
        self.assertEqual(d.profile, "chrome_133")
        self.assertEqual(d.session_id, "888")
        self.assertNotIn("Proxy-Authorization", clean)


if __name__ == "__main__":
    unittest.main()
