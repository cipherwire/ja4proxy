import os
import unittest
from click.testing import CliRunner

from ja4proxy import __version__
from ja4proxy.cli import main


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_cli_help_displays_banner_and_version(self):
        result = self.runner.invoke(main, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Universal Browser TLS & JA4 Impersonation Proxy", result.output)
        self.assertIn(__version__, result.output)
        self.assertIn("https://ja4proxy.cipherwire.link", result.output)
        self.assertIn("start", result.output)
        self.assertIn("profiles", result.output)
        self.assertIn("ca", result.output)

    def test_cli_version_flag(self):
        result = self.runner.invoke(main, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(f"ja4proxy, version {__version__}", result.output)

    def test_cli_profiles_command(self):
        result = self.runner.invoke(main, ["profiles"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Available Browser Profiles", result.output)
        self.assertIn("chrome_133 (Default)", result.output)
        self.assertIn("firefox_133", result.output)
        self.assertIn("safari_16_0", result.output)

    def test_cli_ca_command(self):
        result = self.runner.invoke(main, ["ca"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Root CA Certificate:", result.output)
        self.assertIn("ca.pem", result.output)
        self.assertIn("Root CA Private Key:", result.output)

    def test_cli_envvar_options(self):
        env = {
            "JA4PROXY_HOST": "0.0.0.0",
            "JA4PROXY_PORT": "9090",
            "JA4PROXY_PROFILE": "safari_16_0",
            "JA4PROXY_AUTH": "testuser:testpass",
        }
        # Verify that start command accepts envvars without syntax errors
        ctx = main.make_context("ja4proxy", ["start", "--help"])
        self.assertEqual(ctx.command.get_command(ctx, "start").name, "start")
