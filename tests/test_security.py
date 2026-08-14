import tempfile
import unittest
from pathlib import Path
import stat

from lsm_vps_init.security import redact_value, scan_text_for_secret_patterns
from lsm_vps_init.util import CommandRunner


class SecurityTests(unittest.TestCase):
    def test_secret_stdin_is_redacted_from_command_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "bootstrap.log"
            runner = CommandRunner(log_file, dry_run=True)
            hidden = "complex secret value with $ and ; characters"
            runner.run(["sudo", "-S", "-p", "", "-v"], input_text=hidden + "\n", secret_stdin=True)
            log_text = log_file.read_text(encoding="utf-8")
            self.assertIn("<stdin: redacted>", log_text)
            self.assertNotIn(hidden, log_text)
            self.assertEqual(stat.S_IMODE(log_file.stat().st_mode), 0o600)

    def test_secret_stdin_is_redacted_on_failed_command_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "bootstrap.log"
            runner = CommandRunner(log_file, dry_run=False)
            hidden = "failure path secret value"
            result = runner.run(
                ["python3", "-c", "import sys; sys.exit(7)"],
                input_text=hidden + "\n",
                secret_stdin=True,
                check=False,
            )
            self.assertEqual(result.returncode, 7)
            log_text = log_file.read_text(encoding="utf-8")
            self.assertIn("<stdin: redacted>", log_text)
            self.assertNotIn(hidden, log_text)
            self.assertEqual(stat.S_IMODE(log_file.stat().st_mode), 0o600)

    def test_secret_scanner_and_redactor_cover_public_risk_patterns(self):
        text = "\n".join(
            [
                "github=ghp_" + ("A" * 32),
                "openai=sk-" + ("B" * 24),
                "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            ]
        )
        findings = scan_text_for_secret_patterns(text)
        self.assertIn("github_token", findings)
        self.assertIn("openai_key", findings)
        self.assertIn("private_key", findings)
        self.assertNotIn("ghp_" + ("A" * 32), redact_value(text))
        self.assertNotIn("sk-" + ("B" * 24), redact_value(text))


if __name__ == "__main__":
    unittest.main()
