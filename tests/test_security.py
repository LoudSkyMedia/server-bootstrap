import tempfile
import unittest
from pathlib import Path
import stat

from lsm_vps_init.security import redact_value, scan_text_for_secret_patterns
from lsm_vps_init.util import CommandRunner, LocalEnvConflict, parse_allowed_local_env, validate_local_env_contract


ROOT = Path(__file__).resolve().parents[1]


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

    def test_known_secret_values_are_redacted_from_child_output_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "bootstrap.log"
            runner = CommandRunner(log_file, dry_run=False)
            hidden = "cloudflare-token-output-placeholder"
            result = runner.run(
                ["python3", "-c", "import os; print(os.environ['HIDDEN_FOR_TEST'])"],
                env={"HIDDEN_FOR_TEST": hidden},
                redact_values=[hidden],
            )
            self.assertIn("[REDACTED]", result.stdout)
            self.assertNotIn(hidden, result.stdout)
            log_text = log_file.read_text(encoding="utf-8")
            self.assertIn("[REDACTED]", log_text)
            self.assertNotIn(hidden, log_text)

    def test_command_timeout_reports_failure_without_hanging(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "bootstrap.log"
            runner = CommandRunner(log_file, dry_run=False)
            result = runner.run(
                ["python3", "-c", "import time; time.sleep(2)"],
                timeout=1,
                check=False,
            )
            self.assertEqual(result.returncode, 124)
            self.assertIn("command timed out", result.stderr)
            self.assertIn("command timed out", log_file.read_text(encoding="utf-8"))

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

    def test_local_env_parser_accepts_only_allowed_keys_without_shell_sourcing(self):
        text = "\n".join(
            [
                "N8N1_VPS_USERNAME=sadmin",
                "N8N1_VPS_SSH_KEY='~/.ssh/lsm_vps_ed25519'",
                "SUDO_PASSWORD='not printed $() ; # value'",
                "UNRELATED_SHOULD_BE_IGNORED=$(echo unsafe)",
            ]
        )
        values = parse_allowed_local_env(text)
        self.assertEqual(values["N8N1_VPS_USERNAME"], "sadmin")
        self.assertEqual(values["N8N1_VPS_SSH_KEY"], "~/.ssh/lsm_vps_ed25519")
        self.assertNotIn("UNRELATED_SHOULD_BE_IGNORED", values)
        validate_local_env_contract(values)

    def test_local_env_contract_rejects_conflicting_canonical_and_fallback_secrets(self):
        with self.assertRaises(LocalEnvConflict):
            validate_local_env_contract(
                {
                    "N8N1_VPS_SUDO_PASSWORD": "canonical-value",
                    "SUDO_PASSWORD": "different-fallback-value",
                }
            )
        with self.assertRaises(LocalEnvConflict):
            validate_local_env_contract(
                {
                    "N8N1_VPS_SSH_KEY": "~/.ssh/lsm_vps_ed25519",
                    "VPS_SSH_IDENTITY_FILE": "~/.ssh/other_key",
                }
            )

    def test_gitignore_and_env_example_keep_local_acceptance_values_out_of_source(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".env", gitignore)
        example = ROOT / ".env.example"
        self.assertTrue(example.exists())
        for line in example.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            key, value = stripped.split("=", 1)
            self.assertTrue(key)
            self.assertEqual(value, "")


if __name__ == "__main__":
    unittest.main()
