import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_status_json_reports_unsupported_mock_os_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            mock_root = Path(tmp) / "root"
            (mock_root / "etc").mkdir(parents=True)
            (mock_root / "etc" / "os-release").write_text('ID="debian"\nVERSION_ID="12"\n', encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lsm_vps_init.cli",
                    "--dry-run",
                    "--state-dir",
                    str(state_dir),
                    "--mock-root",
                    str(mock_root),
                    "status",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertEqual(payload["current_stage"], "bootstrap_installation")
            self.assertIn("revalidation", payload)

    def test_direct_root_verify_ssh_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lsm_vps_init.cli",
                    "--state-dir",
                    str(state_dir),
                    "status",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            state_file = state_dir / "state.json"
            data = json.loads(state_file.read_text(encoding="utf-8"))
            data.setdefault("facts", {})["ssh_recovery_nonce"] = "abc123"
            state_file.write_text(json.dumps(data), encoding="utf-8")
            verify = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "lsm_vps_init.cli",
                    "--state-dir",
                    str(state_dir),
                    "verify-ssh",
                    "--nonce",
                    "abc123",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(verify.returncode, 2)
            self.assertIn("direct root nonce submission is not accepted", verify.stderr)
            updated = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertFalse(updated["checkpoints"]["ssh_recovery_verified"])

    def test_wrapper_strips_no_tmux(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    str(ROOT / "bin" / "lsm-vps-init"),
                    "--no-tmux",
                    "--dry-run",
                    "--state-dir",
                    str(Path(tmp) / "state"),
                    "status",
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertIn("current_stage", payload)


if __name__ == "__main__":
    unittest.main()
