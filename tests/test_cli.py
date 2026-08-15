import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from lsm_vps_init import cli
from lsm_vps_init.state import default_state, set_stage
from lsm_vps_init.stages import Context, StageDefinition, StageResult
from lsm_vps_init.util import CommandRunner, PathLayout


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

    def test_status_syncs_reboot_required_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            mock_root = Path(tmp) / "root"
            (mock_root / "etc").mkdir(parents=True)
            (mock_root / "etc" / "os-release").write_text('ID="ubuntu"\nVERSION_ID="24.04"\n', encoding="utf-8")
            (mock_root / "var" / "run").mkdir(parents=True)
            (mock_root / "var" / "run" / "reboot-required").write_text("acceptance-test\n", encoding="utf-8")

            pending = subprocess.run(
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
            self.assertTrue(json.loads(pending.stdout)["reboot"]["pending"])

            (mock_root / "var" / "run" / "reboot-required").unlink()
            cleared = subprocess.run(
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
            reboot = json.loads(cleared.stdout)["reboot"]
            self.assertFalse(reboot["pending"])
            self.assertIsNone(reboot["required_since"])

    def test_status_current_stage_prefers_recorded_blocker_over_stale_detector_gap(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, no_op),
            StageDefinition(16, "docker_hosting_stack", "Docker", lambda _ctx: False, no_op),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            set_stage(state, "ssh_dual_port", "completed")
            set_stage(state, "docker_hosting_stack", "blocked", "missing configuration")
            state["current_stage"] = "ssh_dual_port"
            ctx = Context(layout=layout, state=state, runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)

            output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(output):
                cli.print_status(ctx, as_json=True)

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["current_stage"], "docker_hosting_stack")
        self.assertEqual(payload["blocked"][0]["slug"], "docker_hosting_stack")


if __name__ == "__main__":
    unittest.main()
