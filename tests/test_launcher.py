import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def make_ubuntu_mock_root(base: Path) -> Path:
    mock_root = base / "mock-root"
    (mock_root / "etc").mkdir(parents=True)
    (mock_root / "etc" / "os-release").write_text('ID="ubuntu"\nVERSION_ID="24.04"\n', encoding="utf-8")
    return mock_root


def run_launcher(launcher: Path, args: list[str], *, cwd: Path, env: dict[str, str] | None = None, input_text: str | None = None):
    run_env = os.environ.copy()
    run_env.pop("PYTHONPATH", None)
    if env:
        run_env.update(env)
    return subprocess.run(
        [str(launcher), *args],
        cwd=cwd,
        env=run_env,
        input=input_text,
        text=True,
        capture_output=True,
    )


class LauncherTests(unittest.TestCase):
    def test_source_checkout_launcher_does_not_depend_on_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            state_dir = temp / "state"
            mock_root = make_ubuntu_mock_root(temp)
            result = run_launcher(
                ROOT / "bin" / "lsm-vps-init",
                [
                    "--no-tmux",
                    "--dry-run",
                    "--state-dir",
                    str(state_dir),
                    "--mock-root",
                    str(mock_root),
                    "status",
                    "--json",
                ],
                cwd=temp,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertIn("current_stage", payload)

    def test_installed_launcher_symlink_resolves_app_root_for_core_subcommands(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            install_root = temp / "usr" / "local" / "lib" / "lsm-vps-init"
            sbin = temp / "usr" / "local" / "sbin"
            app_bin = install_root / "bin"
            app_bin.mkdir(parents=True)
            sbin.mkdir(parents=True)
            shutil.copy2(ROOT / "bin" / "lsm-vps-init", app_bin / "lsm-vps-init")
            shutil.copytree(ROOT / "lsm_vps_init", install_root / "lsm_vps_init")
            launcher = sbin / "lsm-vps-init"
            launcher.symlink_to(app_bin / "lsm-vps-init")

            state_dir = temp / "state"
            mock_root = make_ubuntu_mock_root(temp)
            common = ["--no-tmux", "--dry-run", "--state-dir", str(state_dir), "--mock-root", str(mock_root)]

            status = run_launcher(launcher, [*common, "status", "--json"], cwd=temp)
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn("current_stage", json.loads(status.stdout))

            verify = run_launcher(launcher, [*common, "verify-ssh", "--nonce", "nonce-1"], cwd=temp)
            self.assertEqual(verify.returncode, 2)
            self.assertIn("direct root nonce submission is not accepted", verify.stderr)

            state_file = state_dir / "state.json"
            state = json.loads(state_file.read_text(encoding="utf-8"))
            state.setdefault("facts", {})["ssh_recovery_nonce"] = "nonce-1"
            state_file.write_text(json.dumps(state), encoding="utf-8")
            proof = {
                "nonce": "nonce-1",
                "user": "sadmin",
                "local_ssh_port": "65500",
                "publickey_required": True,
                "publickey_auth_verified": True,
                "auth_proof_source": "SSH_USER_AUTH",
                "verified": True,
                "verified_at": "2026-08-14T12:00:00Z",
            }
            record = run_launcher(
                launcher,
                [*common, "record-ssh-proof", "--nonce", "nonce-1"],
                cwd=temp,
                input_text=json.dumps(proof),
            )
            self.assertEqual(record.returncode, 0, record.stderr)
            self.assertIn("SSH recovery checkpoint verified", record.stdout)

            resume = run_launcher(
                launcher,
                [*common, "--until", "bootstrap_installation", "resume"],
                cwd=temp,
            )
            self.assertEqual(resume.returncode, 0, resume.stderr)
            self.assertIn("Loud Sky Media VPS initialization completed successfully.", resume.stdout)

    def test_launcher_fails_clearly_when_package_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            temp = Path(tmp)
            launcher = temp / "lsm-vps-init"
            shutil.copy2(ROOT / "bin" / "lsm-vps-init", launcher)
            result = run_launcher(
                launcher,
                ["--no-tmux", "--dry-run", "status"],
                cwd=temp,
                env={"LSM_VPS_INIT_APP_ROOT": str(temp / "missing-app-root")},
            )
            self.assertEqual(result.returncode, 127)
            self.assertIn("does not contain lsm_vps_init Python package", result.stderr)

    def test_tmux_wrapper_reports_active_blocked_failed_and_success_states(self):
        launcher = (ROOT / "bin" / "lsm-vps-init").read_text(encoding="utf-8")
        self.assertIn("Bootstrap is running inside tmux session", launcher)
        self.assertIn("Bootstrap paused at a required checkpoint.", launcher)
        self.assertIn("Bootstrap stopped because a stage failed.", launcher)
        self.assertIn("Loud Sky Media VPS initialization completed successfully.", launcher)
        self.assertIn("--no-tmux status", launcher)
        self.assertIn("Press Enter to close this tmux pane", launcher)
        self.assertIn("new-session -A -s", launcher)


if __name__ == "__main__":
    unittest.main()
