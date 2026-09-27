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
from lsm_vps_init.stages import (
    DOCKER_MODULE,
    RELAY_MODULE,
    SSHD_SADMIN_MATCH_CRITERIA,
    SSH_PORT,
    Context,
    StageDefinition,
    StageResult,
    stage_by_slug as real_stage_by_slug,
)
from lsm_vps_init.util import CommandResult, CommandRunner, PathLayout


ROOT = Path(__file__).resolve().parents[1]
FINAL_GLOBAL = (
    f"port {SSH_PORT}\n"
    "permitrootlogin no\n"
    "passwordauthentication no\n"
    "pubkeyauthentication yes\n"
)
FINAL_SADMIN = FINAL_GLOBAL + "exposeauthinfo no\n"
BAD_PASSWORD_GLOBAL = (
    f"port {SSH_PORT}\n"
    "permitrootlogin no\n"
    "passwordauthentication yes\n"
    "pubkeyauthentication yes\n"
)
PRE_GLOBAL = (
    "port 22\n"
    "permitrootlogin no\n"
    "passwordauthentication no\n"
    "pubkeyauthentication yes\n"
)
PRE_SADMIN = PRE_GLOBAL + "exposeauthinfo yes\n"
DUAL_GLOBAL = (
    "port 22\n"
    f"port {SSH_PORT}\n"
    "permitrootlogin no\n"
    "passwordauthentication no\n"
    "pubkeyauthentication yes\n"
)
DUAL_SADMIN = DUAL_GLOBAL + "exposeauthinfo yes\n"
SSH_65500_LISTENER = "LISTEN 0 128 0.0.0.0:65500 0.0.0.0:*\n"
DUAL_LISTENER = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n" + SSH_65500_LISTENER
FINAL_UFW_WITH_STALE_WEB = (
    "Status: active\n"
    "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
    "65500/tcp ALLOW IN Anywhere\n"
    "80/tcp ALLOW IN Anywhere\n"
    "443/tcp ALLOW IN Anywhere\n"
)
FINAL_UFW_WITH_443_ONLY = (
    "Status: active\n"
    "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
    "65500/tcp ALLOW IN Anywhere\n"
    "443/tcp ALLOW IN Anywhere\n"
)
FINAL_UFW_STANDALONE = (
    "Status: active\n"
    "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
    "65500/tcp ALLOW IN Anywhere\n"
)
PHASE_A_UFW = (
    "Status: active\n"
    "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
    "22/tcp ALLOW IN Anywhere\n"
    "65500/tcp ALLOW IN Anywhere\n"
)
INACTIVE_UFW = "Status: inactive\n"
STAGED_PHASE_A_UFW = (
    "Added user rules (see 'ufw status' for running firewall):\n"
    "ufw allow 22/tcp\n"
    "ufw allow 65500/tcp\n"
)


class LegacyFinalSshRunner:
    def __init__(
        self,
        *,
        ufw_status: str = FINAL_UFW_WITH_STALE_WEB,
        global_config: str = FINAL_GLOBAL,
        sadmin_config: str = FINAL_SADMIN,
        listeners: str = SSH_65500_LISTENER,
    ):
        self.ufw_status = ufw_status
        self.global_config = global_config
        self.sadmin_config = sadmin_config
        self.listeners = listeners
        self.calls: list[tuple[str, ...]] = []
        self.logs: list[str] = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        args = tuple(args)
        self.calls.append(args)
        if args == ("sudo", "-n", "sshd", "-T"):
            return CommandResult(list(args), 0, self.global_config, "")
        if args == ("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA):
            return CommandResult(list(args), 0, self.sadmin_config, "")
        if args == ("ss", "-tln"):
            return CommandResult(list(args), 0, self.listeners, "")
        if args == ("ufw", "status", "verbose"):
            return CommandResult(list(args), 0, self.ufw_status, "")
        if args == ("bash", "-lc", "command -v docker >/dev/null"):
            return CommandResult(list(args), 1, "", "")
        if args == ("ufw", "allow", f"{SSH_PORT}/tcp"):
            return CommandResult(list(args), 0, "", "")
        if args == ("ufw", "delete", "allow", "80/tcp"):
            self.ufw_status = FINAL_UFW_WITH_443_ONLY
            return CommandResult(list(args), 0, "", "")
        if args == ("ufw", "delete", "allow", "443/tcp"):
            self.ufw_status = FINAL_UFW_STANDALONE
            return CommandResult(list(args), 0, "", "")
        if args == ("ufw", "--force", "enable"):
            return CommandResult(list(args), 0, "", "")
        raise AssertionError(f"unexpected command: {args}")


class PreHardeningRunner:
    def __init__(self):
        self.ufw_status = INACTIVE_UFW
        self.global_checks = 0
        self.listener_checks = 0
        self.calls: list[tuple[str, ...]] = []
        self.logs: list[str] = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        args = tuple(args)
        self.calls.append(args)
        if args == ("sudo", "-n", "sshd", "-T"):
            self.global_checks += 1
            config = PRE_GLOBAL if self.global_checks <= 2 else DUAL_GLOBAL
            return CommandResult(list(args), 0, config, "")
        if args == ("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA):
            config = PRE_SADMIN if self.global_checks <= 2 else DUAL_SADMIN
            return CommandResult(list(args), 0, config, "")
        if args == ("ss", "-tln"):
            self.listener_checks += 1
            listeners = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n" if self.listener_checks <= 2 else DUAL_LISTENER
            return CommandResult(list(args), 0, listeners, "")
        if args == ("ufw", "status", "verbose"):
            return CommandResult(list(args), 0, self.ufw_status, "")
        if args == ("bash", "-lc", "command -v docker >/dev/null"):
            return CommandResult(list(args), 1, "", "")
        if args[:2] == ("bash", "-lc") and "sshd_config.bak" in args[2]:
            return CommandResult(list(args), 0, "", "")
        if args == ("sudo", "-n", "sshd", "-t"):
            return CommandResult(list(args), 0, "", "")
        if args == ("systemctl", "daemon-reload"):
            return CommandResult(list(args), 0, "", "")
        if args == ("systemctl", "is-active", "--quiet", "ssh.socket"):
            return CommandResult(list(args), 1, "", "")
        if args == ("systemctl", "reload", "ssh"):
            return CommandResult(list(args), 0, "", "")
        if args == ("apt-get", "install", "-y", "ufw"):
            return CommandResult(list(args), 0, "", "")
        if args == ("ufw", "default", "deny", "incoming"):
            return CommandResult(list(args), 0, "", "")
        if args == ("ufw", "default", "allow", "outgoing"):
            return CommandResult(list(args), 0, "", "")
        if args == ("ufw", "allow", "22/tcp"):
            return CommandResult(list(args), 0, "", "")
        if args == ("ufw", "allow", f"{SSH_PORT}/tcp"):
            return CommandResult(list(args), 0, "", "")
        if args == ("ufw", "show", "added"):
            return CommandResult(list(args), 0, STAGED_PHASE_A_UFW, "")
        if args == ("ufw", "--force", "enable"):
            self.ufw_status = PHASE_A_UFW
            return CommandResult(list(args), 0, "", "")
        raise AssertionError(f"unexpected command: {args}")


def real_stage_subset(*slugs: str) -> list[StageDefinition]:
    return [real_stage_by_slug(slug) for slug in slugs]


def fake_stage_lookup(stages: list[StageDefinition]):
    def lookup(slug):
        for stage in stages:
            if stage.slug == slug or str(stage.index) == str(slug):
                return stage
        raise KeyError(slug)

    return lookup


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
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, no_op, ("final_host_hardening",)),
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

    def test_status_labels_failed_records_as_failed_not_blocked(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        fake_stages = [
            StageDefinition(10, "codex_install_auth", "Codex", lambda _ctx: False, no_op),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            set_stage(state, "codex_install_auth", "failed", "command failed with 124")
            ctx = Context(layout=layout, state=state, runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)

            output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(output):
                cli.print_status(ctx, as_json=False)

        text = output.getvalue()
        self.assertIn("10 codex_install_auth: failed", text)
        self.assertIn("    failed: command failed with 124", text)
        self.assertNotIn("    blocked: command failed with 124", text)

    def test_resume_retries_previously_failed_codex_stage(self):
        calls = []

        def repair(_ctx):
            calls.append("codex")
            return StageResult("completed", "repaired")

        fake_stages = [
            StageDefinition(10, "codex_install_auth", "Codex", lambda _ctx: False, repair),
        ]

        def fake_stage_by_slug(slug):
            return fake_stages[0]

        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            store = cli.StateStore(layout.state_file)
            state = store.load()
            set_stage(state, "codex_install_auth", "failed", "old installer failed")
            store.save(state)
            ctx = Context(layout=layout, state=store.load(), runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)

            with mock.patch.object(cli, "STAGES", fake_stages), mock.patch.object(cli, "stage_by_slug", fake_stage_by_slug):
                result = cli.run_stages(ctx, store)
            updated = store.load()

        self.assertEqual(result, 0)
        self.assertEqual(calls, ["codex"])
        self.assertEqual(updated["stages"]["codex_install_auth"]["status"], "completed")

    def test_status_reports_complete_when_transitional_stages_are_superseded_by_final_hardening(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(6, "firewall_phase_a", "Firewall Phase A", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(15, "final_host_hardening", "Final", lambda _ctx: True, no_op),
            StageDefinition(16, "docker_hosting_stack", "Docker", lambda _ctx: True, no_op),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            state["reboot"]["pending"] = False
            state["revalidation"]["boot_changed"] = True
            for stage in fake_stages:
                set_stage(state, stage.slug, "completed")
            state["current_stage"] = "ssh_dual_port"
            ctx = Context(layout=layout, state=state, runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)

            output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(output):
                cli.print_status(ctx, as_json=True)
            text_output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(text_output):
                cli.print_status(ctx, as_json=False)

        payload = json.loads(output.getvalue())
        self.assertIsNone(payload["current_stage"])
        self.assertIn("Current stage: complete", text_output.getvalue())
        self.assertFalse(payload["reboot"]["pending"])
        self.assertTrue(payload["revalidation"]["boot_changed"])
        self.assertEqual(payload["pending"], [])
        self.assertIn("ssh_dual_port", payload["completed"])
        self.assertIn("firewall_phase_a", payload["completed"])

    def test_stage_status_marks_transitional_stages_satisfied_by_supersession(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(6, "firewall_phase_a", "Firewall Phase A", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(15, "final_host_hardening", "Final", lambda _ctx: True, no_op),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            for stage in fake_stages:
                set_stage(state, stage.slug, "completed")
            ctx = Context(layout=layout, state=state, runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)

            with mock.patch.object(cli, "STAGES", fake_stages):
                rows = cli.stage_status(ctx)

        dual = next(row for row in rows if row["slug"] == "ssh_dual_port")
        firewall = next(row for row in rows if row["slug"] == "firewall_phase_a")
        self.assertFalse(dual["detected"])
        self.assertTrue(dual["superseded"])
        self.assertTrue(dual["satisfied"])
        self.assertFalse(firewall["detected"])
        self.assertTrue(firewall["superseded"])
        self.assertTrue(firewall["satisfied"])

    def test_resume_after_full_hardening_skips_superseded_stages_and_does_not_rerun_temporary_phases(self):
        run_calls = []

        def forbidden_run(_ctx):
            run_calls.append("temporary")
            raise AssertionError("temporary stage reran after final hardening")

        def final_run(_ctx):
            run_calls.append("final")
            return StageResult("completed", "final rerun")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, forbidden_run, ("final_host_hardening",)),
            StageDefinition(6, "firewall_phase_a", "Firewall Phase A", lambda _ctx: False, forbidden_run, ("final_host_hardening",)),
            StageDefinition(15, "final_host_hardening", "Final", lambda _ctx: True, final_run),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            store = cli.StateStore(layout.state_file)
            state = store.load()
            for stage in fake_stages:
                set_stage(state, stage.slug, "completed")
            state["current_stage"] = "ssh_dual_port"
            store.save(state)
            ctx = Context(layout=layout, state=store.load(), runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)

            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(StringIO()):
                exit_code = cli.run_stages(ctx, store)
            final_state = store.load()

        self.assertEqual(exit_code, 0)
        self.assertEqual(run_calls, [])
        self.assertIsNone(final_state["current_stage"])

    def test_legacy_hardened_resume_skips_transition_reconciles_firewall_and_continues(self):
        docker_calls = []

        def docker_continue(_ctx):
            docker_calls.append("docker")
            return StageResult("completed", "docker continued")

        stages = [
            *real_stage_subset("ssh_dual_port", "firewall_phase_a", "final_host_hardening"),
            StageDefinition(16, "docker_hosting_stack", "Docker", lambda _ctx: False, docker_continue),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            store = cli.StateStore(layout.state_file)
            state = store.load()
            state["checkpoints"]["ssh_recovery_verified"] = True
            state["selected_modules"][DOCKER_MODULE] = True
            state["selected_modules"][RELAY_MODULE] = False
            state["facts"]["docker_hosting_mode"] = "standalone-app"
            set_stage(state, "ssh_dual_port", "completed")
            set_stage(state, "firewall_phase_a", "completed")
            set_stage(state, "ssh_recovery_checkpoint", "completed")
            set_stage(state, "final_host_hardening", "blocked", "legacy stale web rules")
            set_stage(state, "docker_hosting_stack", "blocked", "legacy validator failure")
            state["current_stage"] = "docker_hosting_stack"
            store.save(state)

            status_ctx = Context(layout=layout, state=json.loads(json.dumps(state)), runner=LegacyFinalSshRunner(), dry_run=False)
            status_output = StringIO()
            with mock.patch.object(cli, "STAGES", stages), mock.patch.object(cli, "stage_by_slug", side_effect=fake_stage_lookup(stages)), redirect_stdout(status_output):
                cli.print_status(status_ctx, as_json=True)
            status_payload = json.loads(status_output.getvalue())
            self.assertEqual(status_payload["current_stage"], "final_host_hardening")
            self.assertIn("ssh_dual_port", status_payload["completed"])
            self.assertIn("firewall_phase_a", status_payload["completed"])

            runner = LegacyFinalSshRunner()
            ctx = Context(layout=layout, state=store.load(), runner=runner, dry_run=False, assume_yes=True)
            with (
                mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0),
                mock.patch.object(cli, "STAGES", stages),
                mock.patch.object(cli, "stage_by_slug", side_effect=fake_stage_lookup(stages)),
                redirect_stdout(StringIO()),
            ):
                exit_code = cli.run_stages(ctx, store)
            final_state = store.load()
            dropin_exists = layout.ssh_dropin.exists()

        self.assertEqual(exit_code, 0)
        self.assertEqual(docker_calls, ["docker"])
        self.assertEqual(final_state["stages"]["final_host_hardening"]["status"], "completed")
        self.assertEqual(final_state["stages"]["docker_hosting_stack"]["status"], "completed")
        self.assertIsNone(final_state["current_stage"])
        self.assertIn(("ufw", "delete", "allow", "80/tcp"), runner.calls)
        self.assertIn(("ufw", "delete", "allow", "443/tcp"), runner.calls)
        self.assertNotIn(("ufw", "allow", "22/tcp"), runner.calls)
        self.assertNotIn(("sudo", "-n", "sshd", "-t"), runner.calls)
        self.assertFalse(any(call[:2] == ("bash", "-lc") and "sshd_config.bak" in call[2] for call in runner.calls))
        self.assertFalse(dropin_exists)

    def test_legacy_hardened_resume_skips_transition_when_final_stage_failed_or_boot_changed(self):
        for final_status, boot_changed in (("failed", False), ("blocked", True)):
            with self.subTest(final_status=final_status, boot_changed=boot_changed), tempfile.TemporaryDirectory() as tmp:
                stages = real_stage_subset("ssh_dual_port", "firewall_phase_a", "final_host_hardening")
                layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
                store = cli.StateStore(layout.state_file)
                state = store.load()
                state["checkpoints"]["ssh_recovery_verified"] = True
                state["selected_modules"][DOCKER_MODULE] = True
                state["selected_modules"][RELAY_MODULE] = False
                state["facts"]["docker_hosting_mode"] = "standalone-app"
                state["revalidation"]["boot_changed"] = boot_changed
                set_stage(state, "ssh_dual_port", "completed")
                set_stage(state, "firewall_phase_a", "completed")
                set_stage(state, "ssh_recovery_checkpoint", "completed")
                set_stage(state, "final_host_hardening", final_status, "legacy stale web rules")
                store.save(state)

                runner = LegacyFinalSshRunner()
                ctx = Context(layout=layout, state=store.load(), runner=runner, dry_run=False, assume_yes=True)
                with (
                    mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0),
                    mock.patch.object(cli, "STAGES", stages),
                    mock.patch.object(cli, "stage_by_slug", side_effect=fake_stage_lookup(stages)),
                    redirect_stdout(StringIO()),
                ):
                    exit_code = cli.run_stages(ctx, store)

                self.assertEqual(exit_code, 0)
                self.assertEqual(store.load()["stages"]["final_host_hardening"]["status"], "completed")
                self.assertIn(("ufw", "delete", "allow", "80/tcp"), runner.calls)
                self.assertIn(("ufw", "delete", "allow", "443/tcp"), runner.calls)
                self.assertNotIn(("ufw", "allow", "22/tcp"), runner.calls)
                self.assertNotIn(("sudo", "-n", "sshd", "-t"), runner.calls)

    def test_completed_hardened_host_keeps_transitional_stages_superseded_idempotently(self):
        stages = real_stage_subset("ssh_dual_port", "firewall_phase_a", "final_host_hardening")
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            store = cli.StateStore(layout.state_file)
            state = store.load()
            state["checkpoints"]["ssh_recovery_verified"] = True
            state["selected_modules"][DOCKER_MODULE] = True
            state["selected_modules"][RELAY_MODULE] = False
            state["facts"]["docker_hosting_mode"] = "standalone-app"
            for slug in ("ssh_dual_port", "firewall_phase_a", "ssh_recovery_checkpoint", "final_host_hardening"):
                set_stage(state, slug, "completed")
            store.save(state)

            runner = LegacyFinalSshRunner(ufw_status=FINAL_UFW_STANDALONE)
            ctx = Context(layout=layout, state=store.load(), runner=runner, dry_run=False, assume_yes=True)
            with (
                mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0),
                mock.patch.object(cli, "STAGES", stages),
                mock.patch.object(cli, "stage_by_slug", side_effect=fake_stage_lookup(stages)),
                redirect_stdout(StringIO()),
            ):
                exit_code = cli.run_stages(ctx, store)

        self.assertEqual(exit_code, 0)
        self.assertNotIn(("ufw", "allow", "22/tcp"), runner.calls)
        self.assertNotIn(("ufw", "delete", "allow", "80/tcp"), runner.calls)
        self.assertNotIn(("sudo", "-n", "sshd", "-t"), runner.calls)

    def test_genuine_pre_hardening_resume_still_runs_transition_and_phase_a(self):
        stages = real_stage_subset("ssh_dual_port", "firewall_phase_a")
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            store = cli.StateStore(layout.state_file)
            state = store.load()
            state["checkpoints"]["ssh_recovery_verified"] = False
            state["selected_modules"][DOCKER_MODULE] = False
            state["selected_modules"][RELAY_MODULE] = False
            store.save(state)

            runner = PreHardeningRunner()
            ctx = Context(layout=layout, state=store.load(), runner=runner, dry_run=False, assume_yes=True)
            with (
                mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0),
                mock.patch.object(cli, "STAGES", stages),
                mock.patch.object(cli, "stage_by_slug", side_effect=fake_stage_lookup(stages)),
                mock.patch.dict("lsm_vps_init.stages.os.environ", {"SSH_CONNECTION": "203.0.113.10 52000 198.51.100.20 22"}, clear=False),
                redirect_stdout(StringIO()),
            ):
                exit_code = cli.run_stages(ctx, store)
            dropin = layout.ssh_dropin.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertIn(("ufw", "allow", "22/tcp"), runner.calls)
        self.assertIn(("ufw", "allow", f"{SSH_PORT}/tcp"), runner.calls)
        self.assertIn(("sudo", "-n", "sshd", "-t"), runner.calls)
        self.assertIn("Port 22", dropin)
        self.assertIn(f"Port {SSH_PORT}", dropin)

    def test_ambiguous_missing_recovery_or_relay_state_does_not_supersede_transition(self):
        stage = real_stage_by_slug("ssh_dual_port")
        scenarios = [
            {"ssh_recovery": False, "relay": False, "global_config": FINAL_GLOBAL},
            {"ssh_recovery": True, "relay": False, "global_config": BAD_PASSWORD_GLOBAL},
            {"ssh_recovery": True, "relay": True, "global_config": FINAL_GLOBAL},
        ]
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
                state = default_state()
                state["checkpoints"]["ssh_recovery_verified"] = scenario["ssh_recovery"]
                state["selected_modules"][DOCKER_MODULE] = False
                state["selected_modules"][RELAY_MODULE] = scenario["relay"]
                if scenario["relay"]:
                    state["checkpoints"]["relay_round_trip_verified"] = False
                ctx = Context(
                    layout=layout,
                    state=state,
                    runner=LegacyFinalSshRunner(global_config=scenario["global_config"]),
                    dry_run=False,
                    assume_yes=True,
                )
                self.assertFalse(cli.stage_superseded(ctx, stage))

    def test_completed_final_hardening_regression_is_reported_at_final_stage_not_temporary_phases(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(6, "firewall_phase_a", "Firewall Phase A", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(15, "final_host_hardening", "Final", lambda _ctx: False, no_op),
            StageDefinition(16, "docker_hosting_stack", "Docker", lambda _ctx: True, no_op),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            for stage in fake_stages:
                set_stage(state, stage.slug, "completed")
            ctx = Context(layout=layout, state=state, runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)

            output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(output):
                cli.print_status(ctx, as_json=True)
                rows = cli.stage_status(ctx)

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["current_stage"], "final_host_hardening")
        self.assertIn("final_host_hardening", [row["slug"] for row in rows])

    def test_active_blocker_still_takes_precedence_over_full_completion(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(15, "final_host_hardening", "Final", lambda _ctx: True, no_op),
            StageDefinition(16, "docker_hosting_stack", "Docker", lambda _ctx: True, no_op),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            set_stage(state, "ssh_dual_port", "completed")
            set_stage(state, "final_host_hardening", "completed")
            set_stage(state, "docker_hosting_stack", "blocked", "operator review required")
            ctx = Context(layout=layout, state=state, runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)

            output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(output):
                cli.print_status(ctx, as_json=True)

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["current_stage"], "docker_hosting_stack")


if __name__ == "__main__":
    unittest.main()
