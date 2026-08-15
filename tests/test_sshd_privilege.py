import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from lsm_vps_init import cli
from lsm_vps_init.state import StateStore, default_state
from lsm_vps_init.stages import (
    SSHD_SADMIN_MATCH_CRITERIA,
    SSH_PORT,
    Blocked,
    Context,
    Failed,
    StageDefinition,
    StageResult,
    detect_final_host_hardening,
    install_managed_ssh_dropin,
    render_ssh_dropin,
    run_ssh_dual_port,
    run_final_host_hardening,
    ssh_checkpoint_proof_from_env,
    sshd_effective_for_sadmin_result,
    sshd_global_effective_config,
    validate_final_sshd_effective_config,
)
from lsm_vps_init.util import CommandError, CommandResult, CommandRunner, PathLayout, secure_write


FINAL_GLOBAL = (
    f"port {SSH_PORT}\n"
    "permitrootlogin no\n"
    "passwordauthentication no\n"
    "pubkeyauthentication yes\n"
)
FINAL_SADMIN = FINAL_GLOBAL + "exposeauthinfo no\n"


def first_value_effective_keywords(config_dir: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in sorted(config_dir.glob("*.conf")):
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#") or " " not in stripped:
                continue
            key, value = stripped.split(None, 1)
            key = key.lower()
            if key not in values:
                values[key] = value.strip()
    return values


class ScriptedRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.logs = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        args = tuple(args)
        self.calls.append(args)
        if not self.responses:
            raise AssertionError(f"unexpected command: {args}")
        expected, response = self.responses.pop(0)
        if args != tuple(expected):
            raise AssertionError(f"expected command {expected}, got {args}")
        if isinstance(response, CommandResult):
            result = response
        else:
            result = CommandResult(list(args), 0, str(response), "")
        if check and result.returncode != 0:
            raise CommandError(result)
        return result


class PrivilegeSensitiveRunner:
    def __init__(self):
        self.calls = []
        self.logs = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        args = tuple(args)
        self.calls.append(args)
        if args[:2] == ("sshd", "-T"):
            result = CommandResult(list(args), 255, "", "/etc/ssh/sshd_config.d/50-cloud-init.conf: Permission denied\n")
        elif args == ("sudo", "-n", "sshd", "-T"):
            result = CommandResult(list(args), 0, FINAL_GLOBAL, "")
        elif args == ("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA):
            result = CommandResult(list(args), 0, FINAL_SADMIN, "")
        elif args == ("ufw", "status"):
            result = CommandResult(list(args), 0, "Status: active\n", "")
        else:
            result = CommandResult(list(args), 0, "", "")
        if check and result.returncode != 0:
            raise CommandError(result)
        return result


def context(tmp, runner) -> Context:
    layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
    state = default_state()
    state["checkpoints"]["ssh_recovery_verified"] = True
    state["checkpoints"]["relay_round_trip_verified"] = True
    state["selected_modules"]["codex-vps-discord-relay"] = False
    state["selected_modules"]["docker-hosting-stack"] = False
    return Context(layout=layout, state=state, runner=runner, dry_run=False, assume_yes=True)


class SshdPrivilegeTests(unittest.TestCase):
    def test_system_sshd_effective_config_uses_sudo_noninteractive(self):
        runner = ScriptedRunner(
            [
                (("sudo", "-n", "sshd", "-T"), FINAL_GLOBAL),
                (("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA), FINAL_SADMIN),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=1000):
                self.assertIn("passwordauthentication no", sshd_global_effective_config(ctx).stdout)
                self.assertIn("exposeauthinfo no", sshd_effective_for_sadmin_result(ctx).stdout)
        self.assertEqual(runner.calls[0], ("sudo", "-n", "sshd", "-T"))
        self.assertEqual(runner.calls[1], ("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA))

    def test_ssh_dual_port_validation_uses_privileged_sshd_commands(self):
        dual_sadmin = "port 22\nport 65500\nexposeauthinfo yes\n"
        runner = ScriptedRunner(
            [
                (("bash", "-lc", mock.ANY), ""),
                (("sudo", "-n", "sshd", "-t"), ""),
                (("sudo", "-n", "sshd", "-t"), ""),
                (("sudo", "-n", "sshd", "-t"), ""),
                (("sudo", "-n", "sshd", "-T"), "port 22\nport 65500\n"),
                (("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA), dual_sadmin),
                (("systemctl", "daemon-reload"), ""),
                (("systemctl", "is-active", "--quiet", "ssh.socket"), CommandResult([], 1, "", "")),
                (("systemctl", "reload", "ssh"), ""),
                (("ss", "-tln"), "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:65500 0.0.0.0:*\n"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0):
                result = run_ssh_dual_port(ctx)
        self.assertEqual(result.status, "completed")
        self.assertIn(("sudo", "-n", "sshd", "-t"), runner.calls)
        self.assertIn(("sudo", "-n", "sshd", "-T"), runner.calls)
        self.assertIn(("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA), runner.calls)
        self.assertNotIn(("sshd", "-T"), runner.calls)

    def test_early_final_dropin_wins_over_cloud_init_password_auth_yes(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            config_dir = layout.map("/etc/ssh/sshd_config.d")
            secure_write(layout.ssh_dropin, render_ssh_dropin("hardened"), 0o644)
            secure_write(config_dir / "50-cloud-init.conf", "PasswordAuthentication yes\n", 0o644)
            secure_write(config_dir / "60-cloudimg-settings.conf", "PasswordAuthentication no\n", 0o644)

            effective = first_value_effective_keywords(config_dir)

        self.assertEqual(effective["port"], SSH_PORT)
        self.assertEqual(effective["permitrootlogin"], "no")
        self.assertEqual(effective["passwordauthentication"], "no")
        self.assertEqual(effective["pubkeyauthentication"], "yes")
        validate_final_sshd_effective_config(FINAL_GLOBAL, FINAL_SADMIN)

    def test_managed_dropin_migrates_legacy_99_file_without_touching_vendor_files(self):
        runner = ScriptedRunner(
            [
                (("sudo", "-n", "sshd", "-t"), ""),
                (("sudo", "-n", "sshd", "-t"), ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            vendor = ctx.layout.map("/etc/ssh/sshd_config.d/50-cloud-init.conf")
            secure_write(vendor, "PasswordAuthentication yes\n", 0o644)
            secure_write(ctx.layout.legacy_ssh_dropin, render_ssh_dropin("dual-port"), 0o644)

            install_managed_ssh_dropin(ctx, "hardened")

            new_text = ctx.layout.ssh_dropin.read_text(encoding="utf-8")
            vendor_text = vendor.read_text(encoding="utf-8")
            legacy_exists = ctx.layout.legacy_ssh_dropin.exists()

        self.assertIn("PasswordAuthentication no", new_text)
        self.assertEqual(vendor_text, "PasswordAuthentication yes\n")
        self.assertFalse(legacy_exists)
        self.assertEqual(runner.calls, [("sudo", "-n", "sshd", "-t"), ("sudo", "-n", "sshd", "-t")])

    def test_managed_dropin_validation_failure_leaves_legacy_file_for_resume(self):
        failed_test = CommandResult(["sudo", "-n", "sshd", "-t"], 1, "", "invalid config")
        runner = ScriptedRunner([(("sudo", "-n", "sshd", "-t"), failed_test)])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            vendor = ctx.layout.map("/etc/ssh/sshd_config.d/50-cloud-init.conf")
            secure_write(vendor, "PasswordAuthentication yes\n", 0o644)
            secure_write(ctx.layout.legacy_ssh_dropin, render_ssh_dropin("dual-port"), 0o644)

            with self.assertRaises(CommandError):
                install_managed_ssh_dropin(ctx, "hardened")

            new_exists = ctx.layout.ssh_dropin.exists()
            legacy_exists = ctx.layout.legacy_ssh_dropin.exists()
            vendor_text = vendor.read_text(encoding="utf-8")

        self.assertTrue(new_exists)
        self.assertTrue(legacy_exists)
        self.assertEqual(vendor_text, "PasswordAuthentication yes\n")

    def test_user_unreadable_sshd_include_does_not_trigger_unprivileged_validation(self):
        runner = PrivilegeSensitiveRunner()
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=1000):
                self.assertTrue(detect_final_host_hardening(ctx))
        self.assertNotIn(("sshd", "-T"), runner.calls)
        self.assertIn(("sudo", "-n", "sshd", "-T"), runner.calls)
        self.assertIn(("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA), runner.calls)

    def test_final_effective_config_requires_root_login_and_password_auth_disabled(self):
        bad_global = (
            f"port {SSH_PORT}\n"
            "permitrootlogin yes\n"
            "passwordauthentication yes\n"
            "pubkeyauthentication yes\n"
        )
        with self.assertRaises(Failed) as caught:
            validate_final_sshd_effective_config(bad_global, FINAL_SADMIN)
        self.assertIn("PermitRootLogin", str(caught.exception))
        self.assertIn("PasswordAuthentication", str(caught.exception))

    def test_final_hardening_fails_before_reload_if_effective_config_is_not_hardened(self):
        pre_sadmin = "port 22\nport 65500\nexposeauthinfo yes\n"
        bad_global = (
            f"port {SSH_PORT}\n"
            "permitrootlogin no\n"
            "passwordauthentication yes\n"
            "pubkeyauthentication yes\n"
        )
        runner = ScriptedRunner(
            [
                (("ss", "-tln"), "LISTEN 0 128 0.0.0.0:65500 0.0.0.0:*\n"),
                (("ufw", "status", "verbose"), "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n22/tcp ALLOW IN Anywhere\n65500/tcp ALLOW IN Anywhere\n"),
                (("bash", "-lc", "command -v docker >/dev/null"), CommandResult([], 1, "", "")),
                (("bash", "-lc", mock.ANY), ""),
                (("sudo", "-n", "sshd", "-t"), ""),
                (("sudo", "-n", "sshd", "-T"), "port 22\nport 65500\n"),
                (("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA), pre_sadmin),
                (("sudo", "-n", "sshd", "-t"), ""),
                (("sudo", "-n", "sshd", "-t"), ""),
                (("sudo", "-n", "sshd", "-T"), bad_global),
                (("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA), FINAL_SADMIN),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            secure_write(ctx.layout.ssh_dropin, render_ssh_dropin("dual-port"), 0o644)
            ctx.confirm = lambda *_args, **_kwargs: True
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0):
                with self.assertRaises(Failed) as caught:
                    run_final_host_hardening(ctx)
        self.assertIn("PasswordAuthentication", str(caught.exception))
        self.assertNotIn(("systemctl", "daemon-reload"), runner.calls)

    def test_ssh_recovery_checkpoint_still_requires_65500_key_only_sadmin_session(self):
        valid_env = {
            "SSH_CONNECTION": "203.0.113.10 52122 159.223.97.195 65500",
            "LSM_VPS_INIT_PUBLICKEY_ONLY": "1",
            "SSH_USER_AUTH": "/tmp/auth-info",
        }
        proof = ssh_checkpoint_proof_from_env(
            nonce="nonce-1",
            env=valid_env,
            username="sadmin",
            auth_reader=lambda _path: "publickey ssh-ed25519 SHA256:example\n",
        )
        self.assertEqual(proof["local_ssh_port"], "65500")
        with self.assertRaises(Blocked):
            ssh_checkpoint_proof_from_env(
                nonce="nonce-1",
                env={**valid_env, "SSH_CONNECTION": "203.0.113.10 52122 159.223.97.195 22"},
                username="sadmin",
                auth_reader=lambda _path: "publickey ssh-ed25519 SHA256:example\n",
            )

    def test_resume_after_validation_failure_clears_failed_stage_on_success(self):
        failure = CommandError(CommandResult(["sudo", "-n", "sshd", "-T"], 255, "", "Permission denied"))

        def detect(_ctx):
            return False

        def fail(_ctx):
            raise failure

        def succeed(_ctx):
            return StageResult("completed", "ok")

        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            store = StateStore(layout.state_file)
            state = store.load()
            ctx = Context(layout=layout, state=state, runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)
            failed_stage = StageDefinition(15, "final_host_hardening", "Final", detect, fail)
            with (
                mock.patch.object(cli, "stage_by_slug", return_value=failed_stage),
                redirect_stderr(StringIO()),
            ):
                self.assertEqual(cli.execute_stage(ctx, store, "final_host_hardening"), "failed")
            self.assertEqual(ctx.state["stages"]["final_host_hardening"]["status"], "failed")

            resumed_state = store.load()
            ctx = Context(layout=layout, state=resumed_state, runner=CommandRunner(layout.log_file, dry_run=True), dry_run=True)
            success_stage = StageDefinition(15, "final_host_hardening", "Final", detect, succeed)
            with (
                mock.patch.object(cli, "stage_by_slug", return_value=success_stage),
                redirect_stdout(StringIO()),
            ):
                self.assertEqual(cli.execute_stage(ctx, store, "final_host_hardening"), "completed")

            final_state = store.load()
            completed = final_state["stages"]["final_host_hardening"]
            current_stage = final_state["current_stage"]
        self.assertEqual(completed["status"], "completed")
        self.assertIsNone(completed["blocked_reason"])
        self.assertIsNone(current_stage)


if __name__ == "__main__":
    unittest.main()
