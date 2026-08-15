import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsm_vps_init.state import default_state
from lsm_vps_init.stages import (
    CODEX_WORK_ROOT,
    RELAY_MODULE,
    Context,
    Failed,
    ensure_relay_native_build_prerequisites,
    relay_native_build_failure_hint,
    relay_native_build_tool_check_script,
    render_relay_native_build_prerequisite_install_script,
    run_discord_relay_install,
)
from lsm_vps_init.util import CommandError, CommandResult, PathLayout


def sadmin_args(script):
    wrapped = (
        'export HOME=/home/sadmin; '
        'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
        f"{script}"
    )
    return ("sudo", "-u", "sadmin", "-H", "bash", "-lc", wrapped)


CHECK_TOOLS = ("bash", "-lc", relay_native_build_tool_check_script())
INSTALL_BUILD_ESSENTIAL = ("bash", "-lc", render_relay_native_build_prerequisite_install_script())
RELAY_CLONE = sadmin_args(
    "if [ -d /home/sadmin/codex-vps-discord-relay/.git ]; then "
    "cd /home/sadmin/codex-vps-discord-relay && git pull --ff-only; "
    "else gh repo clone LoudSkyMedia/codex-vps-discord-relay /home/sadmin/codex-vps-discord-relay; fi"
)
RELAY_CHOWN_ENV = ("chown", "sadmin:sadmin", "/home/sadmin/codex-vps-discord-relay/.env")
RELAY_CHMOD = sadmin_args(
    "cd /home/sadmin/codex-vps-discord-relay && chmod +x bin/*.sh bin/preflight.js bin/codex-vps-relay hooks/codex_vps_notify.py"
)
RELAY_INSTALL_SERVICE = sadmin_args("cd /home/sadmin/codex-vps-discord-relay && bin/install-service.sh")
RELAY_INSTALL_HOOK = sadmin_args("cd /home/sadmin/codex-vps-discord-relay && bin/install-hook.sh")
RELAY_LINGER = ("loginctl", "enable-linger", "sadmin")
RELAY_PREFLIGHT = sadmin_args("cd /home/sadmin/codex-vps-discord-relay && npm run preflight")
RELAY_SERVICE_ACTIVE = sadmin_args("systemctl --user is-active --quiet codex-vps-discord-relay.service")


VALID_RELAY_ENV = {
    "DISCORD_GUILD_ID": "100000000000000000",
    "CODEX_VPS_DEFAULT_CHANNEL_ID": "100000000000000001",
    "CODEX_VPS_ALLOWED_USER_IDS": "100000000000000002",
    "CODEX_VPS_ALLOWED_APPROVER_USER_IDS": "100000000000000003",
    "CODEX_VPS_DEFAULT_SESSION_ID": "00000000-0000-4000-8000-000000000001",
    "CODEX_VPS_ROOT": CODEX_WORK_ROOT,
    "CODEX_VPS_ENGINE": "exec",
    "CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX": "true",
    "CODEX_VPS_SKIP_GIT_REPO_CHECK": "true",
}


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


def make_context(tmp, runner, *, relay_selected=True):
    layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
    state = default_state()
    state["selected_modules"][RELAY_MODULE] = relay_selected
    state["facts"]["codex_session_id"] = "00000000-0000-4000-8000-000000000001"
    return Context(layout=layout, state=state, runner=runner, dry_run=False)


class DiscordRelayPrerequisiteTests(unittest.TestCase):
    def test_relay_selected_missing_tools_installs_build_essential_then_validates(self):
        missing = CommandResult(list(CHECK_TOOLS), 1, "", "")
        runner = ScriptedRunner([(CHECK_TOOLS, missing), (INSTALL_BUILD_ESSENTIAL, ""), (CHECK_TOOLS, "")])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ensure_relay_native_build_prerequisites(ctx)
        self.assertIn("apt-get install -y build-essential", INSTALL_BUILD_ESSENTIAL[2])
        self.assertEqual(runner.calls, [CHECK_TOOLS, INSTALL_BUILD_ESSENTIAL, CHECK_TOOLS])
        self.assertEqual(runner.responses, [])

    def test_relay_selected_tools_already_present_skips_build_essential_install(self):
        runner = ScriptedRunner([(CHECK_TOOLS, "")])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ensure_relay_native_build_prerequisites(ctx)
        self.assertEqual(runner.calls, [CHECK_TOOLS])
        self.assertEqual(runner.responses, [])

    def test_rendered_prerequisite_install_script_is_valid_bash(self):
        subprocess.run(
            ["bash", "-n"],
            input=render_relay_native_build_prerequisite_install_script(),
            text=True,
            check=True,
            capture_output=True,
        )

    def test_relay_not_selected_does_not_install_toolchain(self):
        runner = ScriptedRunner([])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner, relay_selected=False)
            result = run_discord_relay_install(ctx)
        self.assertEqual(result.status, "completed")
        self.assertEqual(runner.calls, [])

    def test_relay_installer_executes_only_after_prerequisite_validation(self):
        runner = ScriptedRunner(
            [
                (RELAY_CLONE, ""),
                (RELAY_CHOWN_ENV, ""),
                (CHECK_TOOLS, ""),
                (RELAY_CHMOD, ""),
                (RELAY_INSTALL_SERVICE, ""),
                (RELAY_INSTALL_HOOK, ""),
                (RELAY_LINGER, ""),
                (RELAY_PREFLIGHT, ""),
                (RELAY_SERVICE_ACTIVE, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            with (
                mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0),
                mock.patch("lsm_vps_init.stages._relay_env_updates", return_value=VALID_RELAY_ENV),
                mock.patch("lsm_vps_init.stages.verify_codex_config_defaults"),
            ):
                result = run_discord_relay_install(ctx)
        self.assertEqual(result.status, "completed")
        self.assertLess(runner.calls.index(CHECK_TOOLS), runner.calls.index(RELAY_INSTALL_SERVICE))
        self.assertEqual(runner.responses, [])

    def test_failed_native_prerequisite_install_can_be_retried(self):
        missing = CommandResult(list(CHECK_TOOLS), 1, "", "")
        failed_install = CommandResult(list(INSTALL_BUILD_ESSENTIAL), 1, "", "apt failed")
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, ScriptedRunner([(CHECK_TOOLS, missing), (INSTALL_BUILD_ESSENTIAL, failed_install)]))
            with self.assertRaises(Failed) as caught:
                ensure_relay_native_build_prerequisites(ctx)
            self.assertIn("resume", str(caught.exception))

            ctx = make_context(tmp, ScriptedRunner([(CHECK_TOOLS, "")]))
            ensure_relay_native_build_prerequisites(ctx)

    def test_native_dependency_build_failure_gets_specific_message(self):
        output = "better-sqlite3 11.10.0\nNo prebuilt binary found\ngyp ERR! Error: not found: make\n"
        hint = relay_native_build_failure_hint(CommandResult([], 1, output, ""))
        self.assertIsNotNone(hint)
        self.assertIn("native Node dependency", hint)
        self.assertIn("make", hint)


if __name__ == "__main__":
    unittest.main()
