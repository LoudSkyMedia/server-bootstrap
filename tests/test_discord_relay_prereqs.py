import json
import os
import subprocess
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsm_vps_init.state import default_state
from lsm_vps_init.stages import (
    CODEX_WORK_ROOT,
    RELAY_MODULE,
    Blocked,
    Context,
    Failed,
    _relay_env_updates,
    ensure_relay_native_build_prerequisites,
    prepare_sadmin_user_manager,
    relay_native_build_failure_hint,
    relay_native_build_tool_check_script,
    read_trusted_existing_relay_env_values,
    render_relay_native_build_prerequisite_install_script,
    run_discord_relay_install,
)
from lsm_vps_init.util import CommandError, CommandResult, PathLayout, merge_env_text


def sadmin_args(script):
    wrapped = (
        'export HOME=/home/sadmin; '
        'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
        f"{script}"
    )
    return ("sudo", "-u", "sadmin", "-H", "bash", "-lc", wrapped)


def sadmin_systemd_args(script, uid="4242"):
    wrapped = (
        'export HOME=/home/sadmin; '
        'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
        f"{script}"
    )
    return (
        "sudo",
        "-u",
        "sadmin",
        "-H",
        "env",
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        "bash",
        "-lc",
        wrapped,
    )


CHECK_TOOLS = ("bash", "-lc", relay_native_build_tool_check_script())
INSTALL_BUILD_ESSENTIAL = ("bash", "-lc", render_relay_native_build_prerequisite_install_script())
SADMIN_UID = ("id", "-u", "sadmin")
RELAY_LINGER = ("loginctl", "enable-linger", "sadmin")
RELAY_START_USER_MANAGER = ("systemctl", "start", "user@4242.service")
RELAY_VERIFY_USER_MANAGER = sadmin_systemd_args(
    'test -d "$XDG_RUNTIME_DIR" && test -S "$XDG_RUNTIME_DIR/bus" && systemctl --user is-system-running >/dev/null'
)
RELAY_CLONE = sadmin_args(
    "if [ -d /home/sadmin/codex-vps-discord-relay/.git ]; then "
    "cd /home/sadmin/codex-vps-discord-relay && git pull --ff-only; "
    "else gh repo clone LoudSkyMedia/codex-vps-discord-relay /home/sadmin/codex-vps-discord-relay; fi"
)
RELAY_CHOWN_ENV = ("chown", "sadmin:sadmin", "/home/sadmin/codex-vps-discord-relay/.env")
RELAY_CHMOD = sadmin_args(
    "cd /home/sadmin/codex-vps-discord-relay && chmod +x bin/*.sh bin/preflight.js bin/codex-vps-relay hooks/codex_vps_notify.py"
)
RELAY_INSTALL_SERVICE = sadmin_systemd_args("cd /home/sadmin/codex-vps-discord-relay && bin/install-service.sh")
RELAY_INSTALL_HOOK = sadmin_args("cd /home/sadmin/codex-vps-discord-relay && bin/install-hook.sh")
RELAY_PREFLIGHT = sadmin_systemd_args("cd /home/sadmin/codex-vps-discord-relay && npm run preflight")
RELAY_SERVICE_ACTIVE = sadmin_systemd_args("systemctl --user is-active --quiet codex-vps-discord-relay.service")


VALID_RELAY_ENV = {
    "DISCORD_BOT_TOKEN": "discord-token-placeholder",
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


def user_systemd_commands(uid):
    return (
        ("id", "-u", "sadmin"),
        ("loginctl", "enable-linger", "sadmin"),
        ("systemctl", "start", f"user@{uid}.service"),
        sadmin_systemd_args(
            'test -d "$XDG_RUNTIME_DIR" && test -S "$XDG_RUNTIME_DIR/bus" && systemctl --user is-system-running >/dev/null',
            uid=uid,
        ),
    )


def relay_install_commands(uid, install_response=""):
    uid_cmd, linger, start, verify = user_systemd_commands(uid)
    return [
        (RELAY_CLONE, ""),
        (RELAY_CHOWN_ENV, ""),
        (uid_cmd, uid),
        (linger, ""),
        (start, ""),
        (verify, ""),
        (CHECK_TOOLS, ""),
        (RELAY_CHMOD, ""),
        (sadmin_systemd_args("cd /home/sadmin/codex-vps-discord-relay && bin/install-service.sh", uid=uid), install_response),
        (RELAY_INSTALL_HOOK, ""),
        (sadmin_systemd_args("cd /home/sadmin/codex-vps-discord-relay && npm run preflight", uid=uid), ""),
        (sadmin_systemd_args("systemctl --user is-active --quiet codex-vps-discord-relay.service", uid=uid), ""),
    ]


class PromptRecorder:
    def __init__(self, values):
        self.values = values
        self.secret_prompts = []
        self.text_prompts = []
        self.confirm_prompts = []

    def attach(self, ctx):
        ctx.require_tty = lambda _purpose: None
        ctx.prompt_secret = self.prompt_secret
        ctx.prompt_text = self.prompt_text
        ctx.confirm = self.confirm

    def prompt_secret(self, prompt, *, confirm=True):
        self.secret_prompts.append(prompt)
        if prompt not in self.values:
            raise AssertionError(f"unexpected secret prompt: {prompt}")
        return self.values[prompt]

    def prompt_text(self, prompt, *, default=None, required=True):
        self.text_prompts.append(prompt)
        if prompt in self.values:
            return self.values[prompt]
        if default is not None:
            return default
        if required:
            raise AssertionError(f"unexpected text prompt: {prompt}")
        return ""

    def confirm(self, prompt, *, default=False):
        self.confirm_prompts.append(prompt)
        return default


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


def write_existing_relay_env(ctx, values, *, mode=0o600):
    env_path = ctx.layout.sadmin_home / "codex-vps-discord-relay" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(merge_env_text("", values), encoding="utf-8")
    os.chmod(env_path, mode)
    return env_path


class DiscordRelayPrerequisiteTests(unittest.TestCase):
    def test_user_systemd_env_uses_resolved_uid(self):
        runner = ScriptedRunner([(SADMIN_UID, "4242")])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            env = ctx.sadmin_systemd_env()
        self.assertEqual(env["XDG_RUNTIME_DIR"], "/run/user/4242")
        self.assertEqual(env["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/run/user/4242/bus")

    def test_prepare_user_manager_enables_linger_and_verifies_bus(self):
        runner = ScriptedRunner(
            [
                (SADMIN_UID, "4242"),
                (RELAY_LINGER, ""),
                (RELAY_START_USER_MANAGER, ""),
                (RELAY_VERIFY_USER_MANAGER, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            uid = prepare_sadmin_user_manager(ctx)
        self.assertEqual(uid, "4242")
        self.assertEqual(runner.responses, [])

    def test_prepare_user_manager_is_idempotent_on_resume(self):
        runner = ScriptedRunner(
            [
                (SADMIN_UID, "4242"),
                (RELAY_LINGER, ""),
                (RELAY_START_USER_MANAGER, ""),
                (RELAY_VERIFY_USER_MANAGER, ""),
                (SADMIN_UID, "4242"),
                (RELAY_LINGER, ""),
                (RELAY_START_USER_MANAGER, ""),
                (RELAY_VERIFY_USER_MANAGER, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            prepare_sadmin_user_manager(ctx)
            prepare_sadmin_user_manager(ctx)
        self.assertEqual(runner.responses, [])

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
                (SADMIN_UID, "4242"),
                (RELAY_LINGER, ""),
                (RELAY_START_USER_MANAGER, ""),
                (RELAY_VERIFY_USER_MANAGER, ""),
                (CHECK_TOOLS, ""),
                (RELAY_CHMOD, ""),
                (RELAY_INSTALL_SERVICE, ""),
                (RELAY_INSTALL_HOOK, ""),
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
        self.assertLess(runner.calls.index(RELAY_VERIFY_USER_MANAGER), runner.calls.index(RELAY_INSTALL_SERVICE))
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

    def test_implementation_does_not_hardcode_uid_1000_for_user_bus(self):
        import inspect
        import lsm_vps_init.stages as stages

        implementation = "\n".join(
            [
                inspect.getsource(stages.Context.sadmin_uid),
                inspect.getsource(stages.Context.sadmin_systemd_env),
                inspect.getsource(stages.Context.sadmin_user_systemd_shell),
                inspect.getsource(stages.prepare_sadmin_user_manager),
            ]
        )
        self.assertNotIn("/run/user/1000", implementation)
        self.assertNotIn("user@1000.service", implementation)

    def test_relay_installer_remains_repo_owned_install_service_script(self):
        self.assertIn("bin/install-service.sh", RELAY_INSTALL_SERVICE[-1])

    def test_failed_relay_installer_leaves_reusable_env_and_resume_does_not_reprompt(self):
        uid = str(os.getuid())
        failed_install = CommandResult(
            list(sadmin_systemd_args("cd /home/sadmin/codex-vps-discord-relay && bin/install-service.sh", uid=uid)),
            1,
            "",
            "relay installer failed after npm ci",
        )
        first_runner = ScriptedRunner(relay_install_commands(uid, install_response=failed_install))
        prompts = PromptRecorder(
            {
                "Discord bot token": VALID_RELAY_ENV["DISCORD_BOT_TOKEN"],
                "Discord server/guild ID": VALID_RELAY_ENV["DISCORD_GUILD_ID"],
                "Discord channel ID for the VPS session": VALID_RELAY_ENV["CODEX_VPS_DEFAULT_CHANNEL_ID"],
                "Codex VPS default session ID": VALID_RELAY_ENV["CODEX_VPS_DEFAULT_SESSION_ID"],
                "Comma-separated allowed Discord user IDs": VALID_RELAY_ENV["CODEX_VPS_ALLOWED_USER_IDS"],
                "Comma-separated allowed Discord approver user IDs": VALID_RELAY_ENV["CODEX_VPS_ALLOWED_APPROVER_USER_IDS"],
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, first_runner)
            prompts.attach(ctx)
            with (
                mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0),
                mock.patch("lsm_vps_init.stages.verify_codex_config_defaults"),
            ):
                with self.assertRaises(CommandError):
                    run_discord_relay_install(ctx)
            env_path = ctx.layout.sadmin_home / "codex-vps-discord-relay" / ".env"
            self.assertTrue(env_path.exists())
            self.assertEqual(stat.S_IMODE(env_path.stat().st_mode), 0o600)
            self.assertEqual(prompts.secret_prompts, ["Discord bot token"])
            self.assertIn("Discord server/guild ID", prompts.text_prompts)
            self.assertNotIn(VALID_RELAY_ENV["DISCORD_BOT_TOKEN"], json.dumps(ctx.state))
            self.assertNotIn(VALID_RELAY_ENV["DISCORD_BOT_TOKEN"], "\n".join(first_runner.logs))
            self.assertNotIn(VALID_RELAY_ENV["DISCORD_BOT_TOKEN"], json.dumps(first_runner.calls))

            resume_runner = ScriptedRunner(
                [
                    (RELAY_CLONE, ""),
                    (("id", "-u", "sadmin"), uid),
                    *relay_install_commands(uid)[1:],
                ]
            )
            ctx = make_context(tmp, resume_runner)
            ctx.prompt_secret = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("secret prompted on resume"))
            ctx.prompt_text = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("text prompted on resume"))
            ctx.confirm = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("confirmation prompted on resume"))
            with (
                mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0),
                mock.patch("lsm_vps_init.stages.verify_codex_config_defaults"),
            ):
                result = run_discord_relay_install(ctx)
            self.assertEqual(result.status, "completed")
            self.assertEqual(resume_runner.responses, [])
            self.assertNotIn(VALID_RELAY_ENV["DISCORD_BOT_TOKEN"], json.dumps(ctx.state))
            self.assertNotIn(VALID_RELAY_ENV["DISCORD_BOT_TOKEN"], "\n".join(resume_runner.logs))
            self.assertNotIn(VALID_RELAY_ENV["DISCORD_BOT_TOKEN"], json.dumps(resume_runner.calls))

    def test_incomplete_existing_env_prompts_only_for_missing_values(self):
        uid = str(os.getuid())
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, ScriptedRunner([(("id", "-u", "sadmin"), uid)]))
            existing = dict(VALID_RELAY_ENV)
            existing["CODEX_VPS_DEFAULT_CHANNEL_ID"] = ""
            env_path = write_existing_relay_env(ctx, existing)
            _, values = read_trusted_existing_relay_env_values(ctx, env_path)
            prompts = PromptRecorder({"Discord channel ID for the VPS session": VALID_RELAY_ENV["CODEX_VPS_DEFAULT_CHANNEL_ID"]})
            prompts.attach(ctx)
            updates = _relay_env_updates(ctx, values)
        self.assertEqual(updates["DISCORD_BOT_TOKEN"], VALID_RELAY_ENV["DISCORD_BOT_TOKEN"])
        self.assertEqual(updates["CODEX_VPS_DEFAULT_CHANNEL_ID"], VALID_RELAY_ENV["CODEX_VPS_DEFAULT_CHANNEL_ID"])
        self.assertEqual(prompts.secret_prompts, [])
        self.assertEqual(prompts.text_prompts, ["Discord channel ID for the VPS session"])

    def test_missing_discord_values_can_pause_before_secret_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, ScriptedRunner([]))
            prompts = PromptRecorder({})
            prompts.attach(ctx)
            ctx.confirm = lambda _prompt, default=False: False
            with self.assertRaises(Blocked) as caught:
                _relay_env_updates(ctx, {})
        self.assertIn("Paused before Discord relay configuration", str(caught.exception))
        self.assertEqual(prompts.secret_prompts, [])
        self.assertEqual(prompts.text_prompts, [])

    def test_existing_env_with_unsafe_mode_is_rejected_before_reuse(self):
        uid = str(os.getuid())
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, ScriptedRunner([]))
            env_path = write_existing_relay_env(ctx, VALID_RELAY_ENV, mode=0o644)
            with self.assertRaises(Blocked) as caught:
                read_trusted_existing_relay_env_values(ctx, env_path)
        self.assertIn("mode 0600", str(caught.exception))

    def test_existing_env_with_wrong_owner_is_rejected_before_reuse(self):
        wrong_uid = str(os.getuid() + 1)
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, ScriptedRunner([(("id", "-u", "sadmin"), wrong_uid)]))
            env_path = write_existing_relay_env(ctx, VALID_RELAY_ENV)
            with self.assertRaises(Blocked) as caught:
                read_trusted_existing_relay_env_values(ctx, env_path)
        self.assertIn("owned by sadmin", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
