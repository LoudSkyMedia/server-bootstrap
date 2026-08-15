import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsm_vps_init.state import default_state
from lsm_vps_init.stages import (
    REQUIRED_CODEX_MODEL,
    REQUIRED_CODEX_REASONING,
    Context,
    codex_bypass_flag_check_script,
    codex_install_script,
    codex_install_validation_script,
    codex_model_availability_check_script,
    run_codex_install_auth,
)
from lsm_vps_init.util import CommandError, CommandResult, PathLayout


def sadmin_args(script):
    wrapped = (
        'export HOME=/home/sadmin; '
        'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
        f"{script}"
    )
    return ("sudo", "-u", "sadmin", "-H", "bash", "-lc", wrapped)


VALIDATION = sadmin_args(codex_install_validation_script())
INSTALL = sadmin_args(codex_install_script())
LOGIN_STATUS = sadmin_args("codex login status")
LOGIN_DEVICE = sadmin_args("codex login --device-auth")
BYPASS_FLAG_CHECK = sadmin_args(codex_bypass_flag_check_script())
MODEL_CHECK = sadmin_args(codex_model_availability_check_script())
CHOWN_NPM = ("chown", "-R", "sadmin:sadmin", "/home/sadmin/.npm-global")
CHOWN_CODEX = ("chown", "-R", "sadmin:sadmin", "/home/sadmin/.codex")


class ScriptedRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.interactive_calls = []
        self.logs = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        self.calls.append(tuple(args))
        return self._next(args, check)

    def run_interactive(self, args, *, check=True, **_kwargs):
        self.interactive_calls.append(tuple(args))
        return self._next(args, check)

    def _next(self, args, check):
        if not self.responses:
            raise AssertionError(f"unexpected command: {args}")
        expected, response = self.responses.pop(0)
        if tuple(args) != tuple(expected):
            raise AssertionError(f"expected command {expected}, got {tuple(args)}")
        result = response if isinstance(response, CommandResult) else CommandResult(list(args), 0, str(response), "")
        if check and result.returncode != 0:
            raise CommandError(result)
        return result


def make_context(tmp, runner):
    layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
    return Context(layout=layout, state=default_state(), runner=runner, dry_run=False)


class CodexInstallTests(unittest.TestCase):
    def test_codex_uses_openai_codex_npm_package_not_old_installer(self):
        script = codex_install_script()
        self.assertIn("npm install -g @openai/codex", script)
        self.assertIn("/home/sadmin/.npm-global", script)
        self.assertIn("codex exec --help", script)
        self.assertNotIn("chatgpt.com/codex/install.sh", script)
        source = (Path(__file__).resolve().parents[1] / "lsm_vps_init" / "stages.py").read_text(encoding="utf-8")
        self.assertNotIn("chatgpt.com/codex/install.sh", source)

    def test_missing_codex_installs_with_sadmin_owned_npm_prefix(self):
        runner = ScriptedRunner(
            [
                (VALIDATION, CommandResult(list(VALIDATION), 1, "", "")),
                (INSTALL, ""),
                (CHOWN_NPM, ""),
                (LOGIN_STATUS, ""),
                (BYPASS_FLAG_CHECK, ""),
                (MODEL_CHECK, ""),
                (CHOWN_CODEX, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch("builtins.print"):
                result = run_codex_install_auth(ctx)
            config = ctx.layout.sadmin_home / ".codex" / "config.toml"
            text = config.read_text(encoding="utf-8")
        self.assertEqual(result.status, "completed")
        self.assertIn(f'model = "{REQUIRED_CODEX_MODEL}"', text)
        self.assertIn(f'model_reasoning_effort = "{REQUIRED_CODEX_REASONING}"', text)
        self.assertEqual(runner.interactive_calls, [])
        self.assertEqual(runner.responses, [])

    def test_valid_existing_codex_install_remains_idempotent(self):
        runner = ScriptedRunner(
            [
                (VALIDATION, ""),
                (LOGIN_STATUS, ""),
                (BYPASS_FLAG_CHECK, ""),
                (MODEL_CHECK, ""),
                (CHOWN_CODEX, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch("builtins.print"):
                result = run_codex_install_auth(ctx)
        self.assertEqual(result.status, "completed")
        self.assertNotIn(INSTALL, runner.calls)
        self.assertEqual(runner.interactive_calls, [])

    def test_codex_auth_uses_device_auth_with_guidance(self):
        runner = ScriptedRunner(
            [
                (VALIDATION, ""),
                (LOGIN_STATUS, CommandResult(list(LOGIN_STATUS), 1, "Not logged in", "")),
                (LOGIN_DEVICE, ""),
                (BYPASS_FLAG_CHECK, ""),
                (MODEL_CHECK, ""),
                (CHOWN_CODEX, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ctx.require_tty = lambda _purpose: None
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch("builtins.print") as printed:
                result = run_codex_install_auth(ctx)
        self.assertEqual(result.status, "completed")
        self.assertEqual(runner.interactive_calls, [LOGIN_DEVICE])
        output = "\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertIn("LOCAL workstation", output)
        self.assertIn("sadmin", output)

    def test_post_auth_validation_uses_subcommand_flag_check_and_structured_model_check(self):
        runner = ScriptedRunner(
            [
                (VALIDATION, ""),
                (LOGIN_STATUS, ""),
                (BYPASS_FLAG_CHECK, ""),
                (MODEL_CHECK, ""),
                (CHOWN_CODEX, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch("builtins.print"):
                result = run_codex_install_auth(ctx)
        self.assertEqual(result.status, "completed")
        self.assertNotIn(sadmin_args("codex --help"), runner.calls)
        self.assertNotIn(sadmin_args("codex debug models"), runner.calls)


if __name__ == "__main__":
    unittest.main()
