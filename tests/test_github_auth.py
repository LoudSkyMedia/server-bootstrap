import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsm_vps_init.state import default_state
from lsm_vps_init.stages import (
    Blocked,
    Context,
    detect_github_auth,
    enforce_github_cli_config_permissions,
    github_cli_config_permissions_ok,
    run_github_auth,
)
from lsm_vps_init.util import CommandError, CommandResult, PathLayout


def sadmin_args(script):
    wrapped = (
        'export HOME=/home/sadmin; '
        'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
        f"{script}"
    )
    return ("sudo", "-u", "sadmin", "-H", "bash", "-lc", wrapped)


class ScriptedRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.interactive_calls = []
        self.secret_stdin_calls = []
        self.logs = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, input_text=None, check=True, secret_stdin=False, **_kwargs):
        self.calls.append(tuple(args))
        if secret_stdin:
            self.secret_stdin_calls.append((tuple(args), input_text))
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
        if isinstance(response, CommandResult):
            result = response
        else:
            result = CommandResult(list(args), 0, str(response), "")
        if check and result.returncode != 0:
            raise CommandError(result)
        return result


def make_context(tmp, runner):
    layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
    return Context(layout=layout, state=default_state(), runner=runner, dry_run=False)


def make_interactive(ctx, *, confirm_value=False, secret_value="test-token"):
    ctx.require_tty = lambda _purpose: None
    ctx.confirm = lambda _prompt, default=False: confirm_value
    ctx.prompt_secret = lambda _prompt, confirm=True: secret_value


STATUS = sadmin_args("gh auth status")
SETUP_GIT = sadmin_args("gh auth setup-git")
RELAY_VIEW = sadmin_args("gh repo view LoudSkyMedia/codex-vps-discord-relay --json nameWithOwner >/dev/null")
STACK_VIEW = sadmin_args("gh repo view LoudSkyMedia/docker-hosting-stack --json nameWithOwner >/dev/null")
OAUTH = sadmin_args("GH_BROWSER=echo BROWSER=echo gh auth login --hostname github.com --git-protocol https --web")
PAT = sadmin_args("gh auth login --with-token")


class GitHubAuthTests(unittest.TestCase):
    def test_already_authenticated_state_does_not_prompt_or_login(self):
        runner = ScriptedRunner([(STATUS, ""), (RELAY_VIEW, ""), (STACK_VIEW, "")])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ctx.confirm = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("prompted unexpectedly"))
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0):
                result = run_github_auth(ctx)
        self.assertEqual(result.status, "completed")
        self.assertEqual(runner.interactive_calls, [])
        self.assertEqual(runner.responses, [])

    def test_already_authenticated_state_repairs_gh_permissions_without_prompt(self):
        runner = ScriptedRunner([(STATUS, ""), (RELAY_VIEW, ""), (STACK_VIEW, "")])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            gh_dir = ctx.layout.sadmin_home / ".config" / "gh"
            gh_dir.mkdir(parents=True)
            hosts = gh_dir / "hosts.yml"
            hosts.write_text("oauth_token: placeholder\n", encoding="utf-8")
            gh_dir.chmod(0o755)
            hosts.chmod(0o644)
            ctx.confirm = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("prompted unexpectedly"))
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0):
                result = run_github_auth(ctx)
            self.assertTrue(github_cli_config_permissions_ok(ctx))
        self.assertEqual(result.status, "completed")
        self.assertEqual(runner.interactive_calls, [])
        self.assertEqual(runner.responses, [])

    def test_device_web_oauth_path_streams_login_and_verifies_access(self):
        runner = ScriptedRunner(
            [
                (STATUS, CommandResult(list(STATUS), 1, "", "")),
                (OAUTH, ""),
                (SETUP_GIT, ""),
                (STATUS, ""),
                (RELAY_VIEW, ""),
                (STACK_VIEW, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            make_interactive(ctx, confirm_value=False)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch("builtins.print"):
                result = run_github_auth(ctx)
        self.assertEqual(result.status, "completed")
        self.assertEqual(runner.interactive_calls, [OAUTH])
        self.assertEqual(runner.secret_stdin_calls, [])
        self.assertEqual(runner.responses, [])

    def test_pat_fallback_reads_token_from_secret_stdin_and_verifies_access(self):
        runner = ScriptedRunner(
            [
                (STATUS, CommandResult(list(STATUS), 1, "", "")),
                (PAT, ""),
                (SETUP_GIT, ""),
                (STATUS, ""),
                (RELAY_VIEW, ""),
                (STACK_VIEW, ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            make_interactive(ctx, confirm_value=True, secret_value="pat-value-not-printed")
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch("builtins.print"):
                result = run_github_auth(ctx)
        self.assertEqual(result.status, "completed")
        self.assertEqual(runner.interactive_calls, [])
        self.assertEqual(len(runner.secret_stdin_calls), 1)
        self.assertEqual(runner.secret_stdin_calls[0][0], PAT)
        self.assertEqual(runner.responses, [])

    def test_failed_oauth_blocks_and_resume_can_retry(self):
        failing_runner = ScriptedRunner(
            [
                (STATUS, CommandResult(list(STATUS), 1, "", "")),
                (OAUTH, CommandResult(list(OAUTH), 1, "", "cancelled")),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, failing_runner)
            make_interactive(ctx, confirm_value=False)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch("builtins.print"):
                with self.assertRaises(Blocked):
                    run_github_auth(ctx)

            retry_runner = ScriptedRunner(
                [
                    (STATUS, CommandResult(list(STATUS), 1, "", "")),
                    (OAUTH, ""),
                    (SETUP_GIT, ""),
                    (STATUS, ""),
                    (RELAY_VIEW, ""),
                    (STACK_VIEW, ""),
                ]
            )
            ctx = make_context(tmp, retry_runner)
            make_interactive(ctx, confirm_value=False)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch("builtins.print"):
                result = run_github_auth(ctx)
        self.assertEqual(result.status, "completed")
        self.assertEqual(retry_runner.interactive_calls, [OAUTH])

    def test_github_cli_config_permissions_are_checked_without_reading_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, ScriptedRunner([]))
            gh_dir = ctx.layout.sadmin_home / ".config" / "gh"
            gh_dir.mkdir(parents=True)
            hosts = gh_dir / "hosts.yml"
            hosts.write_text("oauth_token: placeholder\n", encoding="utf-8")
            gh_dir.chmod(0o755)
            hosts.chmod(0o644)
            self.assertFalse(github_cli_config_permissions_ok(ctx))
            enforce_github_cli_config_permissions(ctx)
            self.assertTrue(github_cli_config_permissions_ok(ctx))


if __name__ == "__main__":
    unittest.main()
