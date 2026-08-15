import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsm_vps_init.state import default_state
from lsm_vps_init.stages import (
    DOCKER_HOSTING_REPO,
    DOCKER_MODULE,
    Blocked,
    Context,
    run_docker_hosting_stack,
)
from lsm_vps_init.util import CommandResult, PathLayout, merge_env_text, parse_env_value


def sadmin_args(script):
    wrapped = (
        'export HOME=/home/sadmin; '
        'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
        f"{script}"
    )
    return ("sudo", "-u", "sadmin", "-H", "bash", "-lc", wrapped)


DOCKER_CLONE = sadmin_args(
    "if [ -d /home/sadmin/docker-hosting-stack/.git ]; then "
    "cd /home/sadmin/docker-hosting-stack && git pull --ff-only; "
    "else gh repo clone LoudSkyMedia/docker-hosting-stack /home/sadmin/docker-hosting-stack; fi"
)
DOCKER_ENSURE_ENV = sadmin_args("cd /home/sadmin/docker-hosting-stack && test -f .env || install -m 0600 .env.example .env")
DOCKER_CHOWN_ENV = ("chown", "sadmin:sadmin", f"{DOCKER_HOSTING_REPO}/.env")
DOCKER_AUDIT = sadmin_args(
    "cd /home/sadmin/docker-hosting-stack && scripts/audit_host_baseline.sh --output docs/instances/bootstrap/audits/host-baseline-$(date -u +%F).md"
)
DOCKER_VALIDATE_N8N = sadmin_args("cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode n8n")
DOCKER_INSTALL_N8N_DRY_RUN = sadmin_args("cd /home/sadmin/docker-hosting-stack && scripts/install_n8n.sh --dry-run")


VALID_N8N_ENV = {
    "CADDY_ACME_EMAIL": "ops@example.com",
    "CF_ACCOUNT_ID": "0123456789abcdef0123456789abcdef",
    "CF_API_TOKEN": "cf_api_token_placeholder_value",
    "N8N_HOSTNAME": "n8n.example.com",
}


class PromptRecorder:
    def __init__(self, values):
        self.values = values
        self.secret_prompts = []
        self.text_prompts = []

    def attach(self, ctx):
        ctx.require_tty = lambda _purpose: None
        ctx.prompt_secret = self.prompt_secret
        ctx.prompt_text = self.prompt_text

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


class ScriptedRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.kwargs = []
        self.logs = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        args = tuple(args)
        self.calls.append(args)
        self.kwargs.append(_kwargs)
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
            raise AssertionError(f"command failed unexpectedly: {args}")
        return result


def make_context(tmp, runner):
    layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
    state = default_state()
    state["selected_modules"][DOCKER_MODULE] = True
    return Context(layout=layout, state=state, runner=runner, dry_run=False)


def write_docker_env(ctx, values, *, mode=0o600):
    env_path = ctx.layout.sadmin_home / "docker-hosting-stack" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(merge_env_text("", values), encoding="utf-8")
    os.chmod(env_path, mode)
    return env_path


def successful_fresh_n8n_commands():
    return [
        (DOCKER_CLONE, ""),
        (DOCKER_ENSURE_ENV, ""),
        (DOCKER_CHOWN_ENV, ""),
        (DOCKER_AUDIT, ""),
        (DOCKER_VALIDATE_N8N, ""),
        (DOCKER_INSTALL_N8N_DRY_RUN, ""),
    ]


def successful_existing_n8n_commands(uid):
    return [
        (DOCKER_CLONE, ""),
        (DOCKER_ENSURE_ENV, ""),
        (("id", "-u", "sadmin"), uid),
        (DOCKER_AUDIT, ""),
        (DOCKER_VALIDATE_N8N, ""),
        (DOCKER_INSTALL_N8N_DRY_RUN, ""),
    ]


class DockerHostingStackTests(unittest.TestCase):
    def test_fresh_n8n_prompts_for_required_values_and_runs_validation_after_collection(self):
        runner = ScriptedRunner(successful_fresh_n8n_commands())
        prompts = PromptRecorder(
            {
                "Caddy ACME email for n8n HTTPS certificates": VALID_N8N_ENV["CADDY_ACME_EMAIL"],
                "Cloudflare account ID": VALID_N8N_ENV["CF_ACCOUNT_ID"],
                "Cloudflare API token": VALID_N8N_ENV["CF_API_TOKEN"],
                "n8n public hostname": VALID_N8N_ENV["N8N_HOSTNAME"],
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            prompts.attach(ctx)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                result = run_docker_hosting_stack(ctx)
            env_path = ctx.layout.sadmin_home / "docker-hosting-stack" / ".env"
            written = env_path.read_text(encoding="utf-8")

        self.assertEqual(result.status, "completed")
        self.assertIn("Caddy ACME email", prompts.text_prompts[0])
        self.assertIn("Cloudflare account ID", prompts.text_prompts)
        self.assertEqual(prompts.secret_prompts, ["Cloudflare API token"])
        self.assertIn("n8n public hostname", prompts.text_prompts)
        self.assertLess(runner.calls.index(DOCKER_CHOWN_ENV), runner.calls.index(DOCKER_VALIDATE_N8N))
        for key, value in VALID_N8N_ENV.items():
            self.assertEqual(parse_env_value(written, key), value)
        self.assertIsNone(parse_env_value(written, "CODEX_NOTIFY_WEBHOOK_URL"))
        self.assertIsNone(parse_env_value(written, "CODEX_NOTIFY_SHARED_SECRET"))
        self.assertIsNone(parse_env_value(written, "N8N_ENCRYPTION_KEY"))
        self.assertEqual(runner.responses, [])

    def test_existing_valid_values_are_reused_on_resume_without_reprompting(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(successful_existing_n8n_commands(uid))
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            env_path = write_docker_env(ctx, {**VALID_N8N_ENV, "UNRELATED_KEEP": "yes"})
            ctx.prompt_secret = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("secret prompted on resume"))
            ctx.prompt_text = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("text prompted on resume"))
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                result = run_docker_hosting_stack(ctx)
            written = env_path.read_text(encoding="utf-8")

        self.assertEqual(result.status, "completed")
        self.assertEqual(parse_env_value(written, "UNRELATED_KEEP"), "yes")
        self.assertEqual(runner.responses, [])

    def test_partial_env_prompts_selectively_preserves_unrelated_values_and_keeps_secrets_out_of_state_and_logs(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_CHOWN_ENV, ""),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_N8N, ""),
                (DOCKER_INSTALL_N8N_DRY_RUN, ""),
            ]
        )
        prompts = PromptRecorder(
            {
                "Caddy ACME email for n8n HTTPS certificates": VALID_N8N_ENV["CADDY_ACME_EMAIL"],
                "Cloudflare API token": VALID_N8N_ENV["CF_API_TOKEN"],
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_docker_env(
                ctx,
                {
                    "CF_ACCOUNT_ID": VALID_N8N_ENV["CF_ACCOUNT_ID"],
                    "N8N_HOSTNAME": VALID_N8N_ENV["N8N_HOSTNAME"],
                    "UNRELATED_KEEP": "yes",
                },
            )
            prompts.attach(ctx)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                result = run_docker_hosting_stack(ctx)
            env_path = ctx.layout.sadmin_home / "docker-hosting-stack" / ".env"
            written = env_path.read_text(encoding="utf-8")
            state_payload = json.dumps(ctx.state)
            call_payload = json.dumps(runner.calls)
            log_payload = "\n".join(runner.logs)

        self.assertEqual(result.status, "completed")
        self.assertEqual(prompts.text_prompts, ["Caddy ACME email for n8n HTTPS certificates"])
        self.assertEqual(prompts.secret_prompts, ["Cloudflare API token"])
        self.assertEqual(parse_env_value(written, "UNRELATED_KEEP"), "yes")
        self.assertEqual(parse_env_value(written, "CF_API_TOKEN"), VALID_N8N_ENV["CF_API_TOKEN"])
        self.assertNotIn(VALID_N8N_ENV["CF_API_TOKEN"], state_payload)
        self.assertNotIn("CF_API_TOKEN", state_payload)
        self.assertNotIn(VALID_N8N_ENV["CF_API_TOKEN"], call_payload)
        self.assertNotIn(VALID_N8N_ENV["CF_API_TOKEN"], log_payload)
        validation_index = runner.calls.index(DOCKER_VALIDATE_N8N)
        self.assertEqual(runner.kwargs[validation_index]["redact_values"], [VALID_N8N_ENV["CF_API_TOKEN"]])

    def test_cloudflare_validation_failure_is_resumable_without_reprompting_valid_env(self):
        uid = str(os.getuid())
        failed_validation = CommandResult(list(DOCKER_VALIDATE_N8N), 1, "missing Cloudflare permission", "")
        prompts = PromptRecorder(
            {
                "Caddy ACME email for n8n HTTPS certificates": VALID_N8N_ENV["CADDY_ACME_EMAIL"],
                "Cloudflare account ID": VALID_N8N_ENV["CF_ACCOUNT_ID"],
                "Cloudflare API token": VALID_N8N_ENV["CF_API_TOKEN"],
                "n8n public hostname": VALID_N8N_ENV["N8N_HOSTNAME"],
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            first_ctx = make_context(
                tmp,
                ScriptedRunner(
                    [
                        (DOCKER_CLONE, ""),
                        (DOCKER_ENSURE_ENV, ""),
                        (DOCKER_CHOWN_ENV, ""),
                        (DOCKER_AUDIT, ""),
                        (DOCKER_VALIDATE_N8N, failed_validation),
                    ]
                ),
            )
            prompts.attach(first_ctx)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(first_ctx)
            self.assertIn("resume", str(caught.exception))
            self.assertEqual(prompts.secret_prompts, ["Cloudflare API token"])

            resume_runner = ScriptedRunner(successful_existing_n8n_commands(uid))
            resume_ctx = make_context(tmp, resume_runner)
            resume_ctx.prompt_secret = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("secret prompted on resume"))
            resume_ctx.prompt_text = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("text prompted on resume"))
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                result = run_docker_hosting_stack(resume_ctx)

        self.assertEqual(result.status, "completed")
        self.assertEqual(resume_runner.responses, [])

    def test_unsafe_env_permissions_are_rejected_before_reuse(self):
        runner = ScriptedRunner([(DOCKER_CLONE, ""), (DOCKER_ENSURE_ENV, "")])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_docker_env(ctx, VALID_N8N_ENV, mode=0o644)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)
        self.assertIn("mode 0600", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
