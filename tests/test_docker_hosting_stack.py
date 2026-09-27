import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsm_vps_init.state import default_state, set_stage
from lsm_vps_init.stages import (
    DOCKER_HOSTING_VALIDATOR_MODES,
    DOCKER_HOSTING_REPO,
    DOCKER_MODULE,
    DOCKER_HOST_PREPARE_APPLY_COMMAND,
    DOCKER_HOST_PREPARE_DRY_RUN_COMMAND,
    SSHD_SADMIN_MATCH_CRITERIA,
    SSH_PORT,
    Blocked,
    Context,
    detect_docker_hosting_stack,
    docker_n8n_env_updates,
    docker_existing_value_valid,
    docker_hosting_validator_mode,
    run_repository_selection,
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
DOCKER_VALIDATE_BASE = sadmin_args("cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode base")
DOCKER_VALIDATE_STANDALONE = sadmin_args("cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode standalone-app")
DOCKER_VALIDATE_N8N = sadmin_args("cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode n8n")
DOCKER_VALIDATE_MIGRATION = sadmin_args("cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode migration")
DOCKER_LAYOUT_DRY_RUN = sadmin_args("cd /home/sadmin/docker-hosting-stack && scripts/bootstrap_layout.sh --dry-run")
DOCKER_INSTALL_N8N_DRY_RUN = sadmin_args("cd /home/sadmin/docker-hosting-stack && scripts/install_n8n.sh --dry-run")
DOCKER_PREPARE_DRY_RUN = sadmin_args(f"cd /home/sadmin/docker-hosting-stack && {DOCKER_HOST_PREPARE_DRY_RUN_COMMAND}")
DOCKER_PREPARE_APPLY = sadmin_args(f"cd /home/sadmin/docker-hosting-stack && {DOCKER_HOST_PREPARE_APPLY_COMMAND}")
DOCKER_COMMAND_EXISTS = ("bash", "-lc", "command -v docker >/dev/null")
DOCKER_VERSION = ("docker", "version")
DOCKER_COMPOSE_VERSION = ("docker", "compose", "version")
DOCKER_SERVICE_ENABLED = ("systemctl", "is-enabled", "docker")
DOCKER_SERVICE_ACTIVE = ("systemctl", "is-active", "docker")
DOCKER_TCP_LISTENERS = ("ss", "-H", "-ltnp")


VALID_INSTANCE_ENV = {
    "INSTANCE_NAME": "test-vps",
    "SERVER_PUBLIC_IPV4": "8.8.8.8",
}
VALID_N8N_ENV = {
    **VALID_INSTANCE_ENV,
    "CADDY_ACME_EMAIL": "ops@valid.test",
    "CF_ACCOUNT_ID": "0123456789abcdef0123456789abcdef",
    "CF_API_TOKEN": "cf_api_token_placeholder_value",
    "N8N_HOSTNAME": "n8n.valid.test",
}
VALID_BASE_ENV = {
    **VALID_INSTANCE_ENV,
    "SERVER_FQDN": "server.valid.test",
    "ADMIN_DOMAIN": "admin.valid.test",
    "PHPMYADMIN_HOSTNAME": "pma.valid.test",
    "SFTPGO_ADMIN_HOSTNAME": "sftp.valid.test",
    "CADDY_ACME_EMAIL": "ops@valid.test",
    "CF_ACCOUNT_ID": "0123456789abcdef0123456789abcdef",
    "CF_API_TOKEN": "cf_api_token_placeholder_value",
}
VALID_SUDO_PASSWORD = " leading sudo\tplaceholder ' \" $ # = \\ ` ; () ! trailing "
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
FINAL_GLOBAL = (
    f"port {SSH_PORT}\n"
    "permitrootlogin no\n"
    "passwordauthentication no\n"
    "pubkeyauthentication yes\n"
)
FINAL_SADMIN = FINAL_GLOBAL + "exposeauthinfo no\n"
SSH_65500_LISTENER = "LISTEN 0 128 0.0.0.0:65500 0.0.0.0:*\n"


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
        if "Docker Hosting Stack Docker host preparation" in prompt:
            return True
        return default


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
    state["facts"]["instance_name"] = VALID_INSTANCE_ENV["INSTANCE_NAME"]
    state["facts"]["public_ipv4"] = VALID_INSTANCE_ENV["SERVER_PUBLIC_IPV4"]
    write_runtime_layout(layout)
    return Context(layout=layout, state=state, runner=runner, dry_run=False, assume_yes=True)


def write_runtime_layout(layout):
    for path in ("/srv/hosting", "/srv/hosting/apps", "/srv/hosting/secrets"):
        layout.map(path).mkdir(parents=True, exist_ok=True)


def write_docker_env(ctx, values, *, mode=0o600):
    env_path = ctx.layout.sadmin_home / "docker-hosting-stack" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(merge_env_text("", values), encoding="utf-8")
    os.chmod(env_path, mode)
    return env_path


def write_home_env(ctx, password=VALID_SUDO_PASSWORD, *, mode=0o600):
    env_path = ctx.layout.sadmin_env
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(merge_env_text("", {"SUDO_PASSWORD": password}), encoding="utf-8")
    os.chmod(env_path, mode)
    return env_path


def successful_fresh_n8n_commands(uid):
    return [
        (DOCKER_CLONE, ""),
        (DOCKER_ENSURE_ENV, ""),
        (("id", "-u", "sadmin"), uid),
        (DOCKER_CHOWN_ENV, ""),
        (DOCKER_AUDIT, ""),
        (DOCKER_VALIDATE_N8N, ""),
        *docker_preparation_commands(),
        (DOCKER_INSTALL_N8N_DRY_RUN, ""),
    ]


def successful_existing_n8n_commands(uid):
    return [
        (DOCKER_CLONE, ""),
        (DOCKER_ENSURE_ENV, ""),
        (("id", "-u", "sadmin"), uid),
        (DOCKER_AUDIT, ""),
        (DOCKER_VALIDATE_N8N, ""),
        *docker_preparation_commands(),
        (DOCKER_INSTALL_N8N_DRY_RUN, ""),
    ]


def successful_existing_commands(uid, validate_command, dry_run_command):
    return [
        (DOCKER_CLONE, ""),
        (DOCKER_ENSURE_ENV, ""),
        (("id", "-u", "sadmin"), uid),
        (DOCKER_AUDIT, ""),
        (validate_command, ""),
        *docker_preparation_commands(),
        (dry_run_command, ""),
    ]


def docker_preparation_commands(
    *,
    dry_run_result="Docker host preparation plan:\n",
    apply_result="Docker host preparation validation passed.\n",
    command_exists_result="",
    docker_version_result="Client: Docker Engine\nServer: Docker Engine\n",
    compose_version_result="Docker Compose version v2.29.7\n",
    service_enabled_result="enabled\n",
    service_active_result="active\n",
    tcp_listener_result="",
):
    return [
        (DOCKER_PREPARE_DRY_RUN, dry_run_result),
        (DOCKER_PREPARE_APPLY, apply_result),
        (DOCKER_COMMAND_EXISTS, command_exists_result),
        (DOCKER_VERSION, docker_version_result),
        (DOCKER_COMPOSE_VERSION, compose_version_result),
        (DOCKER_SERVICE_ENABLED, service_enabled_result),
        (DOCKER_SERVICE_ACTIVE, service_active_result),
        (DOCKER_TCP_LISTENERS, tcp_listener_result),
    ]


class DockerHostingStackTests(unittest.TestCase):
    def test_explicit_capability_to_validator_mapping(self):
        self.assertEqual(
            {mode: docker_hosting_validator_mode(mode) for mode in DOCKER_HOSTING_VALIDATOR_MODES},
            {
                "base": "base",
                "standalone-app": "standalone-app",
                "n8n": "n8n",
                "website-migration": "migration",
            },
        )

    def test_unknown_capability_is_rejected(self):
        with self.assertRaises(Blocked):
            docker_hosting_validator_mode("unknown-mode")

    def test_docker_module_not_selected_does_not_prepare_docker(self):
        runner = ScriptedRunner([])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ctx.state["selected_modules"][DOCKER_MODULE] = False
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0):
                result = run_docker_hosting_stack(ctx)

        self.assertEqual(result.status, "completed")
        self.assertEqual(runner.calls, [])

    def test_sudo_password_is_not_rejected_as_placeholder_text(self):
        self.assertTrue(docker_existing_value_valid("SUDO_PASSWORD", "example-vps"))
        self.assertTrue(docker_existing_value_valid("SUDO_PASSWORD", "203.0.113.10"))

    def test_standalone_app_uses_standalone_validator_and_layout_dry_run_without_cloudflare_prompts(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_CHOWN_ENV, ""),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_STANDALONE, ""),
                *docker_preparation_commands(),
                (DOCKER_LAYOUT_DRY_RUN, ""),
            ]
        )
        prompts = PromptRecorder({})
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            prompts.attach(ctx)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                result = run_docker_hosting_stack(ctx)
            written = (ctx.layout.sadmin_home / "docker-hosting-stack" / ".env").read_text(encoding="utf-8")

        self.assertEqual(result.status, "completed")
        self.assertIn(DOCKER_VALIDATE_STANDALONE, runner.calls)
        self.assertNotIn(DOCKER_VALIDATE_BASE, runner.calls)
        self.assertEqual(prompts.secret_prompts, [])
        self.assertNotIn("Cloudflare account ID", prompts.text_prompts)
        self.assertNotIn("Caddy ACME email for HTTPS certificates", prompts.text_prompts)
        self.assertEqual(parse_env_value(written, "INSTANCE_NAME"), VALID_INSTANCE_ENV["INSTANCE_NAME"])
        self.assertEqual(parse_env_value(written, "SERVER_PUBLIC_IPV4"), VALID_INSTANCE_ENV["SERVER_PUBLIC_IPV4"])
        self.assertIsNone(parse_env_value(written, "CF_API_TOKEN"))
        self.assertLess(runner.calls.index(DOCKER_VALIDATE_STANDALONE), runner.calls.index(DOCKER_PREPARE_DRY_RUN))
        self.assertLess(runner.calls.index(DOCKER_PREPARE_APPLY), runner.calls.index(DOCKER_LAYOUT_DRY_RUN))
        self.assertNotIn(("ufw", "allow", "80/tcp"), runner.calls)
        self.assertNotIn(("ufw", "allow", "443/tcp"), runner.calls)

    def test_existing_standalone_values_are_reused_on_resume_without_reprompting(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(successful_existing_commands(uid, DOCKER_VALIDATE_STANDALONE, DOCKER_LAYOUT_DRY_RUN))
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            env_path = write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD, "UNRELATED_KEEP": "yes"})
            ctx.prompt_secret = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("secret prompted on resume"))
            ctx.prompt_text = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("text prompted on resume"))
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                result = run_docker_hosting_stack(ctx)
            written = env_path.read_text(encoding="utf-8")

        self.assertEqual(result.status, "completed")
        self.assertEqual(parse_env_value(written, "UNRELATED_KEEP"), "yes")
        self.assertEqual(runner.responses, [])
        self.assertIn(DOCKER_PREPARE_DRY_RUN, runner.calls)
        self.assertIn(DOCKER_PREPARE_APPLY, runner.calls)

    def test_website_migration_uses_migration_validator(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(successful_existing_commands(uid, DOCKER_VALIDATE_MIGRATION, DOCKER_LAYOUT_DRY_RUN))
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_BASE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "website-migration"},
                clear=False,
            ):
                result = run_docker_hosting_stack(ctx)

        self.assertEqual(result.status, "completed")
        self.assertIn(DOCKER_VALIDATE_MIGRATION, runner.calls)
        self.assertNotIn(DOCKER_VALIDATE_BASE, runner.calls)
        self.assertLess(runner.calls.index(DOCKER_PREPARE_APPLY), runner.calls.index(DOCKER_LAYOUT_DRY_RUN))

    def test_public_web_modes_prepare_docker_before_capability_handoff(self):
        uid = str(os.getuid())
        cases = [
            ("base", DOCKER_VALIDATE_BASE, DOCKER_LAYOUT_DRY_RUN, VALID_BASE_ENV),
            ("n8n", DOCKER_VALIDATE_N8N, DOCKER_INSTALL_N8N_DRY_RUN, VALID_N8N_ENV),
            ("website-migration", DOCKER_VALIDATE_MIGRATION, DOCKER_LAYOUT_DRY_RUN, VALID_BASE_ENV),
        ]
        for mode, validate_command, handoff_command, env_values in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                runner = ScriptedRunner(successful_existing_commands(uid, validate_command, handoff_command))
                ctx = make_context(tmp, runner)
                write_home_env(ctx)
                write_docker_env(ctx, {**env_values, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
                with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                    os.environ,
                    {"LSM_VPS_DOCKER_MODE": mode},
                    clear=False,
                ):
                    result = run_docker_hosting_stack(ctx)

            self.assertEqual(result.status, "completed")
            self.assertLess(runner.calls.index(validate_command), runner.calls.index(DOCKER_PREPARE_DRY_RUN))
            self.assertLess(runner.calls.index(DOCKER_PREPARE_APPLY), runner.calls.index(handoff_command))

    def test_docker_preparation_dry_run_failure_blocks_stage16(self):
        uid = str(os.getuid())
        dry_run_failure = CommandResult(list(DOCKER_PREPARE_DRY_RUN), 1, "", "Conflicting Docker package family detected:\n- docker.io\n")
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_STANDALONE, ""),
                (DOCKER_PREPARE_DRY_RUN, dry_run_failure),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)

        self.assertIn("Docker package conflict", str(caught.exception))
        self.assertNotIn(DOCKER_PREPARE_APPLY, runner.calls)

    def test_docker_preparation_apply_failure_blocks_stage16(self):
        uid = str(os.getuid())
        apply_failure = CommandResult(list(DOCKER_PREPARE_APPLY), 1, "", "docker.service failed to start\n")
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_STANDALONE, ""),
                (DOCKER_PREPARE_DRY_RUN, "Docker host preparation plan:\n"),
                (DOCKER_PREPARE_APPLY, apply_failure),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)

        self.assertIn("Docker service failure", str(caught.exception))

    def test_compose_missing_after_preparation_blocks_stage16(self):
        uid = str(os.getuid())
        compose_missing = CommandResult(list(DOCKER_COMPOSE_VERSION), 1, "", "docker: 'compose' is not a docker command\n")
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_STANDALONE, ""),
                *docker_preparation_commands(compose_version_result=compose_missing),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)

        self.assertIn("Docker Compose plugin", str(caught.exception))
        self.assertNotIn(DOCKER_LAYOUT_DRY_RUN, runner.calls)

    def test_docker_service_inactive_after_preparation_blocks_stage16(self):
        uid = str(os.getuid())
        inactive = CommandResult(list(DOCKER_SERVICE_ACTIVE), 3, "inactive\n", "")
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_STANDALONE, ""),
                *docker_preparation_commands(service_active_result=inactive),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)

        self.assertIn("docker.service is not active", str(caught.exception))

    def test_docker_tcp_exposure_after_preparation_blocks_stage16(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_STANDALONE, ""),
                *docker_preparation_commands(tcp_listener_result="LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:((\"dockerd\",pid=1,fd=3))\n"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)

        self.assertIn("Docker TCP API exposure", str(caught.exception))

    def test_runtime_layout_missing_after_preparation_blocks_stage16(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_STANDALONE, ""),
                *docker_preparation_commands(),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            shutil.rmtree(ctx.layout.map("/srv/hosting"))
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)

        self.assertIn("Docker runtime layout missing", str(caught.exception))

    def test_completed_stage16_with_missing_live_docker_is_not_detected_and_can_resume(self):
        uid = str(os.getuid())
        with tempfile.TemporaryDirectory() as tmp:
            detect_runner = ScriptedRunner([(DOCKER_COMMAND_EXISTS, CommandResult(list(DOCKER_COMMAND_EXISTS), 1, "", ""))])
            ctx = make_context(tmp, detect_runner)
            ctx.state["facts"]["docker_hosting_mode"] = "standalone-app"
            set_stage(ctx.state, "docker_hosting_stack", "completed")
            (ctx.layout.sadmin_home / "docker-hosting-stack" / ".git").mkdir(parents=True)
            self.assertFalse(detect_docker_hosting_stack(ctx))

            runner = ScriptedRunner(successful_existing_commands(uid, DOCKER_VALIDATE_STANDALONE, DOCKER_LAYOUT_DRY_RUN))
            ctx.runner = runner
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(os.environ, {}, clear=True):
                result = run_docker_hosting_stack(ctx)

        self.assertEqual(result.status, "completed")
        self.assertIn(DOCKER_PREPARE_APPLY, runner.calls)

    def test_completed_stage16_with_valid_live_docker_detects_complete_without_preparation(self):
        runner = ScriptedRunner(docker_preparation_commands()[2:])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ctx.state["facts"]["docker_hosting_mode"] = "standalone-app"
            set_stage(ctx.state, "docker_hosting_stack", "completed")
            (ctx.layout.sadmin_home / "docker-hosting-stack" / ".git").mkdir(parents=True)
            self.assertTrue(detect_docker_hosting_stack(ctx))

        self.assertNotIn(DOCKER_PREPARE_DRY_RUN, runner.calls)
        self.assertNotIn(DOCKER_PREPARE_APPLY, runner.calls)

    def test_repository_selection_persists_docker_capability_before_hardening(self):
        runner = ScriptedRunner([])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ctx.state["selected_modules"] = {}
            with mock.patch.dict(
                os.environ,
                {"LSM_VPS_INIT_MODULES": "docker", "LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                result = run_repository_selection(ctx)

        self.assertEqual(result.status, "completed")
        self.assertTrue(ctx.state["selected_modules"][DOCKER_MODULE])
        self.assertEqual(ctx.state["facts"]["docker_hosting_mode"], "standalone-app")

    def test_stage16_reuses_persisted_capability_without_reprompting(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(successful_existing_commands(uid, DOCKER_VALIDATE_STANDALONE, DOCKER_LAYOUT_DRY_RUN))
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ctx.state["facts"]["docker_hosting_mode"] = "standalone-app"
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            ctx.prompt_secret = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("secret prompted on resume"))
            ctx.prompt_text = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("text prompted on resume"))
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(os.environ, {}, clear=True):
                result = run_docker_hosting_stack(ctx)

        self.assertEqual(result.status, "completed")
        self.assertEqual(ctx.state["facts"]["docker_hosting_mode"], "standalone-app")

    def test_legacy_stage16_resume_reconciles_stale_web_firewall_for_standalone(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(
            [
                (("sudo", "-n", "sshd", "-T"), FINAL_GLOBAL),
                (("sudo", "-n", "sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA), FINAL_SADMIN),
                (("ss", "-tln"), SSH_65500_LISTENER),
                (("ss", "-tln"), SSH_65500_LISTENER),
                (("ufw", "status", "verbose"), FINAL_UFW_WITH_STALE_WEB),
                (("bash", "-lc", "command -v docker >/dev/null"), CommandResult([], 1, "", "")),
                (("ufw", "allow", "65500/tcp"), ""),
                (("ufw", "status", "verbose"), FINAL_UFW_WITH_STALE_WEB),
                (("ufw", "status", "verbose"), FINAL_UFW_WITH_STALE_WEB),
                (("ufw", "delete", "allow", "80/tcp"), ""),
                (("ufw", "status", "verbose"), FINAL_UFW_WITH_443_ONLY),
                (("ufw", "status", "verbose"), FINAL_UFW_WITH_443_ONLY),
                (("ufw", "delete", "allow", "443/tcp"), ""),
                (("ufw", "status", "verbose"), FINAL_UFW_STANDALONE),
                (("ufw", "--force", "enable"), ""),
                (("ufw", "status", "verbose"), FINAL_UFW_STANDALONE),
                *successful_existing_commands(uid, DOCKER_VALIDATE_STANDALONE, DOCKER_LAYOUT_DRY_RUN),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            ctx.state["checkpoints"]["ssh_recovery_verified"] = True
            set_stage(ctx.state, "final_host_hardening", "blocked", "legacy stale web rules")
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_INSTANCE_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD})
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "standalone-app"},
                clear=False,
            ):
                result = run_docker_hosting_stack(ctx)

        self.assertEqual(result.status, "completed")
        self.assertLess(runner.calls.index(("ufw", "delete", "allow", "80/tcp")), runner.calls.index(DOCKER_CLONE))
        self.assertLess(runner.calls.index(("ufw", "delete", "allow", "443/tcp")), runner.calls.index(DOCKER_CLONE))
        self.assertNotIn(("ufw", "allow", "22/tcp"), runner.calls)

    def test_fresh_n8n_prompts_for_required_values_and_runs_validation_after_collection(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(successful_fresh_n8n_commands(uid))
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
            write_home_env(ctx)
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
        self.assertEqual(parse_env_value(written, "SUDO_PASSWORD"), VALID_SUDO_PASSWORD)
        self.assertIsNone(parse_env_value(written, "CODEX_NOTIFY_WEBHOOK_URL"))
        self.assertIsNone(parse_env_value(written, "CODEX_NOTIFY_SHARED_SECRET"))
        self.assertIsNone(parse_env_value(written, "N8N_ENCRYPTION_KEY"))
        self.assertEqual(runner.responses, [])

    def test_existing_valid_values_are_reused_on_resume_without_reprompting(self):
        uid = str(os.getuid())
        runner = ScriptedRunner(successful_existing_n8n_commands(uid))
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            env_path = write_docker_env(ctx, {**VALID_N8N_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD, "UNRELATED_KEEP": "yes"})
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
        self.assertEqual(parse_env_value(written, "SUDO_PASSWORD"), VALID_SUDO_PASSWORD)
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
                *docker_preparation_commands(),
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
            write_home_env(ctx)
            write_docker_env(
                ctx,
                {
                    "CF_ACCOUNT_ID": VALID_N8N_ENV["CF_ACCOUNT_ID"],
                    "SUDO_PASSWORD": "",
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
        self.assertEqual(parse_env_value(written, "SUDO_PASSWORD"), VALID_SUDO_PASSWORD)
        self.assertNotIn(VALID_N8N_ENV["CF_API_TOKEN"], state_payload)
        self.assertNotIn("CF_API_TOKEN", state_payload)
        self.assertNotIn(VALID_N8N_ENV["CF_API_TOKEN"], call_payload)
        self.assertNotIn(VALID_N8N_ENV["CF_API_TOKEN"], log_payload)
        self.assertNotIn(VALID_SUDO_PASSWORD, state_payload)
        self.assertNotIn("SUDO_PASSWORD", state_payload)
        self.assertNotIn(VALID_SUDO_PASSWORD, call_payload)
        self.assertNotIn(VALID_SUDO_PASSWORD, log_payload)
        audit_index = runner.calls.index(DOCKER_AUDIT)
        validation_index = runner.calls.index(DOCKER_VALIDATE_N8N)
        prepare_dry_run_index = runner.calls.index(DOCKER_PREPARE_DRY_RUN)
        prepare_apply_index = runner.calls.index(DOCKER_PREPARE_APPLY)
        install_index = runner.calls.index(DOCKER_INSTALL_N8N_DRY_RUN)
        expected_redactions = [VALID_N8N_ENV["CF_API_TOKEN"], VALID_SUDO_PASSWORD]
        self.assertEqual(runner.kwargs[audit_index]["redact_values"], expected_redactions)
        self.assertEqual(runner.kwargs[validation_index]["redact_values"], expected_redactions)
        self.assertEqual(runner.kwargs[prepare_dry_run_index]["redact_values"], expected_redactions)
        self.assertEqual(runner.kwargs[prepare_apply_index]["redact_values"], expected_redactions)
        self.assertEqual(runner.kwargs[install_index]["redact_values"], expected_redactions)
        self.assertFalse(any("sudo -n true" in " ".join(call) or "sudo -v" in " ".join(call) for call in runner.calls))

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
                        (("id", "-u", "sadmin"), uid),
                        (DOCKER_CHOWN_ENV, ""),
                        (DOCKER_AUDIT, ""),
                        (DOCKER_VALIDATE_N8N, failed_validation),
                    ]
                ),
            )
            write_home_env(first_ctx)
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
        uid = str(os.getuid())
        runner = ScriptedRunner([(DOCKER_CLONE, ""), (DOCKER_ENSURE_ENV, ""), (("id", "-u", "sadmin"), uid)])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx)
            write_docker_env(ctx, {**VALID_N8N_ENV, "SUDO_PASSWORD": VALID_SUDO_PASSWORD}, mode=0o644)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)
        self.assertIn("mode 0600", str(caught.exception))

    def test_unsafe_home_env_permissions_are_rejected_before_secret_read(self):
        uid = str(os.getuid())
        runner = ScriptedRunner([(DOCKER_CLONE, ""), (DOCKER_ENSURE_ENV, ""), (("id", "-u", "sadmin"), uid)])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            write_home_env(ctx, mode=0o644)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)
        self.assertIn("/home/sadmin/.env", str(caught.exception))
        self.assertIn("mode 0600", str(caught.exception))

    def test_sudo_validation_failure_reports_sudo_handoff_not_cloudflare(self):
        uid = str(os.getuid())
        failed_validation = CommandResult(list(DOCKER_VALIDATE_N8N), 1, "", "SUDO_PASSWORD is empty and passwordless sudo is not available")
        runner = ScriptedRunner(
            [
                (DOCKER_CLONE, ""),
                (DOCKER_ENSURE_ENV, ""),
                (("id", "-u", "sadmin"), uid),
                (DOCKER_CHOWN_ENV, ""),
                (DOCKER_AUDIT, ""),
                (DOCKER_VALIDATE_N8N, failed_validation),
            ]
        )
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
            write_home_env(ctx)
            prompts.attach(ctx)
            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                os.environ,
                {"LSM_VPS_DOCKER_MODE": "n8n"},
                clear=False,
            ):
                with self.assertRaises(Blocked) as caught:
                    run_docker_hosting_stack(ctx)
        message = str(caught.exception)
        self.assertIn("sudo credential", message)
        self.assertNotIn("Cloudflare account ID/token permissions", message)

    def test_missing_n8n_values_can_pause_before_prompting(self):
        runner = ScriptedRunner([])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = make_context(tmp, runner)
            prompts = PromptRecorder({})
            prompts.attach(ctx)
            ctx.confirm = lambda _prompt, default=False: False
            with self.assertRaises(Blocked) as caught:
                docker_n8n_env_updates(ctx, {})
        self.assertIn("Paused before Docker Hosting Stack n8n configuration", str(caught.exception))
        self.assertEqual(prompts.secret_prompts, [])
        self.assertEqual(prompts.text_prompts, [])


if __name__ == "__main__":
    unittest.main()
