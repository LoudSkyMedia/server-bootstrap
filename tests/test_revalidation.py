import tempfile
import unittest
from pathlib import Path

from lsm_vps_init.state import default_state
from lsm_vps_init.stages import (
    Blocked,
    Context,
    DOCKER_MODULE,
    revalidate_before_final_hardening,
    render_ssh_dropin,
)
from lsm_vps_init.util import CommandResult, PathLayout, secure_write


ACTIVE_PHASE_A_UFW = (
    "Status: active\n"
    "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
    "22/tcp ALLOW IN Anywhere\n"
    "65500/tcp ALLOW IN Anywhere\n"
)


class FakeRunner:
    def __init__(self, responses: dict[tuple[str, ...], CommandResult | str]):
        self.responses = responses
        self.logs: list[str] = []

    def log(self, message: str) -> None:
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        key = tuple(args)
        response = self.responses.get(key)
        if response is None:
            return CommandResult(list(args), 0, "", "")
        if isinstance(response, str):
            return CommandResult(list(args), 0, response, "")
        return response


def context_for_revalidation(tmp: str, runner: FakeRunner, *, docker_selected: bool = False, docker_mode: str | None = None) -> Context:
    layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
    state = default_state()
    state["checkpoints"]["ssh_recovery_verified"] = True
    state["selected_modules"]["codex-vps-discord-relay"] = False
    state["selected_modules"][DOCKER_MODULE] = docker_selected
    if docker_mode:
        state["facts"]["docker_hosting_mode"] = docker_mode
    return Context(layout=layout, state=state, runner=runner, dry_run=False)


class RevalidationTests(unittest.TestCase):
    def test_historical_ssh_checkpoint_does_not_override_current_missing_65500(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner(
                {
                    ("sshd", "-T"): "port 22\n",
                    ("ss", "-tln"): "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n",
                    ("ufw", "status", "verbose"): ACTIVE_PHASE_A_UFW,
                    ("bash", "-lc", "command -v docker >/dev/null"): CommandResult([], 1, "", ""),
                }
            )
            ctx = context_for_revalidation(tmp, runner)
            with self.assertRaises(Blocked) as caught:
                revalidate_before_final_hardening(ctx)
            self.assertIn("effective sshd config does not include port 65500", str(caught.exception))

    def test_current_ssh_listener_and_firewall_phase_a_pass_revalidation(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner(
                {
                    ("ss", "-tln"): "LISTEN 0 128 0.0.0.0:65500 0.0.0.0:*\n",
                    ("ufw", "status", "verbose"): ACTIVE_PHASE_A_UFW,
                    ("bash", "-lc", "command -v docker >/dev/null"): CommandResult([], 1, "", ""),
                }
            )
            ctx = context_for_revalidation(tmp, runner)
            secure_write(ctx.layout.ssh_dropin, render_ssh_dropin("dual-port"), 0o644)
            revalidate_before_final_hardening(ctx)

    def test_docker_published_ports_are_revalidated_before_lockdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner(
                {
                    ("ss", "-tln"): "LISTEN 0 128 0.0.0.0:65500 0.0.0.0:*\n",
                    ("ufw", "status", "verbose"): ACTIVE_PHASE_A_UFW,
                    ("bash", "-lc", "command -v docker >/dev/null"): CommandResult([], 0, "", ""),
                    ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"): "db\t0.0.0.0:5432->5432/tcp\n",
                }
            )
            ctx = context_for_revalidation(tmp, runner)
            secure_write(ctx.layout.ssh_dropin, render_ssh_dropin("dual-port"), 0o644)
            with self.assertRaises(Blocked) as caught:
                revalidate_before_final_hardening(ctx)
            self.assertIn("Docker has unexpected host-published public port(s): 5432", str(caught.exception))

    def test_docker_web_ports_are_allowed_for_public_web_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner(
                {
                    ("ss", "-tln"): "LISTEN 0 128 0.0.0.0:65500 0.0.0.0:*\n",
                    ("ufw", "status", "verbose"): ACTIVE_PHASE_A_UFW,
                    ("bash", "-lc", "command -v docker >/dev/null"): CommandResult([], 0, "", ""),
                    ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"): "web\t0.0.0.0:80->80/tcp, :::443->443/tcp\n",
                }
            )
            ctx = context_for_revalidation(tmp, runner, docker_selected=True, docker_mode="n8n")
            secure_write(ctx.layout.ssh_dropin, render_ssh_dropin("dual-port"), 0o644)
            revalidate_before_final_hardening(ctx)

    def test_standalone_docker_web_ports_are_not_allowed_before_lockdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner(
                {
                    ("ss", "-tln"): "LISTEN 0 128 0.0.0.0:65500 0.0.0.0:*\n",
                    ("ufw", "status", "verbose"): ACTIVE_PHASE_A_UFW,
                    ("bash", "-lc", "command -v docker >/dev/null"): CommandResult([], 0, "", ""),
                    ("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"): "web\t0.0.0.0:80->80/tcp, :::443->443/tcp\n",
                }
            )
            ctx = context_for_revalidation(tmp, runner, docker_selected=True, docker_mode="standalone-app")
            secure_write(ctx.layout.ssh_dropin, render_ssh_dropin("dual-port"), 0o644)
            with self.assertRaises(Blocked) as caught:
                revalidate_before_final_hardening(ctx)
            self.assertIn("80, 443", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
