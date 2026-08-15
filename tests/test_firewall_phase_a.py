import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsm_vps_init.state import default_state, set_stage
from lsm_vps_init.stages import Context, detect_firewall_phase_a, run_firewall_phase_a
from lsm_vps_init.util import CommandResult, PathLayout


class ScriptedRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.logs = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        self.calls.append(tuple(args))
        if not self.responses:
            raise AssertionError(f"unexpected command: {args}")
        expected, response = self.responses.pop(0)
        self.assert_expected(expected, args)
        if isinstance(response, str):
            return CommandResult(list(args), 0, response, "")
        return response

    @staticmethod
    def assert_expected(expected, actual):
        if tuple(actual) != tuple(expected):
            raise AssertionError(f"expected command {expected}, got {actual}")


class FirewallPhaseATests(unittest.TestCase):
    def test_resume_from_inactive_ufw_with_staged_rules_enables_and_validates_active_status(self):
        inactive_status = "Status: inactive\n"
        staged_rules = (
            "Added user rules (see 'ufw status' for running firewall):\n"
            "ufw allow 22/tcp\n"
            "ufw allow 65500/tcp\n"
        )
        active_status = (
            "Status: active\n"
            "Logging: on (low)\n"
            "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
            "New profiles: skip\n\n"
            "To                         Action      From\n"
            "--                         ------      ----\n"
            "22/tcp                     ALLOW IN    Anywhere\n"
            "65500/tcp                  ALLOW IN    Anywhere\n"
        )
        runner = ScriptedRunner(
            [
                (("ufw", "status", "verbose"), inactive_status),
                (("apt-get", "install", "-y", "ufw"), ""),
                (("ufw", "default", "deny", "incoming"), ""),
                (("ufw", "default", "allow", "outgoing"), ""),
                (("ufw", "allow", "22/tcp"), ""),
                (("ufw", "allow", "65500/tcp"), ""),
                (("ufw", "show", "added"), staged_rules),
                (("ufw", "--force", "enable"), ""),
                (("ufw", "status", "verbose"), active_status),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            set_stage(state, "firewall_phase_a", "failed", "previous failed pre-enable active-status check")
            ctx = Context(layout=layout, state=state, runner=runner, dry_run=False)

            with mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0), mock.patch.dict(
                "lsm_vps_init.stages.os.environ",
                {"SSH_CONNECTION": "203.0.113.10 52000 198.51.100.20 22"},
                clear=False,
            ):
                self.assertFalse(detect_firewall_phase_a(ctx))
                result = run_firewall_phase_a(ctx)

        self.assertEqual(result.status, "completed")
        self.assertEqual(result.evidence, {"firewall_ports": ["22/tcp", "65500/tcp"]})
        self.assertEqual(runner.responses, [])
        self.assertEqual(
            runner.calls,
            [
                ("ufw", "status", "verbose"),
                ("apt-get", "install", "-y", "ufw"),
                ("ufw", "default", "deny", "incoming"),
                ("ufw", "default", "allow", "outgoing"),
                ("ufw", "allow", "22/tcp"),
                ("ufw", "allow", "65500/tcp"),
                ("ufw", "show", "added"),
                ("ufw", "--force", "enable"),
                ("ufw", "status", "verbose"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
