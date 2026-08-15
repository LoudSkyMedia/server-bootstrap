import json
import shlex
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from lsm_vps_init import cli
from lsm_vps_init.state import StateStore, default_state, set_stage
from lsm_vps_init.stages import (
    MANAGEMENT_TOOL_COMMANDS,
    MANAGEMENT_TOOL_PACKAGES,
    Context,
    StageDefinition,
    StageResult,
    detect_management_tooling,
    run_management_tooling,
)
from lsm_vps_init.util import CommandResult, CommandRunner, PathLayout


COMMAND_CHECK = (
    "bash",
    "-lc",
    "for c in " + " ".join(shlex.quote(c) for c in MANAGEMENT_TOOL_COMMANDS) + '; do command -v "$c" >/dev/null || exit 1; done',
)
PACKAGE_CHECK = ("dpkg-query", "-W", "-f=${Status}\\n", *MANAGEMENT_TOOL_PACKAGES)
NODE_MAJOR_CHECK = ("node", "-e", "console.log(process.versions.node.split('.')[0])")


def package_status_output() -> str:
    return "".join("install ok installed\n" for _package in MANAGEMENT_TOOL_PACKAGES)


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
            raise AssertionError(f"command failed unexpectedly: {args}")
        return result


class RepairRunner:
    def __init__(self):
        self.calls = []
        self.logs = []

    def log(self, message):
        self.logs.append(message)

    def run(self, args, *, check=True, **_kwargs):
        args = tuple(args)
        self.calls.append(args)
        if args == COMMAND_CHECK:
            return CommandResult(list(args), 1, "", "")
        if args[:2] == ("bash", "-lc") and "apt-get install -y curl ca-certificates" in args[2]:
            return CommandResult(list(args), 0, "", "")
        raise AssertionError(f"unexpected command: {args}")


def context(tmp, runner) -> Context:
    layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
    return Context(layout=layout, state=default_state(), runner=runner, dry_run=False)


def healthy_management_runner() -> ScriptedRunner:
    return ScriptedRunner(
        [
            (COMMAND_CHECK, ""),
            (PACKAGE_CHECK, package_status_output()),
            (NODE_MAJOR_CHECK, "24\n"),
        ]
    )


class ManagementToolingTests(unittest.TestCase):
    def test_completed_management_tooling_detector_accepts_package_only_ca_certificates(self):
        runner = healthy_management_runner()
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            self.assertTrue(detect_management_tooling(ctx))

        self.assertNotIn("ca-certificates", COMMAND_CHECK[2])
        self.assertIn("ca-certificates", PACKAGE_CHECK)
        self.assertEqual(runner.responses, [])

    def test_management_tooling_detector_reports_command_regression(self):
        missing_command = CommandResult(list(COMMAND_CHECK), 1, "", "")
        runner = ScriptedRunner([(COMMAND_CHECK, missing_command)])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            self.assertFalse(detect_management_tooling(ctx))

    def test_management_tooling_detector_reports_package_regression(self):
        missing_package = CommandResult(list(PACKAGE_CHECK), 1, "", "package not installed")
        runner = ScriptedRunner([(COMMAND_CHECK, ""), (PACKAGE_CHECK, missing_package)])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            self.assertFalse(detect_management_tooling(ctx))

    def test_management_tooling_detector_reports_node_regression(self):
        runner = ScriptedRunner([(COMMAND_CHECK, ""), (PACKAGE_CHECK, package_status_output()), (NODE_MAJOR_CHECK, "18\n")])
        with tempfile.TemporaryDirectory() as tmp:
            ctx = context(tmp, runner)
            self.assertFalse(detect_management_tooling(ctx))

    def test_fully_completed_healthy_host_reports_complete_with_boot_changed(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(6, "firewall_phase_a", "Firewall Phase A", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(8, "management_tooling", "Management", detect_management_tooling, run_management_tooling),
            StageDefinition(15, "final_host_hardening", "Final", lambda _ctx: True, no_op),
            StageDefinition(16, "docker_hosting_stack", "Docker", lambda _ctx: True, no_op),
        ]
        runner = healthy_management_runner()
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            state["reboot"]["pending"] = False
            state["revalidation"]["boot_changed"] = True
            for stage in fake_stages:
                set_stage(state, stage.slug, "completed")
            state["current_stage"] = "management_tooling"
            ctx = Context(layout=layout, state=state, runner=runner, dry_run=False)

            json_output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(json_output):
                cli.print_status(ctx, as_json=True)
            text_state = json.loads(json.dumps(state))
            text_ctx = Context(layout=layout, state=text_state, runner=healthy_management_runner(), dry_run=False)
            text_output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(text_output):
                cli.print_status(text_ctx, as_json=False)

        payload = json.loads(json_output.getvalue())
        self.assertIsNone(payload["current_stage"])
        self.assertEqual(payload["pending"], [])
        self.assertFalse(payload["reboot"]["pending"])
        self.assertTrue(payload["revalidation"]["boot_changed"])
        self.assertIn("Current stage: complete", text_output.getvalue())

    def test_management_tooling_regression_becomes_current_stage(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(6, "firewall_phase_a", "Firewall Phase A", lambda _ctx: False, no_op, ("final_host_hardening",)),
            StageDefinition(8, "management_tooling", "Management", detect_management_tooling, run_management_tooling),
            StageDefinition(15, "final_host_hardening", "Final", lambda _ctx: True, no_op),
        ]
        missing_command = CommandResult(list(COMMAND_CHECK), 1, "", "")
        runner = ScriptedRunner([(COMMAND_CHECK, missing_command)])
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            state = default_state()
            for stage in fake_stages:
                set_stage(state, stage.slug, "completed")
            ctx = Context(layout=layout, state=state, runner=runner, dry_run=False)

            output = StringIO()
            with mock.patch.object(cli, "STAGES", fake_stages), redirect_stdout(output):
                cli.print_status(ctx, as_json=True)

        payload = json.loads(output.getvalue())
        self.assertEqual(payload["current_stage"], "management_tooling")

    def test_resume_repairs_genuine_management_tooling_regression_without_reopening_ssh_22(self):
        def no_op(_ctx):
            return StageResult("completed", "unused")

        def forbidden_run(_ctx):
            raise AssertionError("temporary SSH/firewall stage reran")

        fake_stages = [
            StageDefinition(5, "ssh_dual_port", "Dual SSH", lambda _ctx: False, forbidden_run, ("final_host_hardening",)),
            StageDefinition(6, "firewall_phase_a", "Firewall Phase A", lambda _ctx: False, forbidden_run, ("final_host_hardening",)),
            StageDefinition(8, "management_tooling", "Management", detect_management_tooling, run_management_tooling),
            StageDefinition(15, "final_host_hardening", "Final", lambda _ctx: True, no_op),
        ]

        def fake_stage_by_slug(slug):
            for stage in fake_stages:
                if stage.slug == slug or str(stage.index) == slug:
                    return stage
            raise KeyError(slug)

        runner = RepairRunner()
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            store = StateStore(layout.state_file)
            state = store.load()
            for stage in fake_stages:
                set_stage(state, stage.slug, "completed")
            state["current_stage"] = "management_tooling"
            store.save(state)
            ctx = Context(layout=layout, state=store.load(), runner=runner, dry_run=False)

            with (
                mock.patch("lsm_vps_init.stages.os.geteuid", return_value=0),
                mock.patch.object(cli, "STAGES", fake_stages),
                mock.patch.object(cli, "stage_by_slug", side_effect=fake_stage_by_slug),
                redirect_stdout(StringIO()),
            ):
                exit_code = cli.run_stages(ctx, store)
            final_state = store.load()

        self.assertEqual(exit_code, 0)
        self.assertIsNone(final_state["current_stage"])
        command_payload = json.dumps(runner.calls)
        self.assertNotIn("ufw allow 22/tcp", command_payload)
        self.assertNotIn("Port 22", command_payload)


if __name__ == "__main__":
    unittest.main()
