import json
import stat
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from lsm_vps_init.state import StateSafetyError, StateStore, default_state, mark_reboot_pending, set_fact, set_stage


class StateTests(unittest.TestCase):
    def test_state_file_is_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            store = StateStore(path)
            state = store.load()
            set_stage(state, "bootstrap_installation", "completed", evidence={"detected": True})
            store.save(state)
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_sensitive_fact_keys_are_rejected(self):
        state = default_state()
        with self.assertRaises(StateSafetyError):
            set_fact(state, "discord_token", "not-stored")

    def test_state_json_contains_no_secret_keys_after_stage_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            store = StateStore(path)
            state = store.load()
            set_stage(state, "github_auth", "blocked", "GitHub authentication required")
            store.save(state)
            payload = json.loads(path.read_text(encoding="utf-8"))
            flattened = json.dumps(payload).lower()
            self.assertNotIn("password", flattened)
            self.assertNotIn("token", flattened)

    def test_boot_change_sets_revalidation_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            with mock.patch("lsm_vps_init.state.boot_id", return_value="boot-a"):
                store = StateStore(path)
                state = store.load()
                store.save(state)
            with mock.patch("lsm_vps_init.state.boot_id", return_value="boot-b"):
                state = StateStore(path).load()
            self.assertTrue(state["revalidation"]["boot_changed"])
            self.assertEqual(state["last_boot_id"], "boot-b")

    def test_reboot_pending_marker(self):
        state = default_state()
        mark_reboot_pending(state, True)
        self.assertTrue(state["reboot"]["pending"])
        self.assertIsNotNone(state["reboot"]["required_since"])
        mark_reboot_pending(state, False)
        self.assertFalse(state["reboot"]["pending"])
        self.assertIsNone(state["reboot"]["required_since"])

    def test_stage_retry_and_completion_clear_stale_blocked_reason(self):
        state = default_state()
        set_stage(state, "docker_hosting_stack", "blocked", "missing configuration")
        self.assertEqual(state["current_stage"], "docker_hosting_stack")
        self.assertEqual(state["stages"]["docker_hosting_stack"]["blocked_reason"], "missing configuration")

        set_stage(state, "docker_hosting_stack", "in_progress")
        self.assertIsNone(state["stages"]["docker_hosting_stack"]["blocked_reason"])
        self.assertEqual(state["current_stage"], "docker_hosting_stack")

        set_stage(state, "docker_hosting_stack", "completed")
        self.assertIsNone(state["stages"]["docker_hosting_stack"]["blocked_reason"])
        self.assertIsNone(state["current_stage"])


if __name__ == "__main__":
    unittest.main()
