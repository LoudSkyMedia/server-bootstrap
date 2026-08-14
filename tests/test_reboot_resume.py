import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lsm_vps_init.state import StateStore, set_checkpoint, set_stage


class RebootResumeTests(unittest.TestCase):
    def test_boot_change_preserves_progress_and_marks_revalidation_for_key_resume_points(self):
        scenarios = [
            ["system_update"],
            ["system_update", "root_password", "sadmin_user", "sadmin_ssh_key"],
            ["system_update", "root_password", "sadmin_user", "sadmin_ssh_key", "ssh_dual_port"],
            ["system_update", "root_password", "sadmin_user", "sadmin_ssh_key", "ssh_dual_port", "ssh_recovery_checkpoint"],
            [
                "system_update",
                "root_password",
                "sadmin_user",
                "sadmin_ssh_key",
                "ssh_dual_port",
                "ssh_recovery_checkpoint",
                "discord_relay_install",
            ],
            [
                "system_update",
                "root_password",
                "sadmin_user",
                "sadmin_ssh_key",
                "ssh_dual_port",
                "ssh_recovery_checkpoint",
                "discord_relay_install",
                "final_host_hardening",
            ],
        ]
        for completed_stages in scenarios:
            with self.subTest(after=completed_stages[-1]):
                with tempfile.TemporaryDirectory() as tmp:
                    path = Path(tmp) / "state.json"
                    with mock.patch("lsm_vps_init.state.boot_id", return_value="boot-before"):
                        store = StateStore(path)
                        state = store.load()
                        for slug in completed_stages:
                            set_stage(state, slug, "completed")
                        set_checkpoint(state, "ssh_recovery_verified", "ssh_recovery_checkpoint" in completed_stages)
                        set_checkpoint(state, "relay_round_trip_verified", False)
                        store.save(state)
                    with mock.patch("lsm_vps_init.state.boot_id", return_value="boot-after"):
                        reloaded = StateStore(path).load()
                    self.assertTrue(reloaded["revalidation"]["boot_changed"])
                    self.assertEqual(reloaded["last_boot_id"], "boot-after")
                    for slug in completed_stages:
                        self.assertEqual(reloaded["stages"][slug]["status"], "completed")
                    payload = json.loads(path.read_text(encoding="utf-8"))
                    self.assertTrue(payload["revalidation"]["boot_changed"])


if __name__ == "__main__":
    unittest.main()
