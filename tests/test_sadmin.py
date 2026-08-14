import tempfile
import unittest
from pathlib import Path

from lsm_vps_init.state import default_state
from lsm_vps_init.stages import Context, detect_sadmin, run_sadmin
from lsm_vps_init.util import CommandRunner, PathLayout


class SadminTests(unittest.TestCase):
    def test_mock_sadmin_stage_requires_and_repairs_sudo_group_membership(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            group_file = layout.map("/etc/group")
            group_file.parent.mkdir(parents=True, exist_ok=True)
            group_file.write_text("sudo:x:27:\n", encoding="utf-8")
            ctx = Context(
                layout=layout,
                state=default_state(),
                runner=CommandRunner(layout.log_file, dry_run=True),
                dry_run=True,
            )
            run_sadmin(ctx)
            self.assertIn("sudo:x:27:sadmin", group_file.read_text(encoding="utf-8"))
            self.assertTrue(detect_sadmin(ctx))

            group_file.write_text("sudo:x:27:\n", encoding="utf-8")
            self.assertFalse(detect_sadmin(ctx))


if __name__ == "__main__":
    unittest.main()
