import stat
import tempfile
import unittest
from pathlib import Path

from lsm_vps_init.util import append_unique_line, file_mode, merge_env_text, parse_env_value, secure_write


class UtilTests(unittest.TestCase):
    def test_merge_env_preserves_unknown_keys_and_quotes_updates(self):
        existing = "EXISTING=keep\nSUDO_PASSWORD=old\n# comment\n"
        updated = merge_env_text(existing, {"SUDO_PASSWORD": "pa ss'word", "NEW_KEY": "value"})
        self.assertIn("EXISTING=keep", updated)
        self.assertIn("# comment", updated)
        self.assertIn("SUDO_PASSWORD='pa ss'\"'\"'word'", updated)
        self.assertIn("NEW_KEY=value", updated)

    def test_sudo_password_round_trips_shell_metacharacters_without_source(self):
        values = [
            " leading space",
            "trailing space ",
            "\tleading tab",
            "trailing tab\t",
            "space value",
            "tab\tvalue",
            "single'quote",
            'double"quote',
            "dollar$value",
            "hash#value",
            "equals=value",
            "back\\slash",
            "`backticks`",
            "semi;colon",
            "paren(value)",
            "bang!value",
            "mixed '\"$#=\\`();!\t value",
        ]
        for value in values:
            with self.subTest(length=len(value)):
                text = merge_env_text("", {"SUDO_PASSWORD": value})
                self.assertEqual(parse_env_value(text, "SUDO_PASSWORD"), value)

    def test_sudo_password_rejects_unrepresentable_single_line_values(self):
        for value in ["nul\x00byte", "line\nfeed", "carriage\rreturn"]:
            with self.subTest(length=len(value)):
                with self.assertRaises(ValueError):
                    merge_env_text("", {"SUDO_PASSWORD": value})

    def test_secure_write_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / ".env"
            secure_write(path, "SUDO_PASSWORD='x'\n", 0o600)
            self.assertEqual(file_mode(path), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_append_unique_line(self):
        value = append_unique_line("a\nb\n", "b")
        self.assertEqual(value, "a\nb\n")
        value = append_unique_line(value, "c")
        self.assertEqual(value, "a\nb\nc\n")


if __name__ == "__main__":
    unittest.main()
