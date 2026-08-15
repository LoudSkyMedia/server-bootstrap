import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DocsTests(unittest.TestCase):
    def test_readme_contains_resume_and_pinned_install_commands(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("sudo lsm-vps-init resume", readme)
        self.assertIn("LSM_VPS_INIT_SHA256", readme)
        self.assertIn("curl -fsSL", readme)
        self.assertIn("Before You Start", readme)
        self.assertIn("Paste sadmin SSH public key", readme)
        self.assertIn("DISCORD_BOT_TOKEN", readme)
        self.assertIn("CADDY_ACME_EMAIL", readme)
        self.assertIn("/stable/bootstrap.sh", readme)
        self.assertIn("Do not bootstrap new VPS hosts from `main`", readme)
        self.assertNotIn("/v0.1.0/bootstrap.sh", readme)

    def test_architecture_names_all_stages(self):
        arch = (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
        for slug in [
            "bootstrap_installation",
            "system_update",
            "root_password",
            "sadmin_user",
            "sadmin_ssh_key",
            "ssh_dual_port",
            "firewall_phase_a",
            "ssh_recovery_checkpoint",
            "management_tooling",
            "github_auth",
            "codex_install_auth",
            "codex_manager_session",
            "repository_selection",
            "discord_relay_install",
            "discord_relay_checkpoint",
            "final_host_hardening",
            "docker_hosting_stack",
        ]:
            self.assertIn(slug, arch)

    def test_release_trust_documents_stable_and_pinned_channels(self):
        release = (ROOT / "docs" / "release-trust.md").read_text(encoding="utf-8")
        self.assertIn("stable", release)
        self.assertIn("vX.Y.Z", release)
        self.assertIn("LSM_VPS_INIT_SHA256", release)
        self.assertIn("checksum", release.lower())
        self.assertIn("/stable/bootstrap.sh", release)
        self.assertNotIn("/v0.1.0/bootstrap.sh", release)

    def test_bootstrap_default_ref_matches_current_public_channel(self):
        bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        self.assertIn('DEFAULT_REF="stable"', bootstrap)
        self.assertNotIn('DEFAULT_REF="main"', bootstrap)


if __name__ == "__main__":
    unittest.main()
