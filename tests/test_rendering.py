import subprocess
import unittest

from lsm_vps_init.stages import (
    DOCKER_MODULE,
    NODEJS_VERSION,
    NODEJS_RELEASE_KEY_FINGERPRINTS,
    REQUIRED_CODEX_MODEL,
    REQUIRED_CODEX_REASONING,
    Blocked,
    codex_config_has_required_defaults,
    codex_exec_args,
    extract_codex_session_id,
    firewall_ports_for_modules,
    node_artifact_for_machine,
    parse_docker_published_ports,
    render_ssh_dropin,
    render_nodejs_install_script,
    render_ufw_phase_a_plan,
    upsert_codex_config,
    ufw_status_allows,
    validate_relay_codex_contract,
    validate_relay_env_policy,
)


class RenderingTests(unittest.TestCase):
    def test_dual_port_ssh_config_keeps_22(self):
        rendered = render_ssh_dropin("dual-port")
        self.assertIn("Port 22", rendered)
        self.assertIn("Port 65500", rendered)
        self.assertNotIn("PasswordAuthentication no", rendered)
        self.assertIn("Match User sadmin", rendered)
        self.assertIn("    ExposeAuthInfo yes", rendered)

    def test_hardened_ssh_config_removes_22_and_disables_passwords(self):
        rendered = render_ssh_dropin("hardened")
        self.assertNotIn("Port 22", rendered)
        self.assertIn("Port 65500", rendered)
        self.assertIn("PermitRootLogin no", rendered)
        self.assertIn("PasswordAuthentication no", rendered)
        self.assertIn("ExposeAuthInfo no", rendered)
        self.assertNotIn("ExposeAuthInfo yes", rendered)

    def test_firewall_ports_are_capability_derived(self):
        self.assertEqual(firewall_ports_for_modules({}), ["65500/tcp"])
        self.assertEqual(
            firewall_ports_for_modules({DOCKER_MODULE: True}),
            ["65500/tcp", "80/tcp", "443/tcp"],
        )

    def test_firewall_phase_a_keeps_current_ssh_path(self):
        self.assertEqual(render_ufw_phase_a_plan("22"), ["22/tcp", "65500/tcp"])
        self.assertEqual(render_ufw_phase_a_plan("65500"), ["22/tcp", "65500/tcp"])
        with self.assertRaises(Blocked):
            render_ufw_phase_a_plan("2222")

    def test_ufw_status_matching(self):
        status = "Status: active\n\n22/tcp ALLOW IN Anywhere\n65500/tcp ALLOW IN Anywhere\n"
        self.assertTrue(ufw_status_allows(status, "22/tcp"))
        self.assertTrue(ufw_status_allows(status, "65500/tcp"))
        self.assertFalse(ufw_status_allows(status, "80/tcp"))

    def test_docker_published_ports_are_parsed(self):
        ports = "web\t0.0.0.0:80->80/tcp, :::443->443/tcp\ndb\t127.0.0.1:5432->5432/tcp\n"
        self.assertEqual(parse_docker_published_ports(ports), {80, 443, 5432})

    def test_node_artifact_selection_and_install_script(self):
        self.assertEqual(node_artifact_for_machine("x86_64"), "linux-x64")
        self.assertEqual(node_artifact_for_machine("aarch64"), "linux-arm64")
        script = render_nodejs_install_script()
        self.assertIn(NODEJS_VERSION, script)
        self.assertIn(NODEJS_RELEASE_KEY_FINGERPRINTS[0], script)
        self.assertIn("Unpinned Node.js release key fingerprint", script)
        self.assertIn("VALIDSIG", script)
        self.assertIn("SHASUMS256.txt.asc", script)
        self.assertIn("gpgv --status-fd=1 --keyring", script)
        self.assertIn("sha256sum --check --ignore-missing", script)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True, capture_output=True)

    def test_bootstrap_discord_acl_policy_rejects_empty_or_invalid_ids(self):
        valid = {
            "DISCORD_GUILD_ID": "100000000000000000",
            "CODEX_VPS_DEFAULT_CHANNEL_ID": "100000000000000001",
            "CODEX_VPS_ALLOWED_USER_IDS": "100000000000000002",
            "CODEX_VPS_ALLOWED_APPROVER_USER_IDS": "",
        }
        validate_relay_env_policy(valid)
        invalid = dict(valid)
        invalid["CODEX_VPS_ALLOWED_USER_IDS"] = ""
        with self.assertRaises(Blocked):
            validate_relay_env_policy(invalid)
        invalid = dict(valid)
        invalid["CODEX_VPS_ALLOWED_APPROVER_USER_IDS"] = "not-a-discord-id"
        with self.assertRaises(Blocked):
            validate_relay_env_policy(invalid)

    def test_codex_config_upsert_preserves_existing_tables(self):
        existing = "[features]\nhooks = true\n"
        updated = upsert_codex_config(existing)
        self.assertIn(f'model = "{REQUIRED_CODEX_MODEL}"', updated)
        self.assertIn(f'model_reasoning_effort = "{REQUIRED_CODEX_REASONING}"', updated)
        self.assertIn("[features]\nhooks = true", updated)
        self.assertTrue(codex_config_has_required_defaults(updated))

    def test_codex_exec_args_pin_root_model_reasoning_and_bypass(self):
        args = codex_exec_args(session_id="00000000-0000-4000-8000-000000000001", json_output=True)
        self.assertEqual(args[:3], ["codex", "exec", "--json"])
        self.assertIn("--cd", args)
        self.assertIn("/home/sadmin", args)
        self.assertIn("--dangerously-bypass-approvals-and-sandbox", args)
        self.assertIn("-m", args)
        self.assertIn(REQUIRED_CODEX_MODEL, args)
        self.assertIn(f'model_reasoning_effort="{REQUIRED_CODEX_REASONING}"', args)
        self.assertIn("resume", args)

    def test_extract_codex_session_id_from_jsonl(self):
        output = '{"type":"thread.started","thread_id":"019fde3b-f1c6-7020-9047-f7267469e56e"}\n'
        self.assertEqual(extract_codex_session_id(output), "019fde3b-f1c6-7020-9047-f7267469e56e")

    def test_extract_codex_session_id_ignores_human_readable_uuid(self):
        output = "created session 019fde3b-f1c6-7020-9047-f7267469e56e\n"
        self.assertIsNone(extract_codex_session_id(output))

    def test_relay_codex_contract_requires_required_config(self):
        values = {
            "CODEX_VPS_ROOT": "/home/sadmin",
            "CODEX_VPS_ENGINE": "exec",
            "CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX": "true",
            "CODEX_VPS_SKIP_GIT_REPO_CHECK": "true",
            "CODEX_VPS_DEFAULT_SESSION_ID": "00000000-0000-4000-8000-000000000001",
        }
        validate_relay_codex_contract(values, upsert_codex_config(""))
        with self.assertRaises(Blocked):
            validate_relay_codex_contract({**values, "CODEX_VPS_ROOT": "/tmp"}, upsert_codex_config(""))
        with self.assertRaises(Blocked):
            validate_relay_codex_contract(values, 'model = "other"\nmodel_reasoning_effort = "xhigh"\n')


if __name__ == "__main__":
    unittest.main()
