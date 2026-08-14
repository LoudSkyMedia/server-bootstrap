import json
import tempfile
import unittest
from pathlib import Path

from lsm_vps_init.state import default_state
from lsm_vps_init.stages import (
    Blocked,
    Context,
    record_ssh_checkpoint_proof,
    run_ssh_recovery,
    ssh_checkpoint_proof_from_env,
)
from lsm_vps_init.util import CommandRunner, PathLayout


class SshCheckpointTests(unittest.TestCase):
    def test_second_session_proof_requires_sadmin_65500_and_publickey_auth(self):
        env = {
            "SSH_CONNECTION": "203.0.113.10 52000 198.51.100.20 65500",
            "SSH_USER_AUTH": "/tmp/ssh-user-auth",
            "LSM_VPS_INIT_PUBLICKEY_ONLY": "1",
        }
        proof = ssh_checkpoint_proof_from_env(
            nonce="nonce-1",
            env=env,
            username="sadmin",
            auth_reader=lambda _: "publickey ssh-ed25519 SHA256:example\n",
        )
        self.assertEqual(proof["user"], "sadmin")
        self.assertEqual(proof["local_ssh_port"], "65500")
        self.assertTrue(proof["publickey_required"])
        self.assertTrue(proof["publickey_auth_verified"])
        self.assertEqual(proof["auth_proof_source"], "SSH_USER_AUTH")

    def test_second_session_proof_rejects_original_port_or_missing_publickey_auth(self):
        base_env = {
            "SSH_CONNECTION": "203.0.113.10 52000 198.51.100.20 22",
            "SSH_USER_AUTH": "/tmp/ssh-user-auth",
            "LSM_VPS_INIT_PUBLICKEY_ONLY": "1",
        }
        with self.assertRaises(Blocked):
            ssh_checkpoint_proof_from_env(
                nonce="nonce-1",
                env=base_env,
                username="sadmin",
                auth_reader=lambda _: "publickey ssh-ed25519 SHA256:example\n",
            )

        no_key_env = dict(base_env)
        no_key_env["SSH_CONNECTION"] = "203.0.113.10 52000 198.51.100.20 65500"
        with self.assertRaises(Blocked):
            ssh_checkpoint_proof_from_env(
                nonce="nonce-1",
                env=no_key_env,
                username="sadmin",
                auth_reader=lambda _: "password\n",
            )

    def test_record_ssh_checkpoint_stores_only_nonsecret_evidence_and_clears_nonce(self):
        state = default_state()
        state["facts"]["ssh_recovery_nonce"] = "nonce-1"
        proof = {
            "nonce": "nonce-1",
            "user": "sadmin",
            "local_ssh_port": "65500",
            "publickey_required": True,
            "publickey_auth_verified": True,
            "auth_proof_source": "SSH_USER_AUTH",
            "verified": True,
            "verified_at": "2026-08-14T12:00:00Z",
        }
        evidence = record_ssh_checkpoint_proof(state, proof)
        payload = json.dumps(state)
        self.assertTrue(state["checkpoints"]["ssh_recovery_verified"])
        self.assertNotIn("ssh_recovery_nonce", state["facts"])
        self.assertNotIn("ssh-ed25519", payload)
        self.assertEqual(evidence["user"], "sadmin")
        self.assertEqual(evidence["local_ssh_port"], "65500")

    def test_record_ssh_checkpoint_rejects_nonce_mismatch(self):
        state = default_state()
        state["facts"]["ssh_recovery_nonce"] = "expected"
        proof = {
            "nonce": "other",
            "user": "sadmin",
            "local_ssh_port": "65500",
            "publickey_required": True,
            "verified": True,
        }
        with self.assertRaises(Blocked):
            record_ssh_checkpoint_proof(state, proof)
        self.assertFalse(state["checkpoints"]["ssh_recovery_verified"])

    def test_ssh_recovery_stage_only_blocks_with_second_session_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            layout = PathLayout(mock_root=Path(tmp) / "root", state_dir=Path(tmp) / "state")
            ctx = Context(
                layout=layout,
                state=default_state(),
                runner=CommandRunner(layout.log_file, dry_run=True),
                dry_run=True,
            )
            with self.assertRaises(Blocked) as caught:
                run_ssh_recovery(ctx)
            message = str(caught.exception)
            self.assertIn("ssh -tt", message)
            self.assertIn("PasswordAuthentication=no", message)
            self.assertIn("KbdInteractiveAuthentication=no", message)
            self.assertIn("PreferredAuthentications=publickey", message)
            self.assertIn("record-ssh-proof", message)
            self.assertIn("verify-ssh --emit-proof", message)


if __name__ == "__main__":
    unittest.main()
