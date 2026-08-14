# Disposable VPS Acceptance Test Runbook

This runbook is for the first real Ubuntu 24.04 disposable-VPS rehearsal of
`lsm-vps-init`. Do not use it on a production VPS. Do not paste real passwords,
tokens, Discord IDs, SSH private keys, or provider credentials into this file or
any issue comment.

The rehearsal should prove the full bootstrap lifecycle, including deliberate
disconnect and reboot recovery, before a public repository or release is
created.

## Roles And Terminals

Use three terminal roles:

- Workstation: your local machine.
- Terminal A: the original SSH session to the fresh VPS, usually on port `22`.
- Terminal B: a separate `sadmin` SSH session to the VPS on port `65500`.

Keep provider web console access open throughout the test. The provider console
is the recovery path if SSH or firewall changes lock you out. The root password
created during this run is for console recovery only and must not be stored in
the bootstrap state or copied into any repo.

## Placeholders

Set these on the workstation before starting:

```bash
export VPS_IP="<fresh-ubuntu-24.04-vps-public-ipv4>"
export INITIAL_USER="<root-or-provider-sudo-user>"
export SSH_IDENTITY="$HOME/.ssh/lsm_vps_rehearsal_ed25519"
export BOOTSTRAP_URL="<temporary-https-url-to-bootstrap.sh>"
export ARCHIVE_URL="<temporary-https-url-to-server-bootstrap.tar.gz>"
export ARCHIVE_SHA256="<sha256-of-server-bootstrap.tar.gz>"
```

Pass criteria for every step:

- The command exits successfully, or the wizard blocks only at the documented
  hard checkpoint.
- No password, token, private key, Codex auth content, or Discord credential is
  printed.
- `sudo lsm-vps-init status` remains usable unless the step deliberately
  reboots the VPS.

On any unexpected failure, stop and capture the failure bundle in the next
section before retrying.

## Failure Bundle

Run this from any working SSH session, or from the provider console if SSH is
broken. Treat the resulting archive as sensitive operational evidence even
though the bootstrap is designed not to log secrets.

```bash
sudo bash -s <<'BASH'
set -Eeuo pipefail
umask 077
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dir="/root/lsm-vps-init-failure-$stamp"
mkdir -p "$dir"
cp -a /var/lib/lsm-vps-init/state.json "$dir/state.json" 2>/dev/null || true
cp -a /var/log/lsm-vps-init/bootstrap.log "$dir/bootstrap.log" 2>/dev/null || true
ss -tulpn > "$dir/ss-tulpn.txt" 2>&1 || true
ufw status verbose > "$dir/ufw-status.txt" 2>&1 || true
sshd -T > "$dir/sshd-effective.txt" 2>&1 || true
sshd -T -C user=sadmin,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=65500 \
  > "$dir/sshd-effective-sadmin-65500.txt" 2>&1 || true
journalctl -u ssh -u ssh.socket -u fail2ban -u unattended-upgrades \
  --no-pager -n 400 > "$dir/system-journal.txt" 2>&1 || true
sudo -iu sadmin env XDG_RUNTIME_DIR="/run/user/$(id -u sadmin)" \
  journalctl --user -u codex-vps-discord-relay.service --no-pager -n 400 \
  > "$dir/relay-user-journal.txt" 2>&1 || true
tar -C /root -czf "$dir.tar.gz" "$(basename "$dir")"
printf 'failure_bundle=%s\n' "$dir.tar.gz"
BASH
```

## Workstation Preparation

Create a rehearsal-only SSH key if one is not already available:

```bash
ssh-keygen -t ed25519 -f "$SSH_IDENTITY" \
  -C "lsm-vps-init-rehearsal-$(date -u +%Y%m%d)" -N ''
ssh-add "$SSH_IDENTITY"
```

Build a pre-public archive from the reviewed local checkout. If `git status`
shows unexpected files, stop and resolve that before packaging. For this
pre-public rehearsal, the command below packages tracked files plus untracked
non-ignored review files, excludes `.git`, and runs the public-safety scan
first:

```bash
cd /home/adenso/server-bootstrap
git status --short
scripts/secret_scan.sh
artifact_dir="$(mktemp -d -t lsm-vps-init-artifact.XXXXXXXXXX)"
{
  git ls-files -z
  git ls-files -z --others --exclude-standard
} | tar --null -T - --transform 's#^#server-bootstrap/#' -czf "$artifact_dir/server-bootstrap.tar.gz"
cp bootstrap.sh "$artifact_dir/bootstrap.sh"
sha256sum "$artifact_dir/server-bootstrap.tar.gz"
sha256sum "$artifact_dir/bootstrap.sh"
printf 'artifact_dir=%s\n' "$artifact_dir"
```

Upload `bootstrap.sh` and `server-bootstrap.tar.gz` from `artifact_dir` to an
operator-controlled temporary HTTPS location reachable by the VPS. Use those
URLs for `BOOTSTRAP_URL` and `ARCHIVE_URL`; use the archive checksum for
`ARCHIVE_SHA256`. This pre-public path still exercises bootstrap download,
checksum verification, local install, and resume behavior without requiring Git
on the VPS.

STOP if `git status --short` contains any unexpected file, if the secret scan
fails, or if the archive is not created from the reviewed local checkout.

## Provider And VPS Preparation

Create a new disposable Ubuntu 24.04 LTS VPS. Confirm the provider firewall or
security group allows your workstation IP to reach TCP `22` and TCP `65500`.
Do not open application, database, Docker API, Discord relay, or admin-helper
ports.

Connect to the fresh server with a TTY:

```bash
ssh -tt -i "$SSH_IDENTITY" -o IdentitiesOnly=yes "$INITIAL_USER@$VPS_IP"
```

On the VPS, confirm the target OS:

```bash
cat /etc/os-release
```

Expected result: `ID=ubuntu` and `VERSION_ID="24.04"`.

STOP if the VPS is not Ubuntu 24.04.

To intentionally exercise pending-reboot handling even if the image has no
kernel update available, create a disposable reboot marker before bootstrap:

```bash
sudo sh -c 'printf "lsm-vps-init-acceptance\n" > /var/run/reboot-required'
sudo sh -c 'printf "lsm-vps-init-acceptance\n" > /var/run/reboot-required.pkgs'
```

## 1. Initial Bootstrap

Run the bootstrap without requiring Git on the VPS:

```bash
export BOOTSTRAP_URL="<temporary-https-url-to-bootstrap.sh>"
export ARCHIVE_URL="<temporary-https-url-to-server-bootstrap.tar.gz>"
export ARCHIVE_SHA256="<sha256-of-server-bootstrap.tar.gz>"

curl -fsSL "$BOOTSTRAP_URL" -o /tmp/lsm-vps-bootstrap.sh
sha256sum /tmp/lsm-vps-bootstrap.sh
sudo LSM_VPS_INIT_ARCHIVE_URL="$ARCHIVE_URL" \
  LSM_VPS_INIT_SHA256="$ARCHIVE_SHA256" \
  bash /tmp/lsm-vps-bootstrap.sh
```

Expected result:

- Bootstrap installs prerequisites including `tmux`.
- `/usr/local/sbin/lsm-vps-init` exists.
- The wizard starts or resumes in the `lsm-vps-init` tmux session.
- The output prints the reattach command.

Verify from Terminal A:

```bash
sudo test -x /usr/local/sbin/lsm-vps-init
sudo lsm-vps-init status
sudo stat -c '%U:%G %a %n' /var/lib/lsm-vps-init /var/lib/lsm-vps-init/state.json /var/log/lsm-vps-init/bootstrap.log
```

Expected result: state directory is root-owned mode `700`; state and log files
are root-owned mode `600`.

Recovery:

```bash
sudo dpkg --configure -a
sudo apt-get -f install
sudo lsm-vps-init resume
```

STOP if bootstrap cannot install the local wizard or state/log paths are not
root-protected.

## 2. System Update And Pending Reboot

Let the wizard complete `system_update`.

Verify:

```bash
sudo lsm-vps-init status --json | sudo tee /root/lsm-vps-init-status-system-update.json >/dev/null
sudo python3 - <<'PY'
import json
from pathlib import Path
state = json.loads(Path("/var/lib/lsm-vps-init/state.json").read_text())
print("system_update:", state["stages"].get("system_update", {}).get("status"))
print("reboot_pending:", state.get("reboot", {}).get("pending"))
PY
```

Expected result: `system_update` is `completed`; `reboot_pending` is `True` if
the marker exists.

STOP on unresolved apt/dpkg errors. Capture the failure bundle.

## 3. Root Password Reset

At the wizard prompt, enter and confirm a new root recovery password. Do not
record it in shell history or notes.

Verify:

```bash
sudo passwd -S root | awk '{print $1, $2}'
```

Expected result: `root P`.

Recovery: use the provider console if the prompt is interrupted, then run:

```bash
sudo lsm-vps-init resume
```

STOP if the root password is not set before any planned reboot.

## 4. sadmin Creation And Sudo Verification

At the wizard prompt, enter and confirm the `sadmin` sudo password. This same
password is intentionally written to `/home/sadmin/.env` by the wizard.

Verify the account without printing the password:

```bash
id sadmin
getent group sudo
sudo -iu sadmin bash -lc 'whoami && groups'
```

Expected result: user is `sadmin`, home is `/home/sadmin`, shell is usable, and
`sudo` group membership includes `sadmin`.

Perform an interactive sudo check as `sadmin`:

```bash
sudo -iu sadmin
sudo -v
exit
```

Expected result: `sudo -v` succeeds after the operator enters the `sadmin`
password.

STOP if `sadmin` cannot use sudo.

## 5. sadmin .env Verification

Verify the required file exists without exposing the value:

```bash
sudo stat -c '%U:%G %a %n' /home/sadmin/.env
sudo awk -F= '$1=="SUDO_PASSWORD"{found=1} END{print found ? "SUDO_PASSWORD key present" : "SUDO_PASSWORD key missing"}' /home/sadmin/.env
sudo test -f /home/sadmin/AGENTS.md
```

Expected result: `/home/sadmin/.env` is `sadmin:sadmin` mode `600`, the
`SUDO_PASSWORD` key is present, and `/home/sadmin/AGENTS.md` exists.

STOP if the file is missing, has broader permissions, or the key is absent.
Capture the failure bundle, but do not print or copy the `.env` value.

## 6. SSH Public Key Installation

When prompted, paste the public key from:

```bash
cat "$SSH_IDENTITY.pub"
```

Verify on the VPS:

```bash
sudo stat -c '%U:%G %a %n' /home/sadmin/.ssh /home/sadmin/.ssh/authorized_keys
sudo ssh-keygen -l -f /home/sadmin/.ssh/authorized_keys
```

Expected result: `.ssh` is mode `700`, `authorized_keys` is mode `600`, and
`ssh-keygen -l` prints fingerprints without exposing private key material.

STOP if the key is invalid or permissions are incorrect.

## 7. Dual SSH Listeners And UFW Phase A

Let the wizard complete `ssh_dual_port` and `firewall_phase_a`.

Verify:

```bash
sudo sshd -t
sudo sshd -T | awk '/^port /{print}'
sudo sshd -T -C user=sadmin,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=65500 \
  | awk '/^(port|exposeauthinfo|passwordauthentication|pubkeyauthentication) /{print}'
sudo ss -tln | awk '$4 ~ /:(22|65500)$/ {print $1, $4}'
sudo ufw status verbose
```

Expected result:

- Effective SSH config includes both `port 22` and `port 65500`.
- A server-side listener exists for both ports.
- Effective `sadmin` config has temporary `exposeauthinfo yes`.
- UFW is active, default incoming is deny, outgoing is allow, and both
  `22/tcp` and `65500/tcp` are allowed.

Recovery while Terminal A still works:

```bash
sudo ufw allow 22/tcp
sudo ufw allow 65500/tcp
sudo sshd -t
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket || sudo systemctl restart ssh
```

Provider-console recovery if SSH is broken:

```bash
sudo ufw --force disable
sudo install -m 0644 /dev/stdin /etc/ssh/sshd_config.d/01-lsm-vps-init-recovery.conf <<'EOF'
Port 22
Port 65500
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin prohibit-password
EOF
sudo sshd -t
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket || sudo systemctl restart ssh
```

STOP if either SSH port is not listening, if UFW does not allow the current SSH
path, or if `sshd -t` fails.

## 8. Second-Session SSH Proof

The wizard blocks at `ssh_recovery_checkpoint` and prints an SSH command. From
the workstation or Terminal B, run the printed command exactly. The command must
use these options:

```text
-o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PreferredAuthentications=publickey -p 65500
```

If your key is not in your SSH agent, add it first on the workstation:

```bash
ssh-add "$SSH_IDENTITY"
```

Expected result: the second session connects as `sadmin`, records the proof
through `sudo lsm-vps-init record-ssh-proof`, removes its temporary proof file,
and prints:

```text
SSH recovery checkpoint verified
Resume with: sudo lsm-vps-init resume
```

Verify safe proof metadata:

```bash
sudo python3 - <<'PY'
import json
from pathlib import Path
state = json.loads(Path("/var/lib/lsm-vps-init/state.json").read_text())
proof = state["facts"].get("ssh_recovery_verification", {})
print("verified:", proof.get("verified"))
print("user:", proof.get("user"))
print("local_ssh_port:", proof.get("local_ssh_port"))
print("publickey_required:", proof.get("publickey_required"))
print("publickey_auth_verified:", proof.get("publickey_auth_verified"))
print("nonce_still_present:", "ssh_recovery_nonce" in state.get("facts", {}))
PY
```

Expected result: `verified: True`, `user: sadmin`, `local_ssh_port: 65500`,
public-key fields are true, and the nonce is no longer present.

STOP if the proof cannot be recorded from the second session. Do not proceed to
final hardening.

## 9. Intentional Loss Of Original SSH Session

While the wizard is blocked or waiting in tmux, intentionally close Terminal A.
Reconnect from the workstation:

```bash
ssh -tt -i "$SSH_IDENTITY" -o IdentitiesOnly=yes "$INITIAL_USER@$VPS_IP" \
  'sudo tmux attach-session -t lsm-vps-init'
```

If tmux is not available or the session is gone, use persistent state:

```bash
ssh -tt -i "$SSH_IDENTITY" -o IdentitiesOnly=yes "$INITIAL_USER@$VPS_IP" \
  'sudo lsm-vps-init resume'
```

Expected result: the wizard resumes from the same checkpoint or the next valid
stage. It must not repeat completed password prompts unnecessarily.

STOP if neither tmux reattach nor persistent resume works.

## 10. Deliberate Mid-Initialization Reboot

After the SSH checkpoint is verified and before Codex installation, reboot the
VPS:

```bash
sudo lsm-vps-init status
sudo systemctl reboot
```

Reconnect on port `65500` as `sadmin`:

```bash
ssh -tt -i "$SSH_IDENTITY" -o IdentitiesOnly=yes \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey -p 65500 sadmin@"$VPS_IP"
```

Resume:

```bash
sudo lsm-vps-init status --json | sudo tee /root/lsm-vps-init-status-after-mid-reboot.json >/dev/null
sudo lsm-vps-init resume
```

Expected result:

- `revalidation.boot_changed` is true in status JSON.
- The persisted reboot flag reflects the current `/var/run/reboot-required`
  marker.
- The wizard revalidates mutable conditions and continues at management
  tooling or the first invalidated stage.

Recovery: use the provider console root password, confirm SSH and UFW state,
then run:

```bash
sudo lsm-vps-init status
sudo lsm-vps-init resume
```

STOP if post-reboot status cannot be read or if port `65500` no longer works.

## 11. Management Tooling

Let the wizard install management tooling.

Verify:

```bash
command -v curl git gh jq openssl python3 node npm tmux
node --version
npm --version
gh --version | head -n 1
```

Expected result: all commands exist and Node.js major version is `20` or newer.
If the official Node.js binary path was used, `/usr/local/bin/node` points into
`/opt/nodejs`.

STOP if Node release-key trust verification fails, Node is older than 20, or
`gh` is missing.

## 12. GitHub Authentication As sadmin

Let the wizard run GitHub authentication as `sadmin`, or run the equivalent
commands manually if it blocks:

```bash
sudo -iu sadmin gh auth login --hostname github.com --git-protocol https
sudo -iu sadmin gh auth setup-git
sudo -iu sadmin gh auth status
sudo -iu sadmin gh repo view LoudSkyMedia/codex-vps-discord-relay --json nameWithOwner --jq .nameWithOwner
sudo -iu sadmin gh repo view LoudSkyMedia/docker-hosting-stack --json nameWithOwner --jq .nameWithOwner
```

Expected result: `gh auth status` succeeds as `sadmin`, and both private repo
lookups print their repository names.

STOP if GitHub auth fails or either private repo is inaccessible.

## 13. Codex Installation, Authentication, And Contract

Let the wizard install and authenticate Codex as `sadmin`.

Verify:

```bash
sudo -iu sadmin codex login status
sudo -iu sadmin codex --help | grep -F -- '--dangerously-bypass-approvals-and-sandbox'
sudo -iu sadmin python3 - <<'PY'
from pathlib import Path
import tomllib
config = tomllib.loads(Path("/home/sadmin/.codex/config.toml").read_text())
print("model:", config.get("model"))
print("model_reasoning_effort:", config.get("model_reasoning_effort"))
PY
```

Expected result: Codex login succeeds, the bypass flag is present, `model` is
`gpt-5.5`, and `model_reasoning_effort` is `xhigh`.

Verify a direct resume invocation uses the same contract after the manager
session is created in the next step.

STOP if Codex auth fails, if `gpt-5.5` is unavailable, if `xhigh` is not
accepted, or if the bypass flag is missing.

## 14. VPS Server Manager Session

Let the wizard complete `codex_manager_session`.

Verify the session ID is recorded:

```bash
SESSION_ID="$(sudo python3 - <<'PY'
import json
from pathlib import Path
state = json.loads(Path("/var/lib/lsm-vps-init/state.json").read_text())
print(state.get("facts", {}).get("codex_session_id", ""))
PY
)"
printf 'session_id_present=%s\n' "$([ -n "$SESSION_ID" ] && echo yes || echo no)"
```

Verify the ID came from a `thread.started` JSONL event in the bootstrap log
without printing prompt content:

```bash
sudo python3 - <<'PY'
import json
from pathlib import Path
found = False
for line in Path("/var/log/lsm-vps-init/bootstrap.log").read_text(errors="replace").splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    if event.get("type") == "thread.started" and event.get("thread_id"):
        found = True
        break
print("thread.started_jsonl_seen:", found)
PY
```

Verify direct resume with the required execution contract:

```bash
sudo -iu sadmin env SESSION_ID="$SESSION_ID" bash <<'BASH'
set -Eeuo pipefail
cd /home/sadmin
printf '%s\n' 'Reply OK only.' | codex exec resume "$SESSION_ID" \
  --json \
  --skip-git-repo-check \
  --dangerously-bypass-approvals-and-sandbox \
  -m gpt-5.5 \
  -c 'model_reasoning_effort="xhigh"' \
  >/tmp/lsm-codex-resume-check.jsonl
python3 - <<'PY'
from pathlib import Path
text = Path("/tmp/lsm-codex-resume-check.jsonl").read_text(errors="replace")
print("resume_jsonl_nonempty:", bool(text.strip()))
PY
BASH
```

Expected result: a UUID session ID is present, `thread.started_jsonl_seen` is
true for the creation path, and direct resume returns non-empty JSONL.

STOP if the session ID is missing, invalid, or cannot be resumed.

## 15. Repository Selection

At the wizard module prompt:

- Select `Codex VPS Discord Relay`.
- Select `Docker Hosting Stack` so the final dry-run handoff is exercised.

Verify:

```bash
sudo python3 - <<'PY'
import json
from pathlib import Path
state = json.loads(Path("/var/lib/lsm-vps-init/state.json").read_text())
print(state.get("selected_modules", {}))
PY
```

Expected result: both module keys are present and true.

STOP if either selected module is not recorded as intended.

## 16. Discord Relay Clone And Configuration

Let the wizard clone and configure:

```text
/home/sadmin/codex-vps-discord-relay
```

When prompted, enter Discord values from the Discord developer portal and the
target test server/channel. Use test-only credentials.

Required operator setup in Discord:

- Create a Discord application and bot for the rehearsal.
- Enable Guild Install for the application.
- Enable Message Content Intent for the bot.
- Add the bot to the test Discord server.
- Grant permissions required by the relay runbook for reading and sending
  messages in the intended channel.
- Retrieve the server/guild ID, channel ID, allowed operator user ID, and
  approver user ID from Discord developer mode.

Verify repo and env file permissions:

```bash
sudo -iu sadmin test -d /home/sadmin/codex-vps-discord-relay/.git
sudo stat -c '%U:%G %a %n' /home/sadmin/codex-vps-discord-relay/.env
sudo -u sadmin grep -q '^SUDO_PASSWORD=' /home/sadmin/codex-vps-discord-relay/.env \
  && echo 'relay env contains forbidden sudo key: FAIL' \
  || echo 'relay env omits sudo key: PASS'
```

Verify ACLs and relay Codex contract without printing IDs or tokens:

```bash
sudo -u sadmin python3 - <<'PY'
from pathlib import Path
import re
import shlex

env = Path("/home/sadmin/codex-vps-discord-relay/.env").read_text()
values = {}
for raw in env.splitlines():
    stripped = raw.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        continue
    key, value = stripped.split("=", 1)
    if key in {
        "DISCORD_GUILD_ID",
        "CODEX_VPS_DEFAULT_CHANNEL_ID",
        "CODEX_VPS_ALLOWED_USER_IDS",
        "CODEX_VPS_ALLOWED_APPROVER_USER_IDS",
        "CODEX_VPS_DEFAULT_SESSION_ID",
        "CODEX_VPS_ROOT",
        "CODEX_VPS_ENGINE",
        "CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX",
        "CODEX_VPS_SKIP_GIT_REPO_CHECK",
    }:
        values[key] = shlex.split(stripped, comments=True)[0].split("=", 1)[1]

snowflake = re.compile(r"^[0-9]{17,20}$")
allowed = [item.strip() for item in values.get("CODEX_VPS_ALLOWED_USER_IDS", "").split(",") if item.strip()]
approvers = [item.strip() for item in values.get("CODEX_VPS_ALLOWED_APPROVER_USER_IDS", "").split(",") if item.strip()]
print("guild_id_valid:", bool(snowflake.fullmatch(values.get("DISCORD_GUILD_ID", ""))))
print("channel_id_valid:", bool(snowflake.fullmatch(values.get("CODEX_VPS_DEFAULT_CHANNEL_ID", ""))))
print("allowed_user_count:", len(allowed))
print("approver_user_count:", len(approvers))
print("allowed_ids_valid:", all(snowflake.fullmatch(item) for item in allowed))
print("approver_ids_valid:", all(snowflake.fullmatch(item) for item in approvers))
print("relay_root_ok:", values.get("CODEX_VPS_ROOT") == "/home/sadmin")
print("relay_engine_ok:", values.get("CODEX_VPS_ENGINE", "exec").lower() == "exec")
print("relay_bypass_ok:", values.get("CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX", "").lower() == "true")
print("relay_skip_git_ok:", values.get("CODEX_VPS_SKIP_GIT_REPO_CHECK", "").lower() == "true")
print("session_id_present:", bool(values.get("CODEX_VPS_DEFAULT_SESSION_ID")))
PY
```

Expected result: `.env` is `sadmin:sadmin` mode `600`, it does not contain the
sudo-password key, allowed-user count is at least `1`, approver count is at
least `1` unless the operator explicitly chose no remote approval authority,
and all IDs are syntactically valid.

STOP if the relay `.env` contains the sudo-password key, has unsafe
permissions, lacks explicit allowed users, or points away from `/home/sadmin`.

## 17. Relay Preflight, Service, Hook, And Linger

The wizard delegates these steps to the relay repository. Verify:

```bash
sudo -iu sadmin bash -lc 'cd /home/sadmin/codex-vps-discord-relay && npm run preflight'
sudo loginctl show-user sadmin -p Linger
sudo -iu sadmin env XDG_RUNTIME_DIR="/run/user/$(id -u sadmin)" \
  systemctl --user is-active codex-vps-discord-relay.service
sudo -iu sadmin env XDG_RUNTIME_DIR="/run/user/$(id -u sadmin)" \
  systemctl --user status codex-vps-discord-relay.service --no-pager
```

Expected result: preflight passes, `Linger=yes`, and the user service is active.

STOP if preflight fails or the service is not healthy. Capture relay user
journal logs with the failure bundle.

## 18. Real Discord Round Trip

From an explicitly allowed Discord user in the configured channel, send:

```text
Reply with the hostname and say lsm relay checkpoint ok.
```

Expected result: Discord receives a response from the relay-backed VPS Server
Manager Codex session, and the response includes the requested phrase.

Only after observing the real Discord response, record the manual checkpoint:

```bash
sudo lsm-vps-init confirm-relay
sudo lsm-vps-init status
```

STOP if Discord does not receive the Codex response, if an unlisted Discord user
can trigger the privileged session, or if the reply comes from the wrong Codex
session.

## 19. Final Hardening

Run final hardening from an `sadmin` SSH session on port `65500`, and keep that
session open:

```bash
ssh -tt -i "$SSH_IDENTITY" -o IdentitiesOnly=yes \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey -p 65500 sadmin@"$VPS_IP"
sudo lsm-vps-init resume
```

Read the printed hardening plan. Confirm only if:

- The `sadmin` port-65500 proof is recorded.
- The Discord relay round trip is recorded.
- UFW Phase A is active with both SSH ports allowed.
- No unexpected Docker host-published public ports are present.

Verify in the same session immediately after the wizard completes:

```bash
printf 'current_ssh_connection=%s\n' "$SSH_CONNECTION"
sudo lsm-vps-init status
sudo sshd -t
sudo sshd -T | awk '/^(port|permitrootlogin|passwordauthentication|pubkeyauthentication) /{print}'
sudo sshd -T -C user=sadmin,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=65500 \
  | awk '/^exposeauthinfo /{print}'
sudo ufw status verbose
sudo fail2ban-client status sshd
systemctl is-enabled unattended-upgrades || true
```

Expected result:

- Current SSH session remains connected.
- `PermitRootLogin no`.
- `PasswordAuthentication no`.
- Effective SSH ports include `65500` and not `22`.
- Effective `sadmin` config does not retain `exposeauthinfo yes`.
- UFW no longer allows `22/tcp`.
- UFW allows `65500/tcp` and only selected application ports.
- fail2ban SSH jail is active on `65500`.
- unattended upgrades are enabled or service restart is non-fatal but configured.

Recovery while the current session still works:

```bash
sudo ufw allow 22/tcp
sudo install -m 0644 /dev/stdin /etc/ssh/sshd_config.d/01-lsm-vps-init-recovery.conf <<'EOF'
Port 22
Port 65500
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin prohibit-password
EOF
sudo sshd -t
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket || sudo systemctl restart ssh
```

Provider-console recovery if all SSH is broken:

```bash
sudo ufw --force disable
sudo install -m 0644 /dev/stdin /etc/ssh/sshd_config.d/01-lsm-vps-init-recovery.conf <<'EOF'
Port 22
Port 65500
PasswordAuthentication yes
PubkeyAuthentication yes
PermitRootLogin prohibit-password
EOF
sudo sshd -t
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket || sudo systemctl restart ssh
```

Remove `/etc/ssh/sshd_config.d/01-lsm-vps-init-recovery.conf` after recovery
and before retrying final hardening.

STOP if the current session drops, `sshd -t` fails, UFW removes every admin
path, or final config still exposes auth info.

## 20. New SSH Session After Final Hardening

From the workstation, prove port `65500` works with key-only auth:

```bash
ssh -tt -i "$SSH_IDENTITY" -o IdentitiesOnly=yes \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey -p 65500 sadmin@"$VPS_IP" \
  'id -un; printf "ssh_connection=%s\n" "$SSH_CONNECTION"'
```

Prove port `22` is not usable:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=8 -p 22 sadmin@"$VPS_IP" true \
  && echo 'port 22 reachable: FAIL' \
  || echo 'port 22 unavailable as expected: PASS'
```

Prove root SSH is disabled on port `65500`:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=8 \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey -p 65500 root@"$VPS_IP" true \
  && echo 'root ssh reachable: FAIL' \
  || echo 'root ssh unavailable as expected: PASS'
```

Expected result: `sadmin` succeeds on port `65500`; port `22` and root SSH do
not succeed.

STOP if a new `sadmin` key-only session cannot be opened on port `65500`.

## 21. Listening Ports And Docker Exposure

Inspect actual host listeners:

```bash
sudo ss -tulpn
sudo bash -lc 'command -v docker >/dev/null && docker ps --format "{{.Names}}\t{{.Ports}}" || true'
sudo bash -lc 'ss -tulpn | grep -E ":(2375|2376)[[:space:]]" && exit 1 || echo "Docker TCP API closed: PASS"'
```

Expected result:

- SSH listens on `65500`, not `22`.
- No database/helper/admin port is publicly listening unless explicitly selected.
- The Discord relay exposes no inbound listener.
- Docker Engine is not exposed on TCP `2375` or `2376`.

STOP if an unexpected public listener is present.

## 22. Reboot After Final Hardening

Reboot:

```bash
sudo systemctl reboot
```

Reconnect from the workstation:

```bash
ssh -tt -i "$SSH_IDENTITY" -o IdentitiesOnly=yes \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o PreferredAuthentications=publickey -p 65500 sadmin@"$VPS_IP"
```

Verify post-reboot state:

```bash
sudo lsm-vps-init status
sudo lsm-vps-init status --json | sudo tee /root/lsm-vps-init-status-after-final-reboot.json >/dev/null
sudo sshd -T | awk '/^(port|permitrootlogin|passwordauthentication|pubkeyauthentication) /{print}'
sudo sshd -T -C user=sadmin,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=65500 \
  | awk '/^exposeauthinfo /{print}'
sudo ufw status verbose
sudo fail2ban-client status sshd
sudo systemctl is-active unattended-upgrades || true
sudo -iu sadmin codex login status
sudo -iu sadmin env XDG_RUNTIME_DIR="/run/user/$(id -u sadmin)" \
  systemctl --user is-active codex-vps-discord-relay.service
ssh -o BatchMode=yes -o ConnectTimeout=8 -p 22 sadmin@"$VPS_IP" true \
  && echo 'post-reboot port 22 reachable: FAIL' \
  || echo 'post-reboot port 22 unavailable as expected: PASS'
```

Expected result:

- SSH works only through `sadmin` on port `65500`.
- Port `22` remains unavailable.
- Relay user service is active after reboot.
- Codex login status succeeds as `sadmin`.
- UFW and fail2ban remain active.
- Bootstrap status reports completion or only the Docker dry-run handoff as
  pending if it has not been run yet.

STOP if port `65500` fails after reboot or if SSH hardening regresses.

## 23. Docker Hosting Stack Dry-Run Handoff

Run the Docker Hosting Stack module only in dry-run/validation mode. If the
wizard already selected this module, resume the final stage:

```bash
sudo lsm-vps-init resume
```

When prompted, choose the intended rehearsal mode, for example `base`, `n8n`,
`standalone-app`, or `website-migration`.

Verify the checkout and dry-run evidence:

```bash
sudo -iu sadmin test -d /home/sadmin/docker-hosting-stack/.git
sudo -iu sadmin bash -lc 'cd /home/sadmin/docker-hosting-stack && git status --short'
sudo -iu sadmin bash -lc 'cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode base'
sudo -iu sadmin bash -lc 'cd /home/sadmin/docker-hosting-stack && scripts/bootstrap_layout.sh --dry-run'
```

For an `n8n` rehearsal, use the repo-owned dry-run:

```bash
sudo -iu sadmin bash -lc 'cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode n8n'
sudo -iu sadmin bash -lc 'cd /home/sadmin/docker-hosting-stack && scripts/install_n8n.sh --dry-run'
```

Expected result: the private repo is accessible, validation is explicit, and
only dry-run commands are used. No Docker service or application port is exposed
unless the selected repo workflow explicitly requires it and the operator has
approved that separate action.

STOP if any command attempts a non-dry-run install, exposes unexpected ports, or
requires unresolved `.env` values. Do not improvise a parallel installer.

## 24. Secret And Log Safety Review

Scan the installed public bootstrap source:

```bash
sudo /usr/local/lib/lsm-vps-init/scripts/secret_scan.sh
```

Scan bootstrap state and log for common token-shaped values without printing
matches:

```bash
sudo python3 - <<'PY'
from pathlib import Path
import re

targets = [
    Path("/var/lib/lsm-vps-init/state.json"),
    Path("/var/log/lsm-vps-init/bootstrap.log"),
]
patterns = {
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
    "openai_token": re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    "private_key": re.compile(r"BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY"),
    "discord_token_shape": re.compile(r"[MN][A-Za-z\d_-]{20,}\.[A-Za-z\d_-]{6,}\.[A-Za-z\d_-]{20,}"),
}
failed = False
for path in targets:
    text = path.read_text(errors="replace") if path.exists() else ""
    for name, pattern in patterns.items():
        if pattern.search(text):
            print(f"{path}: {name}: FAIL")
            failed = True
if failed:
    raise SystemExit(1)
print("state_and_log_secret_shape_scan: PASS")
PY
```

Expected result: scans pass and neither state nor bootstrap log contains
credential material.

STOP if a secret-shaped value is found. Capture the failure bundle and do not
publish artifacts from this run.

## 25. Completion Evidence

Capture final acceptance evidence:

```bash
sudo lsm-vps-init status
sudo lsm-vps-init status --json | sudo tee /root/lsm-vps-init-final-status.json >/dev/null
sudo stat -c '%U:%G %a %n' /var/lib/lsm-vps-init/state.json /var/log/lsm-vps-init/bootstrap.log /home/sadmin/.env /home/sadmin/codex-vps-discord-relay/.env
sudo ss -tulpn | sudo tee /root/lsm-vps-init-final-listeners.txt >/dev/null
sudo ufw status verbose | sudo tee /root/lsm-vps-init-final-ufw.txt >/dev/null
sudo fail2ban-client status sshd | sudo tee /root/lsm-vps-init-final-fail2ban.txt >/dev/null
```

Expected result: the wizard reports complete, or reports only an explicitly
documented non-blocking residual. No secret values are printed.

After review, destroy the disposable VPS through the provider control panel.
Do not reuse it as production infrastructure.
