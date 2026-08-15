# Loud Sky Media VPS Initialization Wizard

Public, resumable bootstrap framework for preparing a fresh Loud Sky Media VPS
before private server-management repositories take over.

## What This Is

This repository is intentionally not the Docker hosting stack and not the Codex
Discord relay. It establishes the administrative path, installs common tooling,
authenticates GitHub and Codex as `sadmin`, delegates selected capabilities to
their private repositories, verifies the Discord/Codex management path, and
only then permits final SSH/firewall hardening.

The bootstrap installs the local command:

```bash
sudo lsm-vps-init
sudo lsm-vps-init resume
sudo lsm-vps-init status
```

## Supported Platform / Release Status

Supported platform:

- Ubuntu 24.04 LTS

The disposable Ubuntu 24.04 acceptance rehearsal has passed for this bootstrap.
The current public install channel is `main` because no `stable` branch or
immutable version tag exists yet.

Release-channel policy:

- `main` is the current repository history and initial publication channel.
- `stable` is planned as the moving accepted-release channel, but it has not
  been created yet.
- Immutable version tags/releases are planned separately with published
  checksums.
- Do not use examples that mention `stable` or a concrete `vX.Y.Z` tag until
  those refs exist in GitHub.

## Before You Start

Prepare these before opening the bootstrap on a new server:

- A fresh Ubuntu 24.04 LTS VPS.
- Initial root SSH, root-capable SSH, or provider console access.
- The original SSH session kept open until the independent `sadmin` port
  `65500` public-key checkpoint succeeds.
- A local workstation with an OpenSSH client.
- A second local terminal for SSH recovery-path verification.
- A local browser for GitHub OAuth and Codex login.
- A GitHub account with access to selected private Loud Sky Media modules:
  `LoudSkyMedia/codex-vps-discord-relay` and/or
  `LoudSkyMedia/docker-hosting-stack`.
- Discord bot details if selecting the Codex VPS Discord Relay module.
- Cloudflare and n8n details if selecting Docker Hosting Stack n8n.

The wizard asks for secrets only in a real terminal. It will not prompt from an
unattended systemd service or no-TTY context.

## Generate Your SSH Key

Generate the administrative SSH key on your local workstation, not on the VPS.
Only paste the `.pub` line when the bootstrap asks:

```text
Paste sadmin SSH public key
```

Linux, macOS, or WSL:

```bash
ssh-keygen \
  -t ed25519 \
  -a 100 \
  -f ~/.ssh/lsm_vps_ed25519 \
  -C "lsm-vps-admin"

cat ~/.ssh/lsm_vps_ed25519.pub
```

Windows PowerShell with OpenSSH:

```powershell
New-Item -ItemType Directory -Force "$HOME\.ssh"
ssh-keygen.exe `
  -t ed25519 `
  -a 100 `
  -f "$HOME\.ssh\lsm_vps_ed25519" `
  -C "lsm-vps-admin"

Get-Content "$HOME\.ssh\lsm_vps_ed25519.pub"
```

Use a passphrase where practical, and prefer a dedicated admin key per
VPS/environment. Never paste, upload, or send the private key.

Final SSH login example after hardening:

```bash
ssh -p 65500 -i ~/.ssh/lsm_vps_ed25519 sadmin@SERVER_IP
```

PowerShell equivalent:

```powershell
ssh -p 65500 -i "$HOME\.ssh\lsm_vps_ed25519" sadmin@SERVER_IP
```

## Prepare Discord Bot

This is required only when selecting the `codex-vps-discord-relay` module. The
relay repository is private, so the essential operator setup is repeated here.

1. Open the Discord Developer Portal.
2. Create a Discord application and bot.
3. On the Bot page, create/reset/copy the bot token.
4. Store the token temporarily in a password manager.
5. Enable Message Content Intent.
6. Leave Presence Intent and Server Members Intent disabled.
7. Use Guild Install only.
8. Give the bot these exact permissions:
   - View Channel
   - Send Messages
   - Embed Links
   - Attach Files
   - Read Message History
9. Use permission integer `117760`.
10. Invite the bot to the intended Discord server/guild.
11. Create and restrict a private VPS operations channel.
12. Enable Discord Developer Mode in your Discord client.
13. Copy the guild/server ID from the server menu.
14. Copy the channel ID from the private operations channel.
15. Copy each operator user ID from the user profile/context menu.

Bootstrap prompts for:

| Prompt label | Environment key |
| --- | --- |
| `Discord bot token` | `DISCORD_BOT_TOKEN` |
| `Discord server/guild ID` | `DISCORD_GUILD_ID` |
| `Discord channel ID for the VPS session` | `CODEX_VPS_DEFAULT_CHANNEL_ID` |
| `Comma-separated allowed Discord user IDs` | `CODEX_VPS_ALLOWED_USER_IDS` |
| `Comma-separated allowed Discord approver user IDs` | `CODEX_VPS_ALLOWED_APPROVER_USER_IDS` |

`CODEX_VPS_DEFAULT_SESSION_ID` normally defaults to the VPS Server Manager
Codex session created by the bootstrap, so you do not need to gather it in
advance.

`CODEX_VPS_ALLOWED_USER_IDS` must contain at least one explicit Discord user
ID. `CODEX_VPS_ALLOWED_APPROVER_USER_IDS` may be empty only if you explicitly
choose the no-remote-approval setup when prompted.

Never paste the Discord bot token into Discord, a GitHub issue, documentation,
or a shell command argument. Paste it only into the bootstrap hidden secret
prompt. Rotate the token immediately if it is exposed.

## Prepare Docker/n8n Credentials

This is required only when selecting Docker Hosting Stack n8n.

Have these values ready:

- `CADDY_ACME_EMAIL`: email address for Caddy ACME/HTTPS certificate issuance.
- `CF_ACCOUNT_ID`: Cloudflare account ID.
- `CF_API_TOKEN`: Cloudflare API token.
- `N8N_HOSTNAME`: public hostname for n8n.

Use least-privilege Cloudflare API tokens:

- Zone read for audited zones.
- DNS edit only for zones that may be changed.
- Account read if account-level validation is required.

Do not put `N8N_ENCRYPTION_KEY` in the Docker Hosting Stack repository `.env`.
That secret belongs under `/srv/hosting/secrets/n8n/n8n.env` in the hosting
stack workflow.

## Start A New VPS

Current initial-publication command:

```bash
curl -fsSL https://raw.githubusercontent.com/LoudSkyMedia/server-bootstrap/main/bootstrap.sh \
  -o /tmp/lsm-vps-bootstrap.sh \
  && sudo bash /tmp/lsm-vps-bootstrap.sh
```

This command uses `main` because `stable` does not exist yet. Once a `stable`
branch is created, it should point only to accepted revisions.

Version-pinned releases are not published yet. When a real tag exists, use the
tag and checksum from the GitHub release with `LSM_VPS_INIT_REF=vX.Y.Z` and
`LSM_VPS_INIT_SHA256=<release-archive-sha256>`.

## What Happens Interactively

The wizard walks through these major checkpoints:

- Set a new root recovery password. The root password is not stored by the
  bootstrap.
- Create or update `sadmin`.
- Set a new `sadmin` sudo password.
- Store `SUDO_PASSWORD=` in `/home/sadmin/.env` with owner `sadmin:sadmin` and
  mode `0600`.
- Install the pasted `sadmin` SSH public key.
- Add SSH port `65500` while keeping port `22`.
- Enable UFW Phase A with both `22/tcp` and `65500/tcp` allowed.
- Prove a second key-only SSH login as `sadmin` on port `65500`.
- Install management tooling.
- Authenticate GitHub CLI as `sadmin`.
- Install and authenticate Codex as `sadmin`.
- Create the VPS Server Manager Codex session.
- Select optional private repository modules.
- Configure and functionally test the Discord relay before final hardening.
- Apply final SSH/firewall hardening only after recovery access and relay
  management are verified.

GitHub authentication uses the web/device OAuth flow by default. When `gh`
prints a one-time code and device-login URL, open that URL on your local
workstation browser. PAT/token login is only an explicit fallback.

Codex login is interactive as `sadmin`. Do not paste GitHub or Codex secrets
into documentation, tickets, or command-line arguments.

## SSH Transition Safety

SSH migration is deliberate:

1. Keep the original port-`22` session open.
2. Bootstrap temporarily enables port `65500` alongside port `22`.
3. Open a second local terminal.
4. Use the exact recovery/checkpoint command printed by the wizard.
5. Confirm the second session is `sadmin`, uses server-side port `65500`, and
   requires public-key authentication.
6. Continue only after the Discord relay round trip is also verified.
7. Final hardening removes port `22`, disables root SSH, disables SSH password
   authentication, keeps public-key auth, and retains port `65500`.

The wizard backs up SSH configuration, validates with `sshd -t`, checks
effective config with `sshd -T`, and refuses to continue if the verified
recovery path is missing. Temporary OpenSSH `ExposeAuthInfo` proof
instrumentation is scoped to `sadmin` and is removed during final hardening.

## Resumability / Recovery

State and logs live at:

```text
/var/lib/lsm-vps-init/state.json
/var/log/lsm-vps-init/bootstrap.log
/usr/local/sbin/lsm-vps-init
```

The state file is root-protected and must not contain passwords, tokens, private
keys, or generated secrets. Each stage rechecks real machine state where that is
practical before trusting a prior checkpoint.

If the shell disconnects, a package operation is interrupted, or the machine
reboots, log back in and run:

```bash
sudo lsm-vps-init status
sudo lsm-vps-init resume
```

Interactive resumes use `tmux` when available:

```bash
sudo tmux attach-session -t lsm-vps-init
```

Persistent state remains authoritative if tmux exits or the host reboots. An
MOTD reminder is installed while initialization is incomplete.

If a stage is blocked, stop at that checkpoint, fix the specific prerequisite
shown in `status`, and rerun `resume`. Use the provider console for recovery if
SSH access is broken.

## Secrets Policy

The bootstrap never logs or stores in state:

- root passwords
- GitHub tokens
- Discord bot tokens
- Codex auth files
- SSH private keys

The operational `/home/sadmin/.env` file intentionally contains:

```text
SUDO_PASSWORD=
```

It is owned by `sadmin:sadmin` and mode `0600`. The `sadmin` sudo password is
securely retained there for the approved automation design. It is not an SSH
password-login mechanism after final hardening.

The value is not exported globally, copied into the Discord relay `.env`,
exposed to Docker containers, or passed as a process argument. Bootstrap code
parses this file deliberately; it does not `source` arbitrary password text.

When the Docker Hosting Stack module is selected, the bootstrap copies this
same value into `/home/sadmin/docker-hosting-stack/.env` only after verifying
both protected env-file boundaries. That repository env file is used by the
stack's stdin-based sudo helper; it is not an application/container env file.

## Optional Modules

Initial module contracts:

- `codex-vps-discord-relay`: clones
  `LoudSkyMedia/codex-vps-discord-relay` to
  `/home/sadmin/codex-vps-discord-relay`, writes its `.env`, then delegates to
  its own preflight, service installer, hook installer, tests, and systemd user
  service.
- `docker-hosting-stack`: clones `LoudSkyMedia/docker-hosting-stack` to
  `/home/sadmin/docker-hosting-stack`, starts with the repository's audit,
  validation, and dry-run workflows, then follows its runbooks for selected
  hosting capabilities such as base hosting, standalone apps, n8n, or website
  migration.

The Discord relay is outbound-only and should not open an inbound public port.
Docker hosting ingress ports are derived from selected capabilities, not from a
large static allowlist. Published Docker host ports are inspected directly
because Docker-published traffic is not assumed to be constrained by UFW alone.

## Development / Acceptance

Use dry-run and mocks. Do not run the wizard against the development machine's
real SSH, firewall, users, or package manager.

```bash
python3 -m unittest discover -s tests
bash -n bootstrap.sh bin/lsm-vps-init scripts/secret_scan.sh
./bin/lsm-vps-init --dry-run --state-dir /tmp/lsm-vps-init-state status
```

ShellCheck is recommended when available:

```bash
shellcheck bootstrap.sh bin/lsm-vps-init scripts/secret_scan.sh
```

Run the public-safety scan before publishing:

```bash
scripts/secret_scan.sh
```

Acceptance materials:

- [Acceptance test runbook](docs/acceptance-test-runbook.md)
- [Acceptance checklist](docs/acceptance-test-checklist.md)
