# Loud Sky Media VPS Initialization Wizard

Public, resumable bootstrap framework for preparing a fresh Loud Sky Media VPS
before private server-management repositories take over.

Target for the first implementation:

- Ubuntu 24.04 LTS

This repository is intentionally not the Docker hosting stack and not the Codex
Discord relay. It establishes the administrative path, installs common tooling,
authenticates GitHub and Codex as `sadmin`, delegates selected capabilities to
their private repositories, verifies the Discord/Codex management path, and
only then permits final SSH/firewall hardening.

## Start A New VPS

Preferred convenience form, once the public repository URL exists and a stable
release channel is promoted:

```bash
curl -fsSL https://raw.githubusercontent.com/LoudSkyMedia/server-bootstrap/stable/bootstrap.sh \
  -o /tmp/lsm-vps-bootstrap.sh \
  && sudo bash /tmp/lsm-vps-bootstrap.sh
```

Version-pinned form, once releases are published:

```bash
curl -fsSL https://raw.githubusercontent.com/LoudSkyMedia/server-bootstrap/v0.1.0/bootstrap.sh \
  -o /tmp/lsm-vps-bootstrap.sh \
  && sudo LSM_VPS_INIT_REF=v0.1.0 \
    LSM_VPS_INIT_SHA256=<release-archive-sha256> \
    bash /tmp/lsm-vps-bootstrap.sh
```

The bootstrap installs the local command:

```bash
sudo lsm-vps-init
sudo lsm-vps-init resume
sudo lsm-vps-init status
```

No production VPS should be initialized from this repository until the first
implementation is reviewed and a public release URL/checksum policy is approved.

## What Happens Interactively

The wizard asks for secrets only in a real terminal. It will not prompt from an
unattended systemd service or no-TTY context.

Interactive checkpoints include:

- setting a new root password for console/out-of-band recovery
- creating or updating `sadmin`
- storing `SUDO_PASSWORD=` in `/home/sadmin/.env` with mode `0600`
- installing an `sadmin` SSH public key
- proving a second SSH login to `sadmin@<public-ip>` on port `65500` with a
  generated key-only checkpoint command
- authenticating `gh` and Codex as `sadmin`
- selecting optional private repository modules
- configuring and functionally testing the Discord relay before final hardening

## Resumability

State and logs live at:

```text
/var/lib/lsm-vps-init/state.json
/var/log/lsm-vps-init/bootstrap.log
/usr/local/sbin/lsm-vps-init
```

The state file is root-protected and must not contain passwords, tokens, private
keys, or generated secrets. Each stage rechecks real machine state where that is
practical before trusting a prior checkpoint.

Bootstrap logs are root-protected (`0600`) and secret stdin is redacted.

If the shell disconnects, a package operation is interrupted, or the machine
reboots, log back in and run:

```bash
sudo lsm-vps-init resume
```

An MOTD reminder is installed while initialization is incomplete.

Interactive resumes use `tmux` when available:

```bash
sudo tmux attach-session -t lsm-vps-init
```

Persistent state remains authoritative if tmux exits or the host reboots.

## SSH Transition Safety

SSH migration is two-phase:

1. Add port `65500` while keeping port `22`.
2. Require independent operator confirmation of `sadmin` public-key access on
   port `65500`.
3. Require the Discord/Codex relay round trip.
4. Only then disable root login, disable SSH password auth, remove port `22`,
   and enable UFW/fail2ban hardening.

The wizard backs up SSH configuration, validates with `sshd -t`, checks
effective config with `sshd -T`, and refuses to continue if the verified
recovery path is missing. Temporary OpenSSH `ExposeAuthInfo` proof
instrumentation is scoped to `sadmin` and is removed during final hardening.

## Secrets Policy

The bootstrap never logs or stores:

- root passwords
- sudo passwords beyond the required `/home/sadmin/.env`
- GitHub tokens
- Discord bot tokens
- Codex auth files
- SSH private keys

The operational `/home/sadmin/.env` file intentionally contains:

```text
SUDO_PASSWORD=
```

It is owned by `sadmin:sadmin` and mode `0600`. It is not exported globally,
copied into the relay `.env`, exposed to Docker containers, or passed as a
process argument. Bootstrap code parses this file deliberately; it does not
`source` arbitrary password text.

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

## Local Development

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

## Acceptance Rehearsal

Before any production use or public release, run the disposable-VPS rehearsal:

- [Acceptance test runbook](docs/acceptance-test-runbook.md)
- [Acceptance checklist](docs/acceptance-test-checklist.md)

## Recovery If Bootstrap Stops

Run:

```bash
sudo lsm-vps-init status
sudo lsm-vps-init resume
```

The status output reports completed, pending, blocked/manual stages, current
stage, and whether a reboot is pending. If a stage is blocked, fix the specific
manual prerequisite shown in the output and rerun `resume`.
