# Architecture And State Machine

## Design Goals

`lsm-vps-init` is a small public front door. It installs enough local machinery
to safely prepare a new Ubuntu 24.04 VPS, then delegates repository-specific
deployment behavior to private repositories that own those domains.

The implementation is deliberately split into:

- `bootstrap.sh`: tiny public entrypoint that needs only `curl`, `tar`, `gzip`,
  Python 3, and `tmux` on the target after prerequisite installation.
- `bin/lsm-vps-init`: stable command installed to `/usr/local/sbin`.
- `lsm_vps_init/`: standard-library Python wizard, stage definitions, state,
  command execution, file rendering, and module handoff logic.
- `tests/`: mock/dry-run coverage for state transitions and dangerous rendering.

## Persistence

Default target paths:

```text
/var/lib/lsm-vps-init/state.json
/var/log/lsm-vps-init/bootstrap.log
/usr/local/sbin/lsm-vps-init
/usr/local/lib/lsm-vps-init
/etc/update-motd.d/99-lsm-vps-init
```

State schema:

```json
{
  "schema_version": 1,
  "created_at": "ISO-8601 UTC",
  "updated_at": "ISO-8601 UTC",
  "last_boot_id": "boot-id",
  "current_stage": "stage-slug",
  "stages": {
    "stage-slug": {
      "status": "pending|in_progress|completed|blocked|failed",
      "started_at": "ISO-8601 UTC",
      "completed_at": "ISO-8601 UTC",
      "blocked_reason": "operator-safe text",
      "evidence": {
        "operator-safe": "metadata only"
      }
    }
  },
  "facts": {
    "public_ipv4": "detected public IPv4",
    "codex_session_id": "non-secret session UUID",
    "docker_hosting_mode": "base|standalone-app|n8n|website-migration"
  },
  "selected_modules": {
    "codex-vps-discord-relay": true,
    "docker-hosting-stack": false
  },
  "checkpoints": {
    "ssh_recovery_verified": false,
    "relay_round_trip_verified": false
  },
  "revalidation": {
    "boot_changed": false,
    "boot_changed_at": null
  },
  "reboot": {
    "pending": false,
    "required_since": null,
    "last_seen_boot_id": null
  }
}
```

The state writer rejects sensitive key names such as `password`, `token`,
`secret`, and `private_key`. State is written atomically with mode `0600`.
Command logs are created under a `0700` directory and forced to mode `0600`.
Secret stdin is logged only as `<stdin: redacted>`; bootstrap code must not pass
passwords, tokens, auth file contents, or private keys as command-line
arguments.

## Stage Flow

| ID | Slug | Purpose | Blocking rule |
| --- | --- | --- | --- |
| 0 | `bootstrap_installation` | Verify OS/root, create state/log paths, install command/MOTD | Blocks on unsupported OS or missing privilege |
| 1 | `system_update` | Run apt update/upgrade and detect `/var/run/reboot-required` | Blocks on dpkg/apt failure |
| 2 | `root_password` | Securely set a new root password for console recovery | Requires TTY |
| 3 | `sadmin_user` | Create `sadmin`, set password, write `/home/sadmin/.env` | Requires TTY and sudo validation |
| 4 | `sadmin_ssh_key` | Validate and install an SSH public key | Requires TTY or supplied public key |
| 5 | `ssh_dual_port` | Configure SSH on both `22` and `65500` | Blocks on invalid sshd config or missing listeners |
| 6 | `firewall_phase_a` | Enable UFW with both `22/tcp` and `65500/tcp` allowed | Blocks if current SSH session port would not remain allowed |
| 7 | `ssh_recovery_checkpoint` | Verify independent key-based `sadmin` login on `65500` | Hard checkpoint with second-session proof |
| 8 | `management_tooling` | Install curl, git, gh, jq, openssl, Python, Node/npm, tmux | Blocks on package/tool failure |
| 9 | `github_auth` | Authenticate GitHub CLI as `sadmin`, setup git helper, verify repo access | Requires TTY or stdin PAT |
| 10 | `codex_install_auth` | Install/auth Codex as `sadmin`, configure `gpt-5.5` + `xhigh`, verify bypass flag | Blocks if model/effort unavailable |
| 11 | `codex_manager_session` | Create/resume the VPS Server Manager Codex session | Blocks if no session ID can be captured |
| 12 | `repository_selection` | Select private repository capability modules | Requires operator choice, defaults relay on |
| 13 | `discord_relay_install` | Clone/update relay, configure `.env`, run repo-owned install/preflight/hooks/tests | Blocks on relay preflight/service failure |
| 14 | `discord_relay_checkpoint` | Require real Discord -> relay -> Codex -> Discord round trip | Hard manual checkpoint |
| 15 | `final_host_hardening` | Disable root/password SSH, remove `22`, configure UFW/fail2ban/unattended upgrades | Requires live revalidation of both recovery paths |
| 16 | `docker_hosting_stack` | Clone/update hosting stack, hydrate protected repo `.env`, and hand off to selected dry-run/runbook workflows | Blocks on missing capability decisions or unsafe env boundaries |

## Idempotency Model

Every stage has a detection function. A completed state checkpoint is accepted
only when the detector still passes, when the stage represents an explicitly
manual checkpoint that cannot be machine-verified, or when a later completed
stage intentionally supersedes a temporary transitional state.

Examples:

- `sadmin_user` checks user/group/home and `/home/sadmin/.env` permissions.
- `ssh_dual_port` checks effective SSH config and listeners until final host
  hardening supersedes the temporary dual-port state.
- `github_auth` runs `gh auth status` as `sadmin` and verifies access to the
  selected private repositories.
- `codex_install_auth` runs `codex login status`, checks `--help` for the
  required bypass flag, and inspects the model catalog when supported.
- `discord_relay_install` delegates to `npm run preflight` and the relay's own
  service installer instead of duplicating its internals.

## Historical Versus Mutable Completion

Stage completion is either historical or mutable:

| Stage | Class | Revalidation rule |
| --- | --- | --- |
| `bootstrap_installation` | Mutable | Recheck Ubuntu 24.04 and state path |
| `system_update` | Historical | Do not rerun automatically; continue to detect reboot-required state |
| `root_password` | Historical | Recheck root has a password status, never store the value |
| `sadmin_user` | Mutable | Recheck user existence, sudo env-file mode/key, and `/home/sadmin/AGENTS.md` |
| `sadmin_ssh_key` | Mutable | Recheck `authorized_keys` contains at least one supported public key |
| `ssh_dual_port` | Transitional mutable | Recheck effective sshd ports include both `22` and `65500` until superseded by `final_host_hardening` |
| `firewall_phase_a` | Transitional mutable | Recheck UFW is active and allows both `22/tcp` and `65500/tcp` until superseded by `final_host_hardening` |
| `ssh_recovery_checkpoint` | Historical proof plus mutable dependency | Keep proof metadata, but recheck current `65500` sshd config/listener before lock-down |
| `management_tooling` | Mutable | Recheck executable command availability, package-only prerequisites such as `ca-certificates`, and Node.js major version |
| `github_auth` | Mutable | Re-run `gh auth status` and private-repo access checks |
| `codex_install_auth` | Mutable | Re-run Codex login/config/bypass/model checks |
| `codex_manager_session` | Mutable-ish | Recheck a valid session ID is known; downstream relay preflight verifies transcript readability |
| `repository_selection` | Historical operator choice | Reused unless operator changes selected modules |
| `discord_relay_install` | Mutable | Re-run relay preflight and user service health checks |
| `discord_relay_checkpoint` | Historical proof plus mutable dependency | Keep operator round-trip proof, but recheck relay service/preflight before lock-down |
| `final_host_hardening` | Mutable | Recheck effective SSH, UFW, fail2ban, and Docker exposure |
| `docker_hosting_stack` | Mutable | Recheck checkout exists and run repo-owned validation/dry-runs before handoff |

Supersession is lifecycle metadata, not a blanket waiver. After
`final_host_hardening` completes, or when live system state authoritatively
proves the final SSH transition has already happened, the expected SSH state no
longer includes port `22` or UFW's temporary `22/tcp` allow rule. Status and
resume therefore skip the earlier transitional SSH/UFW stages instead of
reopening the old management path. This narrower supersession requires hardened
effective sshd config, no port-22 listener, a verified port-`65500` recovery
checkpoint, valid relay prerequisites when selected, active UFW, safe UFW
defaults, and an allow for `65500/tcp`; it does not require capability-specific
Docker web-ingress cleanup to be complete. If final hardening still needs to
remove stale managed web rules, the current stage is `final_host_hardening`, not
`ssh_dual_port` or `firewall_phase_a`.

Immediately before `final_host_hardening`, the wizard revalidates current sshd
config/listeners, UFW Phase A, relay health when selected, and Docker
host-published ports. Docker validation is based on actual published host ports
reported by Docker, because Docker's packet handling can route published
container traffic before UFW's normal input rules.

## Reboot Handling

The wizard records `/var/run/reboot-required` but does not automatically reboot
before these recovery prerequisites exist:

- root password set
- `sadmin` account available
- `sadmin` SSH public key installed
- preferably port `65500` key access verified

After reboot, a changed boot ID is recorded, prior critical assumptions are
rechecked, and `resume` continues from the first incomplete or invalidated
stage. A boot change sets `revalidation.boot_changed=true` in state so status
and later stages can distinguish a normal resume from a post-reboot resume.

## SSH And Firewall Strategy

Ubuntu 24.04 reads `/etc/ssh/sshd_config` and
`/etc/ssh/sshd_config.d/*.conf` into `ssh.socket` through a systemd generator,
so SSH changes are made through an owned sshd drop-in and followed by
`systemctl daemon-reload`. The wizard detects whether `ssh.socket` or
`ssh.service` is active before deciding whether to restart the socket or the
service. The bootstrap-owned SSH drop-in is
`/etc/ssh/sshd_config.d/00-lsm-vps-init.conf` so its single-value hardening
keywords are encountered before cloud-init/vendor drop-ins such as
`50-cloud-init.conf`. Older bootstrap-owned
`/etc/ssh/sshd_config.d/99-lsm-vps-init.conf` files are migrated by writing the
new early file, validating sshd configuration, then removing only the obsolete
bootstrap-owned late file.

The dual-port SSH drop-in enables OpenSSH `ExposeAuthInfo` only inside
`Match User sadmin`. This is temporary bootstrap instrumentation used solely to
prove that the recovery connection used public-key authentication. The
`ssh_recovery_checkpoint` command must be run from a second SSH session as
`sadmin` on server-side port `65500` with client password and keyboard
interactive authentication disabled. The proof command records only:

```text
user=sadmin
local_ssh_port=65500
publickey_required=true
publickey_auth_verified=true
auth_proof_source=SSH_USER_AUTH
verified=true
verified_at=<timestamp>
```

It does not store the nonce after successful verification and never records SSH
public key or private key material. Direct nonce submission from the original
root session is rejected. Final hardening rewrites the owned sshd drop-in with
`ExposeAuthInfo no`, validates with `sshd -t` and `sshd -T`, reloads SSH only
after validation, then verifies the effective `sadmin` config no longer exposes
auth info.

Firewall transition is two-phase:

- Phase A enables UFW early with default-deny incoming, default-allow outgoing,
  and both `22/tcp` and `65500/tcp` explicitly allowed.
- Phase B runs only after `sadmin` SSH recovery on `65500` and the
  Discord/Codex relay round trip are verified. It removes `22/tcp`, retains
  `65500/tcp`, and adds only explicitly selected application ports.

Docker hosting adds `80/tcp` and `443/tcp` only when web ingress is selected.
Mail, SFTP, admin tools, database ports, Docker TCP, and relay inbound ports are
never opened implicitly.

## tmux Resilience

`sudo lsm-vps-init resume` runs the interactive wizard inside a predictable
`tmux` session named `lsm-vps-init` when tmux is available and the command is
not already inside tmux. Reattach with:

```bash
sudo tmux attach-session -t lsm-vps-init
```

Correctness does not depend on tmux. If tmux exits or the server reboots,
persistent state remains authoritative and `sudo lsm-vps-init resume` continues
from the appropriate checkpoint.

## Node.js Runtime

Ubuntu 24.04's repository Node.js can be older than the relay requirement. The
wizard accepts any existing `node`/`npm` with Node.js major version `20` or
newer. If the existing runtime is missing or too old, it installs the pinned
official Node.js LTS binary `v24.19.0` from `nodejs.org` under `/opt/nodejs`.

The downloaded Node.js release keyring is not treated as a trust root by
itself. The bootstrap source pins reviewed Node release primary fingerprints in
`NODEJS_RELEASE_KEY_FINGERPRINTS`. During installation the downloaded keyring
must contain only pinned primary fingerprints, and the `VALIDSIG` signer for
`SHASUMS256.txt.asc` must also be one of those pinned fingerprints. Only then
does the installer accept the signed checksum file and verify the tarball
SHA-256. `node`, `npm`, `npx`, and `corepack` are symlinked into
`/usr/local/bin` so user systemd services survive reboot without shell startup
files.

The pinned Node version and release-key fingerprint list must both be reviewed
before each public release.

## Codex Session Contract

Bootstrap-managed Codex execution is centralized around one command builder.
The initial VPS Server Manager session and the direct resume probe both use:

```text
working root: /home/sadmin
model: gpt-5.5
model_reasoning_effort: xhigh
--dangerously-bypass-approvals-and-sandbox
--skip-git-repo-check
```

New session IDs are captured from structured `codex exec --json` output by
strictly parsing a `thread.started` JSONL event with a UUID `thread_id`.
Human-readable output is not scraped. If that event is unavailable, the wizard
falls back to an explicit operator-supplied UUID.

The current Discord relay exec engine builds `codex exec resume` from its own
repository code. For bootstrap-managed privileged installs, the bootstrap
therefore verifies the relay env contract (`CODEX_VPS_ROOT=/home/sadmin`,
exec engine, bypass flag, skip-git check, default session ID) and verifies
`/home/sadmin/.codex/config.toml` contains the required model/reasoning defaults
before and after relay preflight.

## Sudo Password File

`/home/sadmin/.env` intentionally stores `SUDO_PASSWORD=`. The value is written
as a single shell-compatible assignment with robust quoting, but bootstrap code
and generated instructions must parse the file deliberately rather than using
arbitrary `source /home/sadmin/.env`. Password values with leading/trailing
spaces, tabs, shell metacharacters, quotes, `#`, `=`, backslashes, backticks,
parentheses, and exclamation marks are supported as single-line values. NUL,
newline, and carriage return are rejected because they cannot be safely
represented in the chosen single-line format.

When the Docker Hosting Stack module is selected, `/home/sadmin/.env` remains
the source of truth for `SUDO_PASSWORD`. The bootstrap deliberately parses it,
verifies protected file ownership and mode, and writes the same value into the
protected ignored `/home/sadmin/docker-hosting-stack/.env` so the stack's own
stdin-based sudo helper works in a fresh noninteractive `sadmin` process. This
handoff must not place the value in bootstrap state, logs, command arguments,
relay configuration, or application/container env files.

Docker Hosting Stack capability selection happens during repository selection,
before final host hardening. The selected nonsecret capability is persisted as
`facts.docker_hosting_mode` and reused by Stage 15 and Stage 16. The user-facing
capability names map to Docker validator modes as follows:

```text
base              -> base
standalone-app    -> standalone-app
n8n               -> n8n
website-migration -> migration
```

That same capability controls final inbound firewall rules. Management SSH on
`65500/tcp` is always retained. `base`, `n8n`, and `website-migration` retain
public `80/tcp` and `443/tcp` for their public web workflows; `standalone-app`
does not automatically imply public HTTP/HTTPS ingress. If a legacy state
completed Stage 15 before the capability was recorded, or later marked Stage 15
blocked/failed even though SSH was already final-hardened, resume does not replay
the temporary port-22 transition. Stage 15 records the capability when needed and
reconciles stale managed web allows before final completion.

## Release Trust

The working repository name remains `server-bootstrap`; the recommended public
remote is `LoudSkyMedia/server-bootstrap`.

Production usage should not depend on mutable `main`. The bootstrap defaults to
`stable`, the moving accepted release channel.
Release process:

1. Publish reviewed immutable tags such as `vX.Y.Z`.
2. Attach an archive checksum manifest and, ideally, a signed release
   attestation.
3. Maintain a convenience bootstrap URL that resolves to the current stable
   release, not unaccepted `main` work.
4. Document a pinned form using `LSM_VPS_INIT_REF=vX.Y.Z` and
   `LSM_VPS_INIT_SHA256=<sha256>` for reproducible installs.
5. Advance `stable` only after an accepted revision is selected.

## Module Contract

Modules expose a small operational contract in code and docs:

```text
detect
prerequisites
install
configure
verify
resume
firewall_ports
```

Version 1 implements these contracts as Python functions, not as a plugin
platform. The goal is clear separation without hiding logic behind dynamic
loading.

## Public Repository Boundary

This repository may contain:

- private repository names
- public-safe setup guidance
- key names from `.env.example`
- dry-run command plans

It must not contain:

- tokens
- passwords
- private SSH material
- Codex auth files
- copied private repository source
- generated runtime `.env` files
- provider payloads or private config dumps
