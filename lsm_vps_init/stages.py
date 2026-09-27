from __future__ import annotations

import getpass
import ipaddress
import json
import os
import re
import secrets
import shlex
import socket
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .state import mark_reboot_pending, select_module, set_checkpoint, set_fact, set_stage, utc_now
from .util import (
    CommandError,
    CommandResult,
    CommandRunner,
    DEFAULT_BIN_PATH,
    PathLayout,
    append_unique_line,
    file_mode,
    is_ubuntu_2404,
    merge_env_text,
    parse_env_value,
    public_ipv4,
    secure_write,
    user_exists,
)


RELAY_MODULE = "codex-vps-discord-relay"
DOCKER_MODULE = "docker-hosting-stack"
REQUIRED_CODEX_MODEL = "gpt-5.5"
REQUIRED_CODEX_REASONING = "xhigh"
SSH_PORT = "65500"
TMUX_SESSION = "lsm-vps-init"
NODEJS_VERSION = "v24.19.0"
NODEJS_INSTALL_ROOT = "/opt/nodejs"
DISCORD_ID_PATTERN = re.compile(r"^[0-9]{17,20}$")
CODEX_WORK_ROOT = "/home/sadmin"
SSHD_SADMIN_MATCH_CRITERIA = f"user=sadmin,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport={SSH_PORT}"
DOCKER_HOSTING_REPO = "/home/sadmin/docker-hosting-stack"
DOCKER_HOSTING_VALIDATOR_MODES = {
    "base": "base",
    "standalone-app": "standalone-app",
    "n8n": "n8n",
    "website-migration": "migration",
}
DOCKER_HOSTING_MODES = frozenset(DOCKER_HOSTING_VALIDATOR_MODES)
DOCKER_HOSTING_WEB_INGRESS_MODES = frozenset({"base", "n8n", "website-migration"})
DOCKER_HOSTING_WEB_PORTS = ("80/tcp", "443/tcp")
DOCKER_BASE_PROVISIONING_ENV_KEYS = (
    "INSTANCE_NAME",
    "SERVER_FQDN",
    "ADMIN_DOMAIN",
    "SERVER_PUBLIC_IPV4",
    "PHPMYADMIN_HOSTNAME",
    "SFTPGO_ADMIN_HOSTNAME",
    "CADDY_ACME_EMAIL",
    "CF_ACCOUNT_ID",
    "CF_API_TOKEN",
)
DOCKER_STANDALONE_PROVISIONING_ENV_KEYS = (
    "INSTANCE_NAME",
    "SERVER_PUBLIC_IPV4",
)
DOCKER_N8N_PROVISIONING_ENV_KEYS = (
    "INSTANCE_NAME",
    "SERVER_PUBLIC_IPV4",
    "CADDY_ACME_EMAIL",
    "CF_ACCOUNT_ID",
    "CF_API_TOKEN",
    "N8N_HOSTNAME",
)
DOCKER_HOSTING_REQUIRED_ENV_KEYS_BY_MODE = {
    "base": DOCKER_BASE_PROVISIONING_ENV_KEYS,
    "standalone-app": DOCKER_STANDALONE_PROVISIONING_ENV_KEYS,
    "n8n": DOCKER_N8N_PROVISIONING_ENV_KEYS,
    "website-migration": DOCKER_BASE_PROVISIONING_ENV_KEYS,
}
DOCKER_HOSTING_MANAGED_ENV_KEYS = tuple(
    dict.fromkeys(
        (
            *DOCKER_BASE_PROVISIONING_ENV_KEYS,
            *DOCKER_STANDALONE_PROVISIONING_ENV_KEYS,
            *DOCKER_N8N_PROVISIONING_ENV_KEYS,
            "SUDO_PASSWORD",
        )
    )
)
DOCKER_N8N_REQUIRED_ENV_KEYS = DOCKER_N8N_PROVISIONING_ENV_KEYS
DOCKER_HOSTING_SECRET_ENV_KEYS = ("CF_API_TOKEN", "SUDO_PASSWORD")
FINAL_UFW_RECONCILED_PORTS = ("22/tcp", *DOCKER_HOSTING_WEB_PORTS)
DEFAULT_SSH_IDENTITY_HINT = "~/.ssh/lsm_vps_ed25519"
STAGE_TOTAL = 16
MANAGEMENT_TOOL_COMMANDS = (
    "curl",
    "git",
    "gh",
    "jq",
    "openssl",
    "python3",
    "node",
    "npm",
    "tmux",
    "gpg",
    "gpgv",
    "xz",
    "lsb_release",
    "ufw",
    "fail2ban-client",
    "unattended-upgrade",
)


STAGE_INTROS = {
    "root_password": (
        2,
        "Root recovery password",
        "Set a new root password for provider-console or out-of-band recovery. This is a secret. "
        "The bootstrap never stores it.",
    ),
    "sadmin_user": (
        3,
        "sadmin sudo account",
        "`sadmin` is the daily administrative account. Its sudo password is secret and is retained only in "
        "/home/sadmin/.env as SUDO_PASSWORD for approved stdin-based automation.",
    ),
    "sadmin_ssh_key": (
        4,
        "sadmin SSH public key",
        "Paste only the public .pub line generated on your local workstation. Never paste or upload the private key.",
    ),
    "ssh_dual_port": (
        5,
        "SSH dual-port transition",
        "SSH will listen on both 22 and 65500. Keep the original SSH session open until the second-session proof succeeds.",
    ),
    "firewall_phase_a": (
        6,
        "UFW Phase A",
        "UFW will be enabled with both SSH ports explicitly allowed. Port 22 is intentionally retained for now.",
    ),
    "ssh_recovery_checkpoint": (
        7,
        "SSH recovery checkpoint",
        "Run the generated command from a second local workstation terminal. It proves sadmin key-only SSH on port 65500.",
    ),
    "management_tooling": (
        8,
        "Management tooling",
        "Install the base tools required for GitHub, Codex, SSH hardening, firewalling, and selected modules.",
    ),
    "github_auth": (
        9,
        "GitHub authentication",
        "Authenticate GitHub CLI as sadmin. No graphical browser opens on the VPS; use the displayed URL/code on your LOCAL workstation.",
    ),
    "codex_install_auth": (
        10,
        "Codex installation and authentication",
        "Install @openai/codex for sadmin, then authenticate Codex. Browser authorization happens on your LOCAL workstation.",
    ),
    "codex_manager_session": (
        11,
        "VPS Server Manager Codex session",
        "Create and verify a persistent Codex session rooted at /home/sadmin using the required model and reasoning settings.",
    ),
    "repository_selection": (
        12,
        "Repository module selection",
        "Choose which private Loud Sky Media capabilities this VPS should install now. You can resume later.",
    ),
    "discord_relay_install": (
        13,
        "Discord relay configuration",
        "Configure the private Discord relay. The bot token is secret; IDs are copied from Discord Developer Mode.",
    ),
    "discord_relay_checkpoint": (
        14,
        "Discord relay round trip",
        "Verify a real Discord message reaches the VPS Server Manager Codex session and returns a Discord reply.",
    ),
    "final_host_hardening": (
        15,
        "Final SSH and firewall hardening",
        "After recovery SSH and relay management are verified, remove port 22 and disable root/password SSH.",
    ),
    "docker_hosting_stack": (
        16,
        "Docker Hosting Stack handoff",
        "Collect selected hosting values, validate the private stack, and run its dry-run workflow.",
    ),
}
MANAGEMENT_TOOL_PACKAGES = (
    "ca-certificates",
    "python3-venv",
)
NODEJS_RELEASE_KEY_FINGERPRINTS = (
    "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356",
    "DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7",
    "CC68F5A3106FF448322E48ED27F5E38D5B0A215F",
    "8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600",
    "890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4",
    "C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C",
    "108F52B48DB57BB0CC439B2997B01419BD92F80A",
    "655F3B5C1FB3FA8D1A0CA6BDE4A7D232B936D2FD",
    "A363A499291CBBC940DD62E41F10027AF002F8B0",
    "C0D6248439F1D5604AAFFB4021D900FFDB233756",
    "4ED778F539E3634C779C87C6D7062848A1AB005C",
    "141F07595B7B3FFE74309A937405533BE57C7D57",
    "9554F04D7259F04124DE6B476D5A82AC7E37093B",
    "94AE36675C464D64BAFA68DD7434390BDBE9B9C5",
    "1C050899334244A8AF75E53792EF661D867B9DFA",
    "74F12602B6F1C4E913FAA37AD3A89613643B6201",
    "B9AE9905FFD7803F25714661B63B535A4C206CA9",
    "77984A986EBC2AA786BC0F66B01FBB92821C587A",
    "93C7E9E91B49E432C2F75674B0A78B0A6C481CF6",
    "56730D5401028683275BD23C23EFEFE93C4CFFFE",
    "71DCFD284A79C3B38668286BC97EC7A07EDE3FC1",
    "FD3A5288F042B6850C66B31F09FE44734EB7990E",
    "61FC681DFB92A079F1685E77973F295594EC4689",
    "114F43EE0176B71C7BC219DD50A3051F888C628D",
    "C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8",
    "DD8F2338BAE7501E3DD5AC78C273792F7D83545D",
    "A48C2BEE680E841632CD4E44F07496B3EB3C1762",
    "B9E2F5981AA6E0CD28160D9FF13993A75599653C",
    "7937DFD2AB06298B2293C3187D33FF9D0246406D",
)


class Blocked(RuntimeError):
    pass


class Failed(RuntimeError):
    pass


def node_artifact_for_machine(machine: str) -> str:
    normalized = machine.lower()
    if normalized in {"x86_64", "amd64"}:
        return "linux-x64"
    if normalized in {"aarch64", "arm64"}:
        return "linux-arm64"
    if normalized in {"ppc64le", "powerpc64le"}:
        return "linux-ppc64le"
    if normalized in {"s390x"}:
        return "linux-s390x"
    raise Blocked(f"Unsupported CPU architecture for official Node.js binary install: {machine}")


def render_nodejs_install_script(version: str = NODEJS_VERSION, install_root: str = NODEJS_INSTALL_ROOT) -> str:
    version_literal = shlex.quote(version)
    install_root_literal = shlex.quote(install_root)
    fingerprints_case = "|".join(NODEJS_RELEASE_KEY_FINGERPRINTS)
    return f"""
install_official_nodejs() {{
  local version={version_literal}
  local install_root={install_root_literal}
  local machine artifact base url tmpdir target primary_fprs fpr verify_status signer_fpr
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) artifact="linux-x64" ;;
    aarch64|arm64) artifact="linux-arm64" ;;
    ppc64le|powerpc64le) artifact="linux-ppc64le" ;;
    s390x) artifact="linux-s390x" ;;
    *) echo "Unsupported CPU architecture for official Node.js binary install: $machine" >&2; return 42 ;;
  esac
  base="node-$version-$artifact"
  url="https://nodejs.org/dist/$version"
  tmpdir="$(mktemp -d -t lsm-nodejs.XXXXXXXXXX)"
  target="$install_root/$base"
  cleanup_node_tmp() {{
    if [ -n "${{tmpdir:-}}" ] && [ -d "$tmpdir" ] && [ "${{tmpdir#/tmp/lsm-nodejs.}}" != "$tmpdir" ]; then
      rm -rf -- "$tmpdir"
    fi
  }}
  trap cleanup_node_tmp RETURN

  nodejs_fingerprint_allowed() {{
    case "$1" in
    {fingerprints_case})
      return 0
      ;;
    *)
      return 1
      ;;
    esac
  }}

  curl -fsSLo "$tmpdir/nodejs-keyring.kbx" "https://github.com/nodejs/release-keys/raw/HEAD/gpg/pubring.kbx"
  primary_fprs="$(
    gpg --no-default-keyring --keyring "$tmpdir/nodejs-keyring.kbx" \
      --with-colons --fingerprint --list-keys \
      | awk -F: '/^pub:/ {{ want=1; next }} /^sub:/ {{ want=0; next }} want && /^fpr:/ {{ print $10; want=0 }}'
  )"
  if [ -z "$primary_fprs" ]; then
    echo "Node.js release keyring did not contain any primary fingerprints." >&2
    return 43
  fi
  while IFS= read -r fpr; do
    [ -n "$fpr" ] || continue
    if ! nodejs_fingerprint_allowed "$fpr"; then
      echo "Unpinned Node.js release key fingerprint in downloaded keyring: $fpr" >&2
      return 43
    fi
  done <<EOF_NODEJS_PRIMARY_FPRS
$primary_fprs
EOF_NODEJS_PRIMARY_FPRS

  curl -fsSLo "$tmpdir/SHASUMS256.txt.asc" "$url/SHASUMS256.txt.asc"
  verify_status="$(
    gpgv --status-fd=1 --keyring "$tmpdir/nodejs-keyring.kbx" \
      --output "$tmpdir/SHASUMS256.txt" < "$tmpdir/SHASUMS256.txt.asc" 2>&1
  )"
  printf '%s\\n' "$verify_status"
  signer_fpr="$(printf '%s\\n' "$verify_status" | awk '/^\\[GNUPG:\\] VALIDSIG / {{ print $3; exit }}')"
  if [ -z "$signer_fpr" ] || ! nodejs_fingerprint_allowed "$signer_fpr"; then
    echo "Node.js signed checksum was not signed by a pinned release key fingerprint." >&2
    return 43
  fi
  curl -fsSLo "$tmpdir/$base.tar.xz" "$url/$base.tar.xz"
  (cd "$tmpdir" && sha256sum --check --ignore-missing SHASUMS256.txt)
  install -d -o root -g root -m 0755 "$install_root"
  tar -xJf "$tmpdir/$base.tar.xz" -C "$install_root"
  ln -sfn "$target/bin/node" /usr/local/bin/node
  ln -sfn "$target/bin/npm" /usr/local/bin/npm
  ln -sfn "$target/bin/npx" /usr/local/bin/npx
  if [ -x "$target/bin/corepack" ]; then
    ln -sfn "$target/bin/corepack" /usr/local/bin/corepack
  fi
  node --version
  npm --version
}}
"""


def validate_discord_id_list(value: str, field: str, *, required: bool) -> list[str]:
    ids = [entry.strip() for entry in value.split(",") if entry.strip()]
    if required and not ids:
        raise Blocked(f"{field} must contain at least one explicit Discord user ID.")
    invalid = [entry for entry in ids if not DISCORD_ID_PATTERN.fullmatch(entry)]
    if invalid:
        raise Blocked(f"{field} must contain only comma-separated 17-20 digit Discord IDs.")
    return ids


def validate_discord_id(value: str, field: str) -> str:
    candidate = value.strip()
    if not DISCORD_ID_PATTERN.fullmatch(candidate):
        raise Blocked(f"{field} must be a 17-20 digit Discord ID.")
    return candidate


def parse_docker_published_ports(ports_output: str) -> set[int]:
    published: set[int] = set()
    for match in re.finditer(r"(?:0\.0\.0\.0|\[?::\]?|127\.0\.0\.1|\[[^\]]+\]|[0-9a-fA-F:.]+):(\d+)->", ports_output):
        published.add(int(match.group(1)))
    return published


def render_sadmin_agents() -> str:
    return """# VPS Administration Instructions

This home directory is an authorized Loud Sky Media VPS administration
workspace.

`/home/sadmin/.env` intentionally contains `SUDO_PASSWORD=` for approved
stdin-based sudo automation. Do not print it, export it globally, copy it into
Docker or relay environments, pass it as a process argument, or commit it.

Do not load `/home/sadmin/.env` with arbitrary `source` behavior. Use a
deliberate key/value parser and feed sudo through stdin only when elevation is
explicitly approved.
"""


def stage_intro(ctx: Context, slug: str) -> None:
    if ctx.dry_run and not ctx.layout.mock_root:
        return
    intro = STAGE_INTROS.get(slug)
    if not intro:
        return
    index, title, body = intro
    print()
    print("=" * 60)
    print(f"Stage {index:02d}/{STAGE_TOTAL} - {title}")
    print("=" * 60)
    print(body)
    if ctx.state.get("reboot", {}).get("pending"):
        print()
        print("Ubuntu requires a reboot.")
        print("Do not reboot yet. Bootstrap is first establishing verified SSH recovery and management access.")


def confirm_ready_or_pause(ctx: Context, prompt: str, pause_reason: str) -> None:
    if ctx.dry_run:
        return
    if not ctx.confirm(prompt + " Choose no to pause setup and resume later.", default=True):
        raise Blocked(pause_reason + " Resume with `sudo lsm-vps-init resume` when ready.")


def write_browser_handoff(ctx: Context, name: str, label: str) -> Path:
    path = ctx.layout.state_dir / name
    script = (
        "#!/bin/sh\n"
        "printf '\\n%s authorization request:\\n' " + shlex.quote(label) + "\n"
        "printf '%s\\n\\n' \"$1\"\n"
        "printf 'Open this URL in your LOCAL workstation browser and complete authorization.\\n'\n"
        "printf 'No graphical browser is being opened on this VPS.\\n\\n'\n"
    )
    secure_write(path, script, 0o700)
    return path


def headless_browser_env_prefix(path: Path) -> str:
    browser = shlex.quote(str(path))
    return f"GH_BROWSER={browser} BROWSER={browser}"


def shell_quote_local_path_hint(path: str) -> str:
    if path == "~":
        return "~"
    if path.startswith("~/"):
        remainder = path[2:]
        if re.fullmatch(r"[A-Za-z0-9_./@%+=:,~-]+", remainder):
            return "~/" + remainder
        return "~/" + shlex.quote(remainder)
    return shlex.quote(path)


def ssh_connection_server_port(ssh_connection: str) -> str | None:
    parts = ssh_connection.split()
    if len(parts) != 4:
        return None
    return parts[3]


def ssh_user_auth_has_publickey(auth_file: str | None, reader: Callable[[str], str] | None = None) -> bool | None:
    if not auth_file:
        return None
    try:
        text = reader(auth_file) if reader else Path(auth_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        if line.strip().startswith("publickey "):
            return True
    return False


def ssh_checkpoint_proof_from_env(
    *,
    nonce: str,
    env: dict[str, str] | None = None,
    username: str | None = None,
    auth_reader: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    environment = env or os.environ
    effective_user = username or getpass.getuser()
    if effective_user != "sadmin":
        raise Blocked("SSH recovery proof must be generated by effective user sadmin.")
    local_port = ssh_connection_server_port(environment.get("SSH_CONNECTION", ""))
    if local_port != SSH_PORT:
        raise Blocked(f"SSH recovery proof must come from a session whose server-side SSH port is {SSH_PORT}.")
    if environment.get("LSM_VPS_INIT_PUBLICKEY_ONLY") != "1":
        raise Blocked("SSH recovery proof must be generated by the bootstrap key-only SSH command.")
    publickey_verified = ssh_user_auth_has_publickey(environment.get("SSH_USER_AUTH"), auth_reader)
    if publickey_verified is not True:
        raise Blocked("SSH recovery proof requires SSH_USER_AUTH evidence of public-key authentication.")
    if not nonce:
        raise Blocked("SSH recovery nonce is required.")
    return {
        "nonce": nonce,
        "user": effective_user,
        "local_ssh_port": local_port,
        "publickey_required": True,
        "publickey_auth_verified": True,
        "auth_proof_source": "SSH_USER_AUTH",
        "verified": True,
        "verified_at": utc_now(),
    }


def validate_ssh_checkpoint_proof(expected_nonce: str | None, proof: dict[str, Any]) -> dict[str, Any]:
    if not expected_nonce or proof.get("nonce") != expected_nonce:
        raise Blocked("SSH recovery nonce mismatch.")
    if proof.get("user") != "sadmin":
        raise Blocked("SSH recovery proof was not generated by sadmin.")
    if str(proof.get("local_ssh_port")) != SSH_PORT:
        raise Blocked(f"SSH recovery proof was not generated on port {SSH_PORT}.")
    if proof.get("publickey_required") is not True:
        raise Blocked("SSH recovery proof did not use the bootstrap public-key-only procedure.")
    if proof.get("verified") is not True:
        raise Blocked("SSH recovery proof is not verified.")
    return {
        "user": "sadmin",
        "local_ssh_port": SSH_PORT,
        "publickey_required": True,
        "publickey_auth_verified": bool(proof.get("publickey_auth_verified")),
        "auth_proof_source": str(proof.get("auth_proof_source") or "unknown"),
        "verified": True,
        "verified_at": str(proof.get("verified_at") or utc_now()),
    }


def record_ssh_checkpoint_proof(state: dict[str, Any], proof: dict[str, Any]) -> dict[str, Any]:
    evidence = validate_ssh_checkpoint_proof(state.get("facts", {}).get("ssh_recovery_nonce"), proof)
    state.setdefault("facts", {}).pop("ssh_recovery_nonce", None)
    set_fact(state, "ssh_recovery_verification", evidence)
    set_checkpoint(state, "ssh_recovery_verified", True)
    set_stage(state, "ssh_recovery_checkpoint", "completed", "Verified from independent sadmin SSH session on port 65500.", evidence)
    return evidence


@dataclass
class StageResult:
    status: str
    message: str
    evidence: dict[str, Any] | None = None


@dataclass
class StageDefinition:
    index: int
    slug: str
    title: str
    detect: Callable[["Context"], bool]
    run: Callable[["Context"], StageResult]
    superseded_by: tuple[str, ...] = ()


@dataclass
class Context:
    layout: PathLayout
    state: dict[str, Any]
    runner: CommandRunner
    dry_run: bool = False
    non_interactive: bool = False
    assume_yes: bool = False

    def require_root(self) -> None:
        if self.dry_run:
            return
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise Blocked("Run with sudo or as root.")

    def require_tty(self, purpose: str) -> None:
        if self.dry_run:
            return
        if self.non_interactive or not sys.stdin.isatty():
            raise Blocked(f"{purpose} requires a real interactive terminal; rerun `sudo lsm-vps-init resume` from a TTY.")

    def confirm(self, prompt: str, *, default: bool = False) -> bool:
        if self.assume_yes:
            return True
        self.require_tty("Operator confirmation")
        suffix = " [Y/n] " if default else " [y/N] "
        value = input(prompt + suffix).strip().lower()
        if not value:
            return default
        return value in {"y", "yes"}

    def prompt_text(self, prompt: str, *, default: str | None = None, required: bool = True) -> str:
        self.require_tty(prompt)
        suffix = f" [{default}]" if default else ""
        value = input(prompt + suffix + ": ").strip()
        if not value and default is not None:
            value = default
        if required and not value:
            raise Blocked(f"Missing required value for: {prompt}")
        return value

    def prompt_secret(self, prompt: str, *, confirm: bool = True) -> str:
        self.require_tty(prompt)
        first = getpass.getpass(prompt + ": ")
        if not first:
            raise Blocked(f"Missing required secret for: {prompt}")
        if confirm:
            second = getpass.getpass("Confirm " + prompt + ": ")
            if first != second:
                raise Blocked("Secret entries did not match; rerun the stage.")
        return first

    def sadmin_shell(
        self,
        script: str,
        *,
        input_text: str | None = None,
        check: bool = True,
        secret_stdin: bool = False,
        timeout: int | None = None,
        redact_values: list[str] | None = None,
    ):
        wrapped = (
            'export HOME=/home/sadmin; '
            'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
            f"{script}"
        )
        return self.runner.run(
            ["sudo", "-u", "sadmin", "-H", "bash", "-lc", wrapped],
            input_text=input_text,
            check=check,
            secret_stdin=secret_stdin,
            timeout=timeout,
            redact_values=redact_values,
        )

    def sadmin_uid(self) -> str:
        result = self.runner.run(["id", "-u", "sadmin"], check=False)
        if result.returncode != 0:
            raise Failed("Unable to resolve sadmin UID for user systemd operations.")
        uid = result.stdout.strip()
        if not re.fullmatch(r"[0-9]+", uid):
            raise Failed("Resolved sadmin UID was not numeric.")
        return uid

    def sadmin_systemd_env(self, uid: str | None = None) -> dict[str, str]:
        resolved_uid = uid or self.sadmin_uid()
        return {
            "XDG_RUNTIME_DIR": f"/run/user/{resolved_uid}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{resolved_uid}/bus",
        }

    def sadmin_user_systemd_shell(
        self,
        script: str,
        *,
        check: bool = True,
        timeout: int | None = None,
        uid: str | None = None,
    ):
        env = self.sadmin_systemd_env(uid)
        wrapped = (
            'export HOME=/home/sadmin; '
            'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
            f"{script}"
        )
        return self.runner.run(
            [
                "sudo",
                "-u",
                "sadmin",
                "-H",
                "env",
                f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
                f"DBUS_SESSION_BUS_ADDRESS={env['DBUS_SESSION_BUS_ADDRESS']}",
                "bash",
                "-lc",
                wrapped,
            ],
            check=check,
            timeout=timeout,
        )

    def sadmin_interactive_shell(
        self,
        script: str,
        *,
        check: bool = True,
        timeout: int | None = None,
    ):
        wrapped = (
            'export HOME=/home/sadmin; '
            'export PATH="$HOME/.local/bin:$HOME/.npm-global/bin:$PATH"; '
            f"{script}"
        )
        return self.runner.run_interactive(
            ["sudo", "-u", "sadmin", "-H", "bash", "-lc", wrapped],
            check=check,
            timeout=timeout,
        )


def render_ssh_dropin(phase: str) -> str:
    if phase == "dual-port":
        return (
            "# Managed by lsm-vps-init. Keep port 22 until recovery is verified.\n"
            "Port 22\n"
            f"Port {SSH_PORT}\n"
            "PubkeyAuthentication yes\n"
            "Match User sadmin\n"
            "    ExposeAuthInfo yes\n"
        )
    if phase == "hardened":
        return (
            "# Managed by lsm-vps-init after verified recovery checkpoints.\n"
            f"Port {SSH_PORT}\n"
            "PermitRootLogin no\n"
            "PasswordAuthentication no\n"
            "PubkeyAuthentication yes\n"
            "ExposeAuthInfo no\n"
        )
    raise ValueError(f"unknown SSH phase: {phase}")


def docker_hosting_mode_choices() -> str:
    return ", ".join(sorted(DOCKER_HOSTING_MODES))


def validate_docker_hosting_mode(mode: str | None) -> str:
    candidate = (mode or "").strip()
    if candidate not in DOCKER_HOSTING_VALIDATOR_MODES:
        raise Blocked(f"Unsupported Docker hosting capability mode: {candidate or '<empty>'}. Expected one of: {docker_hosting_mode_choices()}.")
    return candidate


def docker_hosting_validator_mode(mode: str) -> str:
    return DOCKER_HOSTING_VALIDATOR_MODES[validate_docker_hosting_mode(mode)]


def docker_hosting_required_env_keys(mode: str) -> tuple[str, ...]:
    return DOCKER_HOSTING_REQUIRED_ENV_KEYS_BY_MODE[validate_docker_hosting_mode(mode)]


def docker_hosting_mode_requires_web_ingress(mode: str) -> bool:
    return validate_docker_hosting_mode(mode) in DOCKER_HOSTING_WEB_INGRESS_MODES


def selected_docker_hosting_mode(ctx: Context) -> str | None:
    mode = ctx.state.get("facts", {}).get("docker_hosting_mode")
    if mode is None:
        return None
    return validate_docker_hosting_mode(str(mode))


def firewall_ports_for_modules(modules: dict[str, bool], docker_hosting_mode: str | None = None) -> list[str]:
    ports = [f"{SSH_PORT}/tcp"]
    if modules.get(DOCKER_MODULE):
        mode = validate_docker_hosting_mode(docker_hosting_mode)
        if docker_hosting_mode_requires_web_ingress(mode):
            ports.extend(DOCKER_HOSTING_WEB_PORTS)
    return ports


def firewall_ports_for_state(ctx: Context) -> list[str]:
    modules = ctx.state.get("selected_modules", {})
    mode = selected_docker_hosting_mode(ctx) if modules.get(DOCKER_MODULE) else None
    return firewall_ports_for_modules(modules, mode)


def render_ufw_phase_a_plan(current_ssh_port: str | None = None) -> list[str]:
    ports = ["22/tcp", f"{SSH_PORT}/tcp"]
    if current_ssh_port and f"{current_ssh_port}/tcp" not in ports:
        raise Blocked(f"Current SSH session port {current_ssh_port} is not in the Phase A firewall allowlist.")
    return ports


def ufw_status_allows(status_text: str, port: str) -> bool:
    return bool(re.search(rf"(?m)^\s*{re.escape(port)}\s+ALLOW\b", status_text))


def ufw_show_added_allows(added_text: str, port: str) -> bool:
    return bool(re.search(rf"(?m)^\s*ufw\s+allow(?:\s+in)?\s+{re.escape(port)}(?:\s*$|\s+)", added_text))


def ufw_status_is_active(status_text: str) -> bool:
    return bool(re.search(r"(?mi)^\s*Status:\s+active\s*$", status_text))


def ufw_status_defaults_are_safe(status_text: str) -> bool:
    return bool(re.search(r"(?mi)^\s*Default:\s*deny\s+\(incoming\),\s*allow\s+\(outgoing\)", status_text))


def validate_ufw_phase_a_active_status(status_text: str, ports: list[str]) -> None:
    if not ufw_status_is_active(status_text):
        raise Failed("UFW Phase A did not become active after enable.")
    if not ufw_status_defaults_are_safe(status_text):
        raise Failed("UFW Phase A default policy is not deny incoming / allow outgoing after enable.")
    for port in ports:
        if not ufw_status_allows(status_text, port):
            raise Failed(f"UFW Phase A did not retain required allow rule after enable: {port}")


def validate_final_ufw_status(status_text: str, required_ports: list[str]) -> None:
    if not ufw_status_is_active(status_text):
        raise Failed("UFW Phase B is not active.")
    if not ufw_status_defaults_are_safe(status_text):
        raise Failed("UFW Phase B default policy is not deny incoming / allow outgoing.")
    required = set(required_ports)
    for port in required_ports:
        if not ufw_status_allows(status_text, port):
            raise Failed(f"UFW is missing required Phase B allow rule: {port}")
    for port in FINAL_UFW_RECONCILED_PORTS:
        if port not in required and ufw_status_allows(status_text, port):
            raise Failed(f"UFW still allows {port} after Phase B hardening.")


def delete_ufw_allow_if_present(ctx: Context, port: str) -> None:
    for _ in range(3):
        status = ctx.runner.run(["ufw", "status", "verbose"], check=False).stdout
        if not ufw_status_allows(status, port):
            return
        ctx.runner.run(["ufw", "delete", "allow", port], check=False)


def reconcile_ufw_final_rules(ctx: Context, required_ports: list[str]) -> None:
    required = set(required_ports)
    for port in required_ports:
        ctx.runner.run(["ufw", "allow", port])
    for port in FINAL_UFW_RECONCILED_PORTS:
        if port not in required:
            delete_ufw_allow_if_present(ctx, port)
    ctx.runner.run(["ufw", "--force", "enable"])
    status = ctx.runner.run(["ufw", "status", "verbose"]).stdout
    validate_final_ufw_status(status, required_ports)


def reconcile_legacy_final_firewall(ctx: Context, mode: str) -> None:
    stage_status = ctx.state.get("stages", {}).get("final_host_hardening", {}).get("status")
    if stage_status not in {"completed", "blocked", "failed", "in_progress"}:
        return
    try_reconcile_already_hardened_final_firewall(ctx, mode)


def selected_relay_requirements_issues(ctx: Context) -> list[str]:
    issues: list[str] = []
    if ctx.state.get("selected_modules", {}).get(RELAY_MODULE):
        if not ctx.state.get("checkpoints", {}).get("relay_round_trip_verified"):
            issues.append("Discord/Codex relay round trip is not verified")
        if ctx.state.get("stages", {}).get("discord_relay_install", {}).get("status") != "completed":
            issues.append("Discord relay install stage is not completed")
        elif not ctx.dry_run and not detect_discord_relay_install(ctx):
            issues.append("Discord relay service/preflight is not currently healthy")
    return issues


def docker_published_port_issues(ctx: Context) -> list[str]:
    if ctx.dry_run:
        return []
    issues: list[str] = []
    docker_available = ctx.runner.run(["bash", "-lc", "command -v docker >/dev/null"], check=False).returncode == 0
    if docker_available:
        result = ctx.runner.run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"], check=False)
        if result.returncode == 0:
            published = parse_docker_published_ports(result.stdout)
            allowed: set[int] = set()
            if ctx.state.get("selected_modules", {}).get(DOCKER_MODULE):
                mode = selected_docker_hosting_mode(ctx)
                if mode and docker_hosting_mode_requires_web_ingress(mode):
                    allowed = {80, 443}
            unexpected = published - allowed
            if unexpected:
                issues.append(f"Docker has unexpected host-published public port(s): {', '.join(str(port) for port in sorted(unexpected))}")
        else:
            issues.append("Docker is installed but published-port inspection failed")
    return issues


def current_final_ssh_hardening_issues(ctx: Context) -> list[str]:
    issues: list[str] = []
    result = sshd_global_effective_config(ctx, check=False)
    if result.returncode != 0:
        issues.append("effective sshd config could not be read")
        return issues
    sadmin_result = sshd_effective_for_sadmin_result(ctx, check=False)
    if sadmin_result.returncode != 0:
        issues.append("effective sadmin sshd config could not be read")
        return issues
    try:
        validate_final_sshd_effective_config(result.stdout, sadmin_result.stdout)
    except Failed as error:
        issues.append(str(error))
    if not ssh_listener_present(ctx, SSH_PORT):
        issues.append(f"sshd is not currently listening on port {SSH_PORT}")
    if ssh_listener_present(ctx, "22"):
        issues.append("sshd is still listening on port 22")
    if not ctx.state.get("checkpoints", {}).get("ssh_recovery_verified"):
        issues.append("sadmin SSH recovery checkpoint is not verified")
    issues.extend(selected_relay_requirements_issues(ctx))
    return issues


def final_ufw_baseline_issues(status_text: str) -> list[str]:
    issues: list[str] = []
    if not ufw_status_is_active(status_text):
        issues.append("UFW is not active")
    if not ufw_status_defaults_are_safe(status_text):
        issues.append("UFW default policy is not deny incoming / allow outgoing")
    management_port = f"{SSH_PORT}/tcp"
    if not ufw_status_allows(status_text, management_port):
        issues.append(f"UFW is missing required management allow rule: {management_port}")
    return issues


def try_reconcile_already_hardened_final_firewall(ctx: Context, mode: str) -> bool:
    if ctx.dry_run:
        return False
    issues = current_final_ssh_hardening_issues(ctx)
    status_result = ctx.runner.run(["ufw", "status", "verbose"], check=False)
    if status_result.returncode != 0:
        issues.append("UFW status could not be read")
        status_text = ""
    else:
        status_text = status_result.stdout
        issues.extend(final_ufw_baseline_issues(status_text))
    issues.extend(docker_published_port_issues(ctx))
    if issues:
        return False

    required_ports = firewall_ports_for_modules(ctx.state.get("selected_modules", {}), mode)
    try:
        validate_final_ufw_status(status_text, required_ports)
        return True
    except Failed:
        reconcile_ufw_final_rules(ctx, required_ports)
        return True


def codex_reasoning_config_arg(reasoning: str = REQUIRED_CODEX_REASONING) -> str:
    return "model_reasoning_effort=" + json.dumps(reasoning)


def codex_exec_args(*, session_id: str | None = None, json_output: bool = False) -> list[str]:
    args = ["codex", "exec"]
    if json_output:
        args.append("--json")
    args.extend(
        [
            "--cd",
            CODEX_WORK_ROOT,
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
            "-m",
            REQUIRED_CODEX_MODEL,
            "-c",
            codex_reasoning_config_arg(),
        ]
    )
    if session_id:
        args.extend(["resume", session_id])
    args.append("-")
    return args


def codex_exec_shell_command(*, session_id: str | None = None, json_output: bool = False) -> str:
    return f"cd {shlex.quote(CODEX_WORK_ROOT)} && {shlex.join(codex_exec_args(session_id=session_id, json_output=json_output))}"


def extract_codex_session_id(output: str) -> str | None:
    uuid_re = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
    for line in output.splitlines():
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if parsed.get("type") != "thread.started":
            continue
        thread_id = parsed.get("thread_id")
        if isinstance(thread_id, str) and uuid_re.fullmatch(thread_id):
            return thread_id
    return None


def codex_config_has_required_defaults(text: str) -> bool:
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return False
    return (
        parsed.get("model") == REQUIRED_CODEX_MODEL
        and parsed.get("model_reasoning_effort") == REQUIRED_CODEX_REASONING
    )


def verify_codex_config_defaults(ctx: Context) -> None:
    config_path = ctx.layout.sadmin_home / ".codex" / "config.toml"
    if not config_path.exists():
        raise Blocked("Missing /home/sadmin/.codex/config.toml; Codex model/reasoning defaults are not verified.")
    if not codex_config_has_required_defaults(config_path.read_text(encoding="utf-8", errors="replace")):
        raise Blocked(f"Codex config must keep model={REQUIRED_CODEX_MODEL} and model_reasoning_effort={REQUIRED_CODEX_REASONING}.")


def upsert_codex_config(text: str, model: str = REQUIRED_CODEX_MODEL, reasoning: str = REQUIRED_CODEX_REASONING) -> str:
    lines = text.splitlines()
    root_end = len(lines)
    for index, line in enumerate(lines):
        if line.strip().startswith("["):
            root_end = index
            break
    wanted = {
        "model": json.dumps(model),
        "model_reasoning_effort": json.dumps(reasoning),
    }
    seen: set[str] = set()
    for index in range(root_end):
        stripped = lines[index].strip()
        for key, value in wanted.items():
            if re.match(rf"^{re.escape(key)}\s*=", stripped):
                lines[index] = f"{key} = {value}"
                seen.add(key)
    insert_at = root_end
    additions = [f"{key} = {value}" for key, value in wanted.items() if key not in seen]
    if additions:
        if insert_at > 0 and lines[insert_at - 1].strip():
            additions.insert(0, "")
        lines[insert_at:insert_at] = additions
    return "\n".join(lines).rstrip() + "\n"


def detected_stage_by_state(ctx: Context, slug: str) -> bool:
    return ctx.state.get("stages", {}).get(slug, {}).get("status") == "completed"


def detect_bootstrap(ctx: Context) -> bool:
    return is_ubuntu_2404(ctx.layout.os_release) and ctx.layout.state_dir.exists()


def run_bootstrap(ctx: Context) -> StageResult:
    ctx.require_root()
    if not is_ubuntu_2404(ctx.layout.os_release):
        raise Failed("Unsupported OS. This implementation supports Ubuntu 24.04 LTS only.")
    ctx.layout.state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    ctx.layout.log_file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    motd = (
        "#!/bin/sh\n"
        "if [ -f /var/lib/lsm-vps-init/state.json ]; then\n"
        "  echo 'Loud Sky Media VPS initialization may be incomplete.'\n"
        "  echo 'Resume with: sudo lsm-vps-init resume'\n"
        "fi\n"
    )
    if ctx.dry_run and not ctx.layout.mock_root:
        ctx.runner.log("DRY-RUN: would install MOTD reminder")
    else:
        secure_write(ctx.layout.motd_file, motd, 0o755)
    return StageResult("completed", "Bootstrap infrastructure is present.")


def detect_system_update(ctx: Context) -> bool:
    return detected_stage_by_state(ctx, "system_update")


def run_system_update(ctx: Context) -> StageResult:
    ctx.require_root()
    script = r"""
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
wait_for_apt_locks() {
  local locks=(
    /var/lib/dpkg/lock
    /var/lib/dpkg/lock-frontend
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  local waited=0
  while true; do
    local busy=0
    for lock in "${locks[@]}"; do
      if [ -e "$lock" ] && command -v fuser >/dev/null 2>&1 && fuser "$lock" >/dev/null 2>&1; then
        busy=1
      fi
    done
    if [ "$busy" -eq 0 ]; then
      return 0
    fi
    if [ "$waited" -ge 900 ]; then
      echo "Timed out waiting for apt/dpkg locks." >&2
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
}
wait_for_apt_locks
if command -v dpkg >/dev/null 2>&1; then
  dpkg --configure -a
fi
wait_for_apt_locks
apt-get update
apt-get -y upgrade
apt-get -y autoremove
"""
    ctx.runner.run(["bash", "-lc", script], timeout=3600)
    reboot_pending = ctx.layout.reboot_required.exists()
    mark_reboot_pending(ctx.state, reboot_pending)
    return StageResult("completed", "System packages updated.", {"reboot_pending": reboot_pending})


def detect_root_password(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "root_password")
    result = ctx.runner.run(["passwd", "-S", "root"], check=False)
    return result.returncode == 0 and re.search(r"^root\s+P\b", result.stdout) is not None


def run_root_password(ctx: Context) -> StageResult:
    ctx.require_root()
    if ctx.dry_run:
        return StageResult("completed", "Would securely set the root recovery password.", {"dry_run": True})
    stage_intro(ctx, "root_password")
    password = ctx.prompt_secret("New root password")
    ctx.runner.run(["chpasswd"], input_text=f"root:{password}\n", secret_stdin=True)
    return StageResult("completed", "Root recovery password was set.", {"account_status": "set"})


def detect_sadmin(ctx: Context) -> bool:
    passwd_file = ctx.layout.map("/etc/passwd") if ctx.layout.mock_root else None
    if not user_exists("sadmin", passwd_file):
        return False
    if ctx.layout.mock_root:
        group_file = ctx.layout.map("/etc/group")
        if not group_file.exists():
            return False
        sudo_group = False
        for line in group_file.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[0] == "sudo":
                sudo_group = "sadmin" in [item.strip() for item in parts[3].split(",") if item.strip()]
                break
        if not sudo_group:
            return False
    elif ctx.runner.run(["id", "-nG", "sadmin"], check=False).stdout.split().count("sudo") == 0:
        return False
    env_ok = ctx.layout.sadmin_env.exists() and file_mode(ctx.layout.sadmin_env) == 0o600
    has_sudo_password_key = False
    if env_ok:
        text = ctx.layout.sadmin_env.read_text(encoding="utf-8", errors="replace")
        has_sudo_password_key = parse_env_value(text, "SUDO_PASSWORD") is not None
    agents_ok = (ctx.layout.sadmin_home / "AGENTS.md").exists()
    return env_ok and has_sudo_password_key and agents_ok


def run_sadmin(ctx: Context) -> StageResult:
    ctx.require_root()
    if ctx.dry_run and not ctx.layout.mock_root:
        return StageResult("completed", "Would create/update sadmin and /home/sadmin/.env.", {"dry_run": True})

    stage_intro(ctx, "sadmin_user")
    password = "dry-run-password"
    if not ctx.dry_run:
        password = ctx.prompt_secret("New sadmin sudo password")
        ctx.runner.run(["id", "sadmin"], check=False)
        ctx.runner.run(["bash", "-lc", "id sadmin >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo sadmin"])
        ctx.runner.run(["usermod", "-aG", "sudo", "sadmin"])
        ctx.runner.run(["chpasswd"], input_text=f"sadmin:{password}\n", secret_stdin=True)
    else:
        passwd_file = ctx.layout.map("/etc/passwd")
        passwd_file.parent.mkdir(parents=True, exist_ok=True)
        if not user_exists("sadmin", passwd_file):
            with passwd_file.open("a", encoding="utf-8") as handle:
                handle.write("sadmin:x:1001:1001::/home/sadmin:/bin/bash\n")
        group_file = ctx.layout.map("/etc/group")
        group_file.parent.mkdir(parents=True, exist_ok=True)
        existing_group = group_file.read_text(encoding="utf-8") if group_file.exists() else ""
        lines = existing_group.splitlines()
        found_sudo_group = False
        has_sadmin_member = False
        changed_group = False
        updated_lines: list[str] = []
        for line in lines:
            if line.startswith("sudo:"):
                found_sudo_group = True
                parts = line.split(":")
                while len(parts) < 4:
                    parts.append("")
                members = [item for item in parts[3].split(",") if item]
                has_sadmin_member = "sadmin" in members
                if not has_sadmin_member:
                    members.append("sadmin")
                    has_sadmin_member = True
                    changed_group = True
                parts[3] = ",".join(members)
                line = ":".join(parts)
            updated_lines.append(line)
        if not found_sudo_group:
            updated_lines.append("sudo:x:27:sadmin")
            changed_group = True
        if changed_group:
            group_file.write_text("\n".join(updated_lines).rstrip() + "\n", encoding="utf-8")

    existing = ctx.layout.sadmin_env.read_text(encoding="utf-8") if ctx.layout.sadmin_env.exists() else ""
    secure_write(ctx.layout.sadmin_env, merge_env_text(existing, {"SUDO_PASSWORD": password}), 0o600)
    secure_write(ctx.layout.sadmin_home / "AGENTS.md", render_sadmin_agents(), 0o644)
    if not ctx.dry_run:
        ctx.runner.run(["chown", "sadmin:sadmin", "/home/sadmin/.env"])
        ctx.runner.run(["chown", "sadmin:sadmin", "/home/sadmin/AGENTS.md"])
        ctx.sadmin_shell("sudo -S -p '' -v", input_text=f"{password}\n", secret_stdin=True)
        ctx.runner.run(["install", "-d", "-o", "sadmin", "-g", "sadmin", "-m", "0750", "/home/sadmin"])
    return StageResult("completed", "sadmin exists, has sudo group membership, and owns a protected .env.")


def detect_sadmin_ssh_key(ctx: Context) -> bool:
    if not ctx.layout.authorized_keys.exists() or file_mode(ctx.layout.authorized_keys) not in {0o600, 0o644}:
        return False
    text = ctx.layout.authorized_keys.read_text(encoding="utf-8", errors="replace")
    return any(line.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")) for line in text.splitlines())


def run_sadmin_ssh_key(ctx: Context) -> StageResult:
    ctx.require_root()
    if ctx.dry_run and not ctx.layout.mock_root:
        return StageResult("completed", "Would validate and install an sadmin SSH public key.", {"dry_run": True})
    stage_intro(ctx, "sadmin_ssh_key")
    key = os.environ.get("LSM_VPS_INIT_SSH_PUBLIC_KEY", "").strip()
    if not key and not ctx.dry_run:
        key = ctx.prompt_text("Paste sadmin SSH public key")
    if ctx.dry_run and not key:
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDryRunPublicKeyMaterialOnlyForMockTests lsm-vps-init-dry-run"
    tmp_key = ctx.layout.state_dir / "candidate_authorized_key.pub"
    secure_write(tmp_key, key + "\n", 0o600)
    if not ctx.dry_run:
        ctx.runner.run(["ssh-keygen", "-l", "-f", str(tmp_key)])
    existing = ctx.layout.authorized_keys.read_text(encoding="utf-8") if ctx.layout.authorized_keys.exists() else ""
    secure_write(ctx.layout.authorized_keys, append_unique_line(existing, key), 0o600)
    ssh_dir = ctx.layout.authorized_keys.parent
    try:
        os.chmod(ssh_dir, 0o700)
    except FileNotFoundError:
        ssh_dir.mkdir(parents=True, mode=0o700)
    if not ctx.dry_run:
        ctx.runner.run(["chown", "-R", "sadmin:sadmin", "/home/sadmin/.ssh"])
    if "ssh_identity_file_hint" not in ctx.state.get("facts", {}):
        hint = os.environ.get("LSM_VPS_INIT_SSH_IDENTITY_FILE", "").strip()
        if not hint and not ctx.dry_run:
            print()
            print("Local SSH identity path hint")
            print("This is only the local workstation path shown in future SSH commands.")
            print("Do not paste private-key contents, upload the key, or enter the key passphrase here.")
            hint = ctx.prompt_text("Local private-key path to show in SSH commands", default=DEFAULT_SSH_IDENTITY_HINT)
        if not hint:
            hint = DEFAULT_SSH_IDENTITY_HINT
        set_fact(ctx.state, "ssh_identity_file_hint", hint)
    return StageResult("completed", "sadmin authorized_keys contains a validated public key.")


def _effective_ssh_ports(ctx: Context) -> set[str]:
    if ctx.layout.mock_root:
        dropin_text = ""
        for path in (ctx.layout.ssh_dropin, ctx.layout.legacy_ssh_dropin):
            if path.exists():
                dropin_text += path.read_text(encoding="utf-8") + "\n"
        if dropin_text:
            return set(re.findall(r"(?mi)^Port\s+(\d+)\s*$", dropin_text))
    result = run_privileged_system_command(ctx, ["sshd", "-T"], check=False)
    return set(re.findall(r"(?mi)^port\s+(\d+)\s*$", result.stdout))


def detect_ssh_dual_port(ctx: Context) -> bool:
    ports = _effective_ssh_ports(ctx)
    return "22" in ports and SSH_PORT in ports


def backup_ssh_config(ctx: Context) -> None:
    timestamp = ctx.state.get("updated_at", "now").replace(":", "").replace("-", "")
    ctx.runner.run(["bash", "-lc", f"cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.{timestamp}; cp -a /etc/ssh/sshd_config.d /root/sshd_config.d.bak.{timestamp}"])


def reload_ssh(ctx: Context) -> None:
    ctx.runner.run(["systemctl", "daemon-reload"])
    socket_active = ctx.runner.run(["systemctl", "is-active", "--quiet", "ssh.socket"], check=False).returncode == 0
    if socket_active:
        ctx.runner.run(["systemctl", "restart", "ssh.socket"])
    else:
        result = ctx.runner.run(["systemctl", "reload", "ssh"], check=False)
        if result.returncode != 0:
            ctx.runner.run(["systemctl", "restart", "ssh"])


def privileged_system_args(args: list[str]) -> list[str]:
    return ["sudo", "-n", *args]


def run_privileged_system_command(ctx: Context, args: list[str], **kwargs):
    return ctx.runner.run(privileged_system_args(args), **kwargs)


def sshd_test_config(ctx: Context) -> None:
    run_privileged_system_command(ctx, ["sshd", "-t"])


def sshd_global_effective_config(ctx: Context, *, check: bool = True):
    return run_privileged_system_command(ctx, ["sshd", "-T"], check=check)


def sshd_effective_for_sadmin_result(ctx: Context, *, check: bool = True):
    return run_privileged_system_command(ctx, ["sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA], check=check)


def sshd_effective_for_sadmin(ctx: Context) -> str:
    return sshd_effective_for_sadmin_result(ctx).stdout


def legacy_ssh_dropin_is_bootstrap_owned(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "Managed by lsm-vps-init" in text


def remove_legacy_ssh_dropin_if_safe(ctx: Context) -> bool:
    legacy_path = ctx.layout.legacy_ssh_dropin
    if not os.path.lexists(legacy_path):
        return False
    try:
        link_stat = legacy_path.lstat()
    except OSError as error:
        raise Failed("Unable to inspect obsolete bootstrap SSH drop-in before migration cleanup.") from error
    if not stat.S_ISREG(link_stat.st_mode):
        raise Failed("Refusing to remove obsolete bootstrap SSH drop-in because it is not a regular file.")
    if not legacy_ssh_dropin_is_bootstrap_owned(legacy_path):
        raise Failed("Refusing to remove legacy SSH drop-in path because it is not bootstrap-owned.")
    legacy_path.unlink()
    ctx.runner.log("Removed obsolete bootstrap SSH drop-in: /etc/ssh/sshd_config.d/99-lsm-vps-init.conf")
    return True


def install_managed_ssh_dropin(ctx: Context, phase: str) -> None:
    secure_write(ctx.layout.ssh_dropin, render_ssh_dropin(phase), 0o644)
    if ctx.dry_run:
        remove_legacy_ssh_dropin_if_safe(ctx)
        return
    sshd_test_config(ctx)
    remove_legacy_ssh_dropin_if_safe(ctx)
    sshd_test_config(ctx)


def validate_final_sshd_effective_config(global_effective: str, sadmin_effective: str) -> None:
    ports = set(re.findall(r"(?mi)^port\s+(\d+)\s*$", global_effective))
    issues: list[str] = []
    if SSH_PORT not in ports:
        issues.append(f"port {SSH_PORT} is not enabled")
    if "22" in ports:
        issues.append("port 22 is still enabled")
    if not re.search(r"(?mi)^permitrootlogin\s+no$", global_effective):
        issues.append("PermitRootLogin is not no")
    if not re.search(r"(?mi)^passwordauthentication\s+no$", global_effective):
        issues.append("PasswordAuthentication is not no")
    if not re.search(r"(?mi)^pubkeyauthentication\s+yes$", global_effective):
        issues.append("PubkeyAuthentication is not yes")
    if re.search(r"(?mi)^exposeauthinfo\s+yes$", sadmin_effective):
        issues.append("ExposeAuthInfo remains enabled for sadmin")
    if issues:
        raise Failed("Final sshd effective configuration is not hardened: " + "; ".join(issues))


def ssh_listener_present(ctx: Context, port: str) -> bool:
    if ctx.dry_run and ctx.layout.mock_root:
        return port in _effective_ssh_ports(ctx)
    result = ctx.runner.run(["ss", "-tln"], check=False)
    return f":{port} " in result.stdout or f":{port}\n" in result.stdout


def run_ssh_dual_port(ctx: Context) -> StageResult:
    ctx.require_root()
    stage_intro(ctx, "ssh_dual_port")
    if ctx.dry_run and not ctx.layout.mock_root:
        ctx.runner.log("DRY-RUN: would render SSH dual-port drop-in")
        return StageResult("completed", "Would configure SSH to listen on ports 22 and 65500.", {"ports": ["22", SSH_PORT]})
    if not ctx.dry_run:
        backup_ssh_config(ctx)
        sshd_test_config(ctx)
    install_managed_ssh_dropin(ctx, "dual-port")
    if not ctx.dry_run:
        sshd_global_effective_config(ctx)
        effective_sadmin = sshd_effective_for_sadmin(ctx)
        if not re.search(r"(?mi)^exposeauthinfo\s+yes$", effective_sadmin):
            raise Failed("OpenSSH ExposeAuthInfo is not effective for sadmin; cannot prove public-key checkpoint.")
        reload_ssh(ctx)
        listeners = ctx.runner.run(["ss", "-tln"], check=False).stdout
        if f":22 " not in listeners and ":22\n" not in listeners:
            raise Failed("SSH port 22 is not listening after dual-port change.")
        if f":{SSH_PORT} " not in listeners and f":{SSH_PORT}\n" not in listeners:
            raise Failed(f"SSH port {SSH_PORT} is not listening after dual-port change.")
    return StageResult("completed", "SSH is configured for ports 22 and 65500.", {"ports": ["22", SSH_PORT]})


def detect_firewall_phase_a(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "firewall_phase_a")
    result = ctx.runner.run(["ufw", "status", "verbose"], check=False)
    text = result.stdout
    if result.returncode != 0:
        return False
    try:
        validate_ufw_phase_a_active_status(text, ["22/tcp", f"{SSH_PORT}/tcp"])
    except Failed:
        return False
    return True


def run_firewall_phase_a(ctx: Context) -> StageResult:
    ctx.require_root()
    stage_intro(ctx, "firewall_phase_a")
    current_port = ssh_connection_server_port(os.environ.get("SSH_CONNECTION", ""))
    ports = render_ufw_phase_a_plan(current_port)
    if ctx.dry_run and not ctx.layout.mock_root:
        return StageResult("completed", "Would enable UFW Phase A with ports 22 and 65500 allowed.", {"firewall_ports": ports})
    if not ctx.dry_run:
        ctx.runner.run(["apt-get", "install", "-y", "ufw"])
        ctx.runner.run(["ufw", "default", "deny", "incoming"])
        ctx.runner.run(["ufw", "default", "allow", "outgoing"])
        for port in ports:
            ctx.runner.run(["ufw", "allow", port])
        staged = ctx.runner.run(["ufw", "show", "added"], check=False).stdout
        for port in ports:
            if not ufw_show_added_allows(staged, port):
                raise Failed(f"UFW Phase A did not show required staged allow rule before enable: {port}")
        ctx.runner.run(["ufw", "--force", "enable"])
        enabled = ctx.runner.run(["ufw", "status", "verbose"]).stdout
        validate_ufw_phase_a_active_status(enabled, ports)
    return StageResult("completed", "UFW Phase A is active with ports 22 and 65500 allowed.", {"firewall_ports": ports})


def revalidate_before_final_hardening(ctx: Context) -> None:
    issues: list[str] = []
    ports = _effective_ssh_ports(ctx)
    if SSH_PORT not in ports:
        issues.append(f"effective sshd config does not include port {SSH_PORT}")
    if not ssh_listener_present(ctx, SSH_PORT):
        issues.append(f"sshd is not currently listening on port {SSH_PORT}")
    if not ctx.state.get("checkpoints", {}).get("ssh_recovery_verified"):
        issues.append("sadmin SSH recovery checkpoint is not verified")
    issues.extend(selected_relay_requirements_issues(ctx))
    if not ctx.dry_run and not detect_firewall_phase_a(ctx):
        issues.append("UFW Phase A is not currently active with both 22/tcp and 65500/tcp allowed")
    issues.extend(docker_published_port_issues(ctx))
    if issues:
        raise Blocked("Refusing final hardening until current conditions are fixed: " + "; ".join(issues))


def detect_ssh_recovery(ctx: Context) -> bool:
    return bool(ctx.state.get("checkpoints", {}).get("ssh_recovery_verified"))


def run_ssh_recovery(ctx: Context) -> StageResult:
    stage_intro(ctx, "ssh_recovery_checkpoint")
    ip = ctx.state.get("facts", {}).get("public_ipv4")
    if not ip and not ctx.dry_run:
        ip = public_ipv4(ctx.runner)
        if ip:
            set_fact(ctx.state, "public_ipv4", ip)
    ip = ip or "<SERVER_PUBLIC_IPV4>"
    nonce = ctx.state.get("facts", {}).get("ssh_recovery_nonce")
    if not nonce:
        nonce = secrets.token_hex(12)
        set_fact(ctx.state, "ssh_recovery_nonce", nonce)
    identity_hint = (
        os.environ.get("LSM_VPS_INIT_SSH_IDENTITY_FILE", "").strip()
        or ctx.state.get("facts", {}).get("ssh_identity_file_hint")
        or DEFAULT_SSH_IDENTITY_HINT
    )
    set_fact(ctx.state, "ssh_identity_file_hint", identity_hint)
    bin_path = str(DEFAULT_BIN_PATH)
    remote_command = (
        f"proof=\"$(LSM_VPS_INIT_PUBLICKEY_ONLY=1 {shlex.quote(bin_path)} "
        f"verify-ssh --emit-proof --nonce {shlex.quote(nonce)})\" "
        f"&& proof_file=\"$(mktemp -t lsm-vps-init-ssh-proof.XXXXXXXXXX)\" "
        f"&& chmod 600 \"$proof_file\" "
        f"&& printf '%s\\n' \"$proof\" > \"$proof_file\" "
        f"&& sudo {shlex.quote(bin_path)} record-ssh-proof --nonce {shlex.quote(nonce)} < \"$proof_file\"; "
        f"rc=$?; rm -f \"${{proof_file:-}}\"; exit \"$rc\""
    )
    command = (
        f"ssh -tt -i {shell_quote_local_path_hint(identity_hint)} -o IdentitiesOnly=yes "
        f"-o PasswordAuthentication=no -o KbdInteractiveAuthentication=no "
        f"-o PreferredAuthentications=publickey -p {SSH_PORT} "
        f"sadmin@{ip} {shlex.quote(remote_command)}"
    )
    message = (
        "Hard checkpoint: open a SECOND LOCAL workstation terminal and prove key-based SSH recovery before continuing.\n"
        "Leave the original VPS session open. Edit the -i path if your workstation path differs. "
        "A local private-key passphrase prompt and a remote sadmin sudo password prompt are expected. "
        "Never copy the private key to the VPS.\n"
        f"Run: {command}"
    )
    if ctx.dry_run:
        raise Blocked(message)
    raise Blocked(message)


def detect_management_tooling(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "management_tooling")
    script = "for c in " + " ".join(shlex.quote(c) for c in MANAGEMENT_TOOL_COMMANDS) + '; do command -v "$c" >/dev/null || exit 1; done'
    result = ctx.runner.run(["bash", "-lc", script], check=False)
    if result.returncode != 0:
        return False
    package_result = ctx.runner.run(
        ["dpkg-query", "-W", "-f=${Status}\\n", *MANAGEMENT_TOOL_PACKAGES],
        check=False,
    )
    if package_result.returncode != 0:
        return False
    package_statuses = [line.strip() for line in package_result.stdout.splitlines() if line.strip()]
    if len(package_statuses) != len(MANAGEMENT_TOOL_PACKAGES):
        return False
    if any(line != "install ok installed" for line in package_statuses):
        return False
    node_version = ctx.runner.run(["node", "-e", "console.log(process.versions.node.split('.')[0])"], check=False)
    try:
        node_major = int(node_version.stdout.strip() or "0")
    except ValueError:
        return False
    return node_version.returncode == 0 and node_major >= 20


def run_management_tooling(ctx: Context) -> StageResult:
    ctx.require_root()
    stage_intro(ctx, "management_tooling")
    script = r"""
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
wait_for_apt_locks() {
  local locks=(
    /var/lib/dpkg/lock
    /var/lib/dpkg/lock-frontend
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  local waited=0
  while true; do
    local busy=0
    for lock in "${locks[@]}"; do
      if [ -e "$lock" ] && command -v fuser >/dev/null 2>&1 && fuser "$lock" >/dev/null 2>&1; then
        busy=1
      fi
    done
    if [ "$busy" -eq 0 ]; then
      return 0
    fi
    if [ "$waited" -ge 900 ]; then
      echo "Timed out waiting for apt/dpkg locks." >&2
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
}
wait_for_apt_locks
apt-get update
apt-get install -y curl ca-certificates git jq openssl python3 python3-venv tmux gnupg gpgv xz-utils lsb-release ufw fail2ban unattended-upgrades
if ! command -v gh >/dev/null 2>&1; then
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
  chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list
  apt-get update
  apt-get install -y gh
fi
""" + render_nodejs_install_script() + r"""
if ! command -v node >/dev/null 2>&1 || [ "$(node -e 'console.log(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)" -lt 20 ]; then
  install_official_nodejs
fi
node_major="$(node -e 'console.log(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)"
if [ "$node_major" -lt 20 ]; then
  echo "Node.js 20+ is required for the Discord relay; install an approved Node.js 20+ runtime, then resume." >&2
  exit 42
fi
"""
    result = ctx.runner.run(["bash", "-lc", script], check=False, timeout=3600)
    if result.returncode == 42:
        raise Blocked("Official Node.js binary installation does not support this CPU architecture. Install an approved Node.js 20+ runtime, then resume.")
    if result.returncode == 43:
        raise Blocked("Node.js release-key trust verification failed. Review pinned release-key fingerprints before resuming.")
    if result.returncode != 0:
        raise CommandError(result)
    return StageResult("completed", "Management tooling is installed and Node.js is compatible.")


GITHUB_REQUIRED_REPOS = ("LoudSkyMedia/codex-vps-discord-relay", "LoudSkyMedia/docker-hosting-stack")


def github_cli_config_permissions_ok(ctx: Context) -> bool:
    gh_dir = ctx.layout.sadmin_home / ".config" / "gh"
    if not gh_dir.exists():
        return True
    for path in [gh_dir, *gh_dir.rglob("*")]:
        try:
            mode = file_mode(path)
            if mode is None:
                return False
            if path.is_dir() and mode & 0o077:
                return False
            if path.is_file() and mode & 0o077:
                return False
        except OSError:
            return False
    return True


def enforce_github_cli_config_permissions(ctx: Context) -> None:
    gh_dir = ctx.layout.sadmin_home / ".config" / "gh"
    if ctx.layout.mock_root:
        if gh_dir.exists():
            for path in [gh_dir, *gh_dir.rglob("*")]:
                if path.is_dir():
                    os.chmod(path, 0o700)
                elif path.is_file():
                    os.chmod(path, 0o600)
        return
    script = r"""
set -Eeuo pipefail
dir=/home/sadmin/.config/gh
if [ -d "$dir" ]; then
  chown -R sadmin:sadmin "$dir"
  find "$dir" -type d -exec chmod 0700 {} +
  find "$dir" -type f -exec chmod 0600 {} +
  if find "$dir" \( -type f -o -type d \) -perm /077 -print -quit | grep -q .; then
    echo "GitHub CLI config contains group/other-readable entries." >&2
    exit 1
  fi
fi
"""
    ctx.runner.run(["bash", "-lc", script])


def github_auth_commands_succeed(ctx: Context) -> bool:
    status = ctx.sadmin_shell("gh auth status", check=False)
    if status.returncode != 0:
        return False
    for repo in GITHUB_REQUIRED_REPOS:
        result = ctx.sadmin_shell(f"gh repo view {shlex.quote(repo)} --json nameWithOwner >/dev/null", check=False)
        if result.returncode != 0:
            return False
    return True


def github_auth_is_valid(ctx: Context) -> bool:
    if not github_auth_commands_succeed(ctx):
        return False
    return github_cli_config_permissions_ok(ctx)


def detect_github_auth(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "github_auth")
    return github_auth_is_valid(ctx)


def run_github_auth(ctx: Context) -> StageResult:
    ctx.require_root()
    if ctx.dry_run:
        return StageResult("completed", "Would authenticate GitHub CLI as sadmin and verify private repo access.", {"dry_run": True})
    if github_auth_commands_succeed(ctx):
        enforce_github_cli_config_permissions(ctx)
        if not github_cli_config_permissions_ok(ctx):
            raise Blocked("GitHub CLI auth exists, but config permissions are not root/sadmin-private. Fix permissions and resume.")
        return StageResult("completed", "GitHub CLI is already authenticated as sadmin and can access required repositories.")
    stage_intro(ctx, "github_auth")
    ctx.require_tty("GitHub authentication")
    print(
        "GitHub authentication requires your LOCAL workstation browser.\n"
        "No graphical browser will be opened on this VPS.\n"
        "GitHub CLI will provide an authorization URL/code; open it locally and complete authorization."
    )
    if ctx.confirm("Use PAT/token fallback instead of GitHub web/device OAuth?", default=False):
        token = ctx.prompt_secret("GitHub PAT/token", confirm=False)
        ctx.sadmin_shell("gh auth login --with-token", input_text=token + "\n", secret_stdin=True)
    else:
        handoff = write_browser_handoff(ctx, "github-browser-handoff.sh", "GitHub")
        try:
            ctx.sadmin_interactive_shell(
                f"{headless_browser_env_prefix(handoff)} gh auth login --hostname github.com --git-protocol https --web",
                timeout=900,
            )
        except CommandError as error:
            raise Blocked("GitHub web/device OAuth did not complete. Re-run `sudo lsm-vps-init resume` to retry or explicitly choose PAT fallback.") from error
    ctx.sadmin_shell("gh auth setup-git")
    ctx.sadmin_shell("gh auth status")
    for repo in GITHUB_REQUIRED_REPOS:
        ctx.sadmin_shell(f"gh repo view {shlex.quote(repo)} --json nameWithOwner >/dev/null")
    enforce_github_cli_config_permissions(ctx)
    return StageResult("completed", "GitHub CLI is authenticated as sadmin and can access required repositories.")


def codex_install_validation_script() -> str:
    return (
        "command -v codex >/dev/null && "
        "codex --version >/dev/null && "
        f"{codex_bypass_flag_check_script()}"
    )


def codex_bypass_flag_check_script() -> str:
    return "codex exec --help | grep -q -- '--dangerously-bypass-approvals-and-sandbox'"


def codex_model_availability_check_script() -> str:
    checker = (
        "import json,sys; "
        "data=json.load(sys.stdin); "
        f"model={json.dumps(REQUIRED_CODEX_MODEL)}; "
        f"reasoning={json.dumps(REQUIRED_CODEX_REASONING)}; "
        "ok=any(m.get('slug')==model and any(level.get('effort')==reasoning "
        "for level in m.get('supported_reasoning_levels', [])) for m in data.get('models', [])); "
        "sys.exit(0 if ok else 1)"
    )
    return f"codex debug models | python3 -c {shlex.quote(checker)}"


def codex_install_script() -> str:
    return (
        "set -Eeuo pipefail; "
        "mkdir -p /home/sadmin/.npm-global; "
        "npm config set prefix /home/sadmin/.npm-global; "
        "npm install -g @openai/codex; "
        f"{codex_install_validation_script()}"
    )


def detect_codex_install_auth(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "codex_install_auth")
    script = (
        f"{codex_install_validation_script()} && "
        "codex login status >/dev/null && "
        "test -f /home/sadmin/.codex/config.toml"
    )
    if ctx.sadmin_shell(script, check=False).returncode != 0:
        return False
    try:
        verify_codex_config_defaults(ctx)
    except Blocked:
        return False
    return True


def _write_codex_config(ctx: Context) -> None:
    config_path = ctx.layout.sadmin_home / ".codex" / "config.toml"
    existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    updated = upsert_codex_config(existing)
    secure_write(config_path, updated, 0o600)
    if not ctx.dry_run:
        ctx.runner.run(["chown", "-R", "sadmin:sadmin", "/home/sadmin/.codex"])


def run_codex_install_auth(ctx: Context) -> StageResult:
    ctx.require_root()
    if ctx.dry_run and not ctx.layout.mock_root:
        return StageResult("completed", "Would install/auth Codex as sadmin and configure gpt-5.5 xhigh.", {"dry_run": True})
    stage_intro(ctx, "codex_install_auth")
    if not ctx.dry_run:
        if ctx.sadmin_shell(codex_install_validation_script(), check=False).returncode != 0:
            ctx.sadmin_shell(codex_install_script(), timeout=1800)
            ctx.runner.run(["chown", "-R", "sadmin:sadmin", "/home/sadmin/.npm-global"])
        if ctx.sadmin_shell("codex login status", check=False).returncode != 0:
            ctx.require_tty("Codex authentication")
            print(
                "Codex authentication is being performed for sadmin.\n"
                "Browser authorization happens on your LOCAL workstation; the VPS should not launch a graphical browser.\n"
                "The bootstrap will validate authentication after completion.\n"
                "Never paste OpenAI credentials into arbitrary bootstrap prompts."
            )
            ctx.sadmin_interactive_shell("codex login --device-auth", timeout=900)
        if ctx.sadmin_shell(codex_bypass_flag_check_script(), check=False).returncode != 0:
            raise Blocked("Installed Codex CLI does not expose --dangerously-bypass-approvals-and-sandbox. Stop and review Codex version.")
        models = ctx.sadmin_shell(codex_model_availability_check_script(), check=False, timeout=30)
        if models.returncode != 0:
            raise Blocked(f"Codex model catalog does not list {REQUIRED_CODEX_MODEL} with reasoning effort {REQUIRED_CODEX_REASONING}; do not downgrade silently.")
    _write_codex_config(ctx)
    return StageResult("completed", f"Codex is installed/authenticated as sadmin and configured for {REQUIRED_CODEX_MODEL} {REQUIRED_CODEX_REASONING}.")


def detect_codex_manager_session(ctx: Context) -> bool:
    session_id = ctx.state.get("facts", {}).get("codex_session_id")
    return bool(session_id and re.fullmatch(r"[0-9a-f-]{36}", session_id, re.I))


def run_codex_manager_session(ctx: Context) -> StageResult:
    ctx.require_root()
    stage_intro(ctx, "codex_manager_session")
    if ctx.dry_run:
        session_id = os.environ.get("LSM_VPS_INIT_MOCK_CODEX_SESSION_ID", "00000000-0000-4000-8000-000000000001")
        set_fact(ctx.state, "codex_session_id", session_id)
        return StageResult("completed", "Would create VPS Server Manager Codex session.", {"session_id": session_id})

    prompt = (
        "You are the VPS Server Manager for this authorized Loud Sky Media server. "
        "Use /home/sadmin as the working root. Read /home/sadmin/AGENTS.md before administration work. "
        "Reply with a one-line readiness acknowledgement."
    )
    verify_codex_config_defaults(ctx)
    command = codex_exec_shell_command(json_output=True)
    result = ctx.sadmin_shell(command, input_text=prompt + "\n", timeout=600)
    session_id = extract_codex_session_id(result.stdout)
    if not session_id:
        ctx.require_tty("Codex session ID fallback")
        supplied = ctx.prompt_text("Codex session ID from the new VPS Server Manager session")
        if not re.fullmatch(r"[0-9a-f-]{36}", supplied, re.I):
            raise Blocked("Provided Codex session ID is not a UUID.")
        session_id = supplied
    verify = ctx.sadmin_shell(
        codex_exec_shell_command(session_id=session_id, json_output=True),
        input_text="Reply OK if this VPS Server Manager session resumes.\n",
        timeout=600,
        check=False,
    )
    if verify.returncode != 0:
        raise Blocked("Codex session could not be resumed; review the session ID and Codex auth.")
    set_fact(ctx.state, "codex_session_id", session_id)
    return StageResult("completed", "VPS Server Manager Codex session exists and resumes.", {"session_id": session_id})


def detect_repository_selection(ctx: Context) -> bool:
    modules = ctx.state.get("selected_modules", {})
    if RELAY_MODULE not in modules or DOCKER_MODULE not in modules:
        return False
    if modules.get(DOCKER_MODULE):
        try:
            selected_docker_hosting_mode(ctx)
        except Blocked:
            return False
    return True


def resolve_docker_hosting_mode(ctx: Context, *, prompt: bool, default: str = "base") -> str:
    env_mode = os.environ.get("LSM_VPS_DOCKER_MODE")
    if env_mode:
        mode = validate_docker_hosting_mode(env_mode)
        set_fact(ctx.state, "docker_hosting_mode", mode)
        return mode

    mode = selected_docker_hosting_mode(ctx)
    if mode:
        return mode

    if ctx.dry_run:
        mode = validate_docker_hosting_mode(default)
        set_fact(ctx.state, "docker_hosting_mode", mode)
        return mode

    if not prompt:
        raise Blocked("Docker Hosting Stack capability mode must be selected before firewall hardening.")

    mode = ctx.prompt_text(
        "Docker hosting capability mode (base, standalone-app, n8n, website-migration)",
        default=default,
    )
    mode = validate_docker_hosting_mode(mode)
    set_fact(ctx.state, "docker_hosting_mode", mode)
    return mode


def run_repository_selection(ctx: Context) -> StageResult:
    stage_intro(ctx, "repository_selection")
    env_modules = os.environ.get("LSM_VPS_INIT_MODULES", "").strip()
    if env_modules:
        selected = {item.strip() for item in env_modules.split(",") if item.strip()}
        select_module(ctx.state, RELAY_MODULE, RELAY_MODULE in selected or "relay" in selected)
        select_module(ctx.state, DOCKER_MODULE, DOCKER_MODULE in selected or "docker" in selected or "hosting" in selected)
    elif RELAY_MODULE in ctx.state.get("selected_modules", {}) and DOCKER_MODULE in ctx.state.get("selected_modules", {}):
        pass
    elif ctx.dry_run:
        select_module(ctx.state, RELAY_MODULE, True)
        select_module(ctx.state, DOCKER_MODULE, False)
    else:
        relay = ctx.confirm("Install and verify Codex VPS Discord Relay? Strongly recommended.", default=True)
        docker = ctx.confirm("Install Docker Hosting Stack module now?", default=False)
        select_module(ctx.state, RELAY_MODULE, relay)
        select_module(ctx.state, DOCKER_MODULE, docker)
    if ctx.state.get("selected_modules", {}).get(DOCKER_MODULE):
        resolve_docker_hosting_mode(ctx, prompt=True)
    return StageResult("completed", "Repository module selection recorded.", {"selected_modules": ctx.state["selected_modules"]})


def detect_discord_relay_install(ctx: Context) -> bool:
    modules = ctx.state.get("selected_modules", {})
    if RELAY_MODULE not in modules:
        return False
    if not modules.get(RELAY_MODULE):
        return True
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "discord_relay_install")
    env_path = ctx.layout.sadmin_home / "codex-vps-discord-relay" / ".env"
    config_path = ctx.layout.sadmin_home / ".codex" / "config.toml"
    if not env_path.exists() or not config_path.exists():
        return False
    try:
        _, env_values = read_trusted_existing_relay_env_values(ctx, env_path)
        validate_relay_env_policy(env_values)
        validate_relay_codex_contract(env_values, config_path.read_text(encoding="utf-8", errors="replace"))
        if not relay_existing_values_are_complete(ctx, env_values):
            return False
    except (Blocked, Failed, ValueError):
        return False
    return ctx.sadmin_user_systemd_shell(
        "test -d /home/sadmin/codex-vps-discord-relay/.git "
        "&& cd /home/sadmin/codex-vps-discord-relay "
        "&& npm run preflight >/dev/null "
        "&& systemctl --user is-active --quiet codex-vps-discord-relay.service",
        check=False,
        timeout=120,
    ).returncode == 0


def _relay_env_defaults(ctx: Context) -> dict[str, str]:
    session_id = ctx.state.get("facts", {}).get("codex_session_id", "")
    return {
        "CODEX_VPS_DEFAULT_SESSION_ID": session_id,
        "CODEX_VPS_ROOT": "/home/sadmin",
        "CODEX_VPS_DEFAULT_SESSION_KEY": "vps",
        "CODEX_VPS_DEFAULT_SESSION_LABEL": "VPS Server Manager",
        "CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX": "true",
        "CODEX_VPS_BYPASS_HOOK_TRUST": "true",
        "CODEX_VPS_SKIP_GIT_REPO_CHECK": "true",
        "CODEX_VPS_ENGINE": "exec",
        "CODEX_VPS_ROUTE_UNMAPPED_TO_DEFAULT": "true",
    }


def relay_env_prompt_keys() -> tuple[str, ...]:
    return (
        "DISCORD_BOT_TOKEN",
        "DISCORD_GUILD_ID",
        "CODEX_VPS_DEFAULT_CHANNEL_ID",
        "CODEX_VPS_DEFAULT_SESSION_ID",
        "CODEX_VPS_ALLOWED_USER_IDS",
        "CODEX_VPS_ALLOWED_APPROVER_USER_IDS",
    )


RELAY_DEFAULT_ENV_KEYS = (
    "CODEX_VPS_DEFAULT_SESSION_ID",
    "CODEX_VPS_ROOT",
    "CODEX_VPS_DEFAULT_SESSION_KEY",
    "CODEX_VPS_DEFAULT_SESSION_LABEL",
    "CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX",
    "CODEX_VPS_BYPASS_HOOK_TRUST",
    "CODEX_VPS_SKIP_GIT_REPO_CHECK",
    "CODEX_VPS_ENGINE",
    "CODEX_VPS_ROUTE_UNMAPPED_TO_DEFAULT",
)


def relay_env_managed_keys() -> list[str]:
    return list(dict.fromkeys([*relay_env_prompt_keys(), *RELAY_DEFAULT_ENV_KEYS]))


def relay_existing_env_trust_error(ctx: Context, env_path: Path) -> str | None:
    if not os.path.lexists(env_path):
        return None
    try:
        link_stat = env_path.lstat()
    except OSError:
        return "cannot stat existing relay .env"
    if not stat.S_ISREG(link_stat.st_mode):
        return "existing relay .env is not a regular file"
    mode = stat.S_IMODE(link_stat.st_mode)
    if mode != 0o600:
        return "existing relay .env must be mode 0600"
    uid = int(ctx.sadmin_uid())
    if link_stat.st_uid != uid:
        return "existing relay .env must be owned by sadmin"
    return None


def relay_env_values_from_existing_text(text: str, keys: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in keys:
        try:
            values[key] = parse_env_value(text, key) or ""
        except ValueError:
            values[key] = ""
    return values


def read_trusted_existing_relay_env_values(ctx: Context, env_path: Path) -> tuple[str, dict[str, str]]:
    if not os.path.lexists(env_path):
        return "", {}
    trust_error = relay_existing_env_trust_error(ctx, env_path)
    if trust_error:
        raise Blocked(f"Existing relay .env is not safe to reuse: {trust_error}. Fix it or move it aside, then resume.")
    existing = env_path.read_text(encoding="utf-8")
    return existing, relay_env_values_from_existing_text(existing, relay_env_managed_keys())


def relay_existing_value_valid(ctx: Context, key: str, value: str) -> bool:
    if key == "DISCORD_BOT_TOKEN":
        return bool(value)
    if key in {"DISCORD_GUILD_ID", "CODEX_VPS_DEFAULT_CHANNEL_ID"}:
        try:
            validate_discord_id(value, key)
            return True
        except Blocked:
            return False
    if key == "CODEX_VPS_ALLOWED_USER_IDS":
        try:
            validate_discord_id_list(value, key, required=True)
            return True
        except Blocked:
            return False
    if key == "CODEX_VPS_ALLOWED_APPROVER_USER_IDS":
        try:
            validate_discord_id_list(value, key, required=False)
            return bool(value.strip()) or bool(ctx.state.get("facts", {}).get("relay_no_remote_approval_authority"))
        except Blocked:
            return False
    if key == "CODEX_VPS_DEFAULT_SESSION_ID":
        return bool(value)
    return bool(value)


def relay_existing_values_are_complete(ctx: Context, values: dict[str, str]) -> bool:
    return all(relay_existing_value_valid(ctx, key, values.get(key, "")) for key in relay_env_prompt_keys())


def print_discord_setup_guidance() -> None:
    print()
    print("Discord relay setup")
    print("Prepare these values before continuing:")
    print("- Developer Portal: create/select Application -> Bot.")
    print("- Bot token: SECRET from the Bot page. Paste only into the hidden bootstrap prompt.")
    print("- Never paste the token into Discord messages, GitHub, docs, or shell command arguments.")
    print("- Rotate the token immediately if it is exposed.")
    print("- Required intents: Message Content Intent ON; Presence Intent OFF; Server Members Intent OFF.")
    print("- Install type: Guild Install only.")
    print("- Permissions: View Channel, Send Messages, Embed Links, Attach Files, Read Message History.")
    print("- Permission integer: 117760.")
    print("- Enable Discord Developer Mode, then copy Server ID, Channel ID, and trusted operator User IDs.")
    print("- Allowed approver IDs grant separate remote approval authority; leaving them empty disables remote approvals.")


def _relay_env_updates(ctx: Context, existing_values: dict[str, str] | None = None) -> dict[str, str]:
    defaults = _relay_env_defaults(ctx)
    if ctx.dry_run:
        updates = {
            **defaults,
            "DISCORD_BOT_TOKEN": "dry-run-token-not-written-to-real-system",
            "DISCORD_GUILD_ID": "100000000000000000",
            "CODEX_VPS_DEFAULT_CHANNEL_ID": "100000000000000001",
            "CODEX_VPS_ALLOWED_USER_IDS": "100000000000000002",
            "CODEX_VPS_ALLOWED_APPROVER_USER_IDS": "100000000000000002",
        }
        validate_relay_env_policy(updates)
        return updates
    existing_values = existing_values or {}
    updates = dict(defaults)
    missing = [key for key in relay_env_prompt_keys() if not relay_existing_value_valid(ctx, key, existing_values.get(key, ""))]
    if missing:
        print_discord_setup_guidance()
        confirm_ready_or_pause(
            ctx,
            "Are the Discord bot token and required Discord IDs ready now?",
            "Paused before Discord relay configuration.",
        )
    if relay_existing_value_valid(ctx, "DISCORD_BOT_TOKEN", existing_values.get("DISCORD_BOT_TOKEN", "")):
        updates["DISCORD_BOT_TOKEN"] = existing_values["DISCORD_BOT_TOKEN"]
    else:
        updates["DISCORD_BOT_TOKEN"] = ctx.prompt_secret("Discord bot token", confirm=False)
    if relay_existing_value_valid(ctx, "DISCORD_GUILD_ID", existing_values.get("DISCORD_GUILD_ID", "")):
        updates["DISCORD_GUILD_ID"] = existing_values["DISCORD_GUILD_ID"]
    else:
        updates["DISCORD_GUILD_ID"] = ctx.prompt_text("Discord server/guild ID")
    if relay_existing_value_valid(ctx, "CODEX_VPS_DEFAULT_CHANNEL_ID", existing_values.get("CODEX_VPS_DEFAULT_CHANNEL_ID", "")):
        updates["CODEX_VPS_DEFAULT_CHANNEL_ID"] = existing_values["CODEX_VPS_DEFAULT_CHANNEL_ID"]
    else:
        updates["CODEX_VPS_DEFAULT_CHANNEL_ID"] = ctx.prompt_text("Discord channel ID for the VPS session")
    if relay_existing_value_valid(ctx, "CODEX_VPS_DEFAULT_SESSION_ID", existing_values.get("CODEX_VPS_DEFAULT_SESSION_ID", "")):
        updates["CODEX_VPS_DEFAULT_SESSION_ID"] = existing_values["CODEX_VPS_DEFAULT_SESSION_ID"]
    else:
        updates["CODEX_VPS_DEFAULT_SESSION_ID"] = ctx.prompt_text("Codex VPS default session ID", default=defaults["CODEX_VPS_DEFAULT_SESSION_ID"])
    if relay_existing_value_valid(ctx, "CODEX_VPS_ALLOWED_USER_IDS", existing_values.get("CODEX_VPS_ALLOWED_USER_IDS", "")):
        updates["CODEX_VPS_ALLOWED_USER_IDS"] = existing_values["CODEX_VPS_ALLOWED_USER_IDS"]
    else:
        updates["CODEX_VPS_ALLOWED_USER_IDS"] = ctx.prompt_text("Comma-separated allowed Discord user IDs")
    if relay_existing_value_valid(ctx, "CODEX_VPS_ALLOWED_APPROVER_USER_IDS", existing_values.get("CODEX_VPS_ALLOWED_APPROVER_USER_IDS", "")):
        updates["CODEX_VPS_ALLOWED_APPROVER_USER_IDS"] = existing_values.get("CODEX_VPS_ALLOWED_APPROVER_USER_IDS", "")
    else:
        approvers = ctx.prompt_text("Comma-separated allowed Discord approver user IDs", required=False)
        if not approvers:
            if not ctx.confirm("No human approver ACL means Plan/sensitive approvals cannot be granted through Discord. Continue with no-approval setup?", default=False):
                raise Blocked("At least one CODEX_VPS_ALLOWED_APPROVER_USER_IDS value is required unless no-approval setup is explicitly selected.")
            set_fact(ctx.state, "relay_no_remote_approval_authority", True)
        updates["CODEX_VPS_ALLOWED_APPROVER_USER_IDS"] = approvers
    validate_relay_env_policy(updates)
    return updates


def validate_relay_env_policy(values: dict[str, str]) -> None:
    validate_discord_id(values.get("DISCORD_GUILD_ID", ""), "DISCORD_GUILD_ID")
    validate_discord_id(values.get("CODEX_VPS_DEFAULT_CHANNEL_ID", ""), "CODEX_VPS_DEFAULT_CHANNEL_ID")
    validate_discord_id_list(values.get("CODEX_VPS_ALLOWED_USER_IDS", ""), "CODEX_VPS_ALLOWED_USER_IDS", required=True)
    validate_discord_id_list(values.get("CODEX_VPS_ALLOWED_APPROVER_USER_IDS", ""), "CODEX_VPS_ALLOWED_APPROVER_USER_IDS", required=False)


def validate_relay_codex_contract(values: dict[str, str], codex_config_text: str) -> None:
    if values.get("CODEX_VPS_ROOT") != CODEX_WORK_ROOT:
        raise Blocked(f"CODEX_VPS_ROOT must be {CODEX_WORK_ROOT} for bootstrap-managed relay sessions.")
    if values.get("CODEX_VPS_ENGINE", "exec").strip().lower() != "exec":
        raise Blocked("Bootstrap-managed relay sessions currently require CODEX_VPS_ENGINE=exec.")
    if values.get("CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX", "").strip().lower() != "true":
        raise Blocked("Bootstrap-managed relay sessions require CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX=true.")
    if values.get("CODEX_VPS_SKIP_GIT_REPO_CHECK", "").strip().lower() != "true":
        raise Blocked("Bootstrap-managed relay sessions require CODEX_VPS_SKIP_GIT_REPO_CHECK=true.")
    if not values.get("CODEX_VPS_DEFAULT_SESSION_ID"):
        raise Blocked("CODEX_VPS_DEFAULT_SESSION_ID is required for bootstrap-managed relay sessions.")
    if not codex_config_has_required_defaults(codex_config_text):
        raise Blocked(f"Relay Codex config must inherit model={REQUIRED_CODEX_MODEL} and model_reasoning_effort={REQUIRED_CODEX_REASONING}.")


def relay_env_values_from_text(text: str, keys: list[str]) -> dict[str, str]:
    return {key: parse_env_value(text, key) or "" for key in keys}


RELAY_CONTRACT_KEYS = [
    "DISCORD_GUILD_ID",
    "CODEX_VPS_DEFAULT_CHANNEL_ID",
    "CODEX_VPS_ALLOWED_USER_IDS",
    "CODEX_VPS_ALLOWED_APPROVER_USER_IDS",
    "CODEX_VPS_DEFAULT_SESSION_ID",
    "CODEX_VPS_ROOT",
    "CODEX_VPS_ENGINE",
    "CODEX_VPS_BYPASS_APPROVALS_AND_SANDBOX",
    "CODEX_VPS_SKIP_GIT_REPO_CHECK",
]


RELAY_NATIVE_BUILD_TOOLS = ("make", "g++", "python3")


def relay_native_build_tool_check_script() -> str:
    tools = " ".join(shlex.quote(tool) for tool in RELAY_NATIVE_BUILD_TOOLS)
    return f'for c in {tools}; do command -v "$c" >/dev/null 2>&1 || exit 1; done'


def render_relay_native_build_prerequisite_install_script() -> str:
    return r"""
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
wait_for_apt_locks() {
  local locks=(
    /var/lib/dpkg/lock
    /var/lib/dpkg/lock-frontend
    /var/lib/apt/lists/lock
    /var/cache/apt/archives/lock
  )
  local waited=0
  while true; do
    local busy=0
    for lock in "${locks[@]}"; do
      if [ -e "$lock" ] && command -v fuser >/dev/null 2>&1 && fuser "$lock" >/dev/null 2>&1; then
        busy=1
      fi
    done
    if [ "$busy" -eq 0 ]; then
      return 0
    fi
    if [ "$waited" -ge 900 ]; then
      echo "Timed out waiting for apt/dpkg locks." >&2
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
}
wait_for_apt_locks
apt-get update
apt-get install -y build-essential
"""


def relay_native_build_prerequisites_present(ctx: Context) -> bool:
    return ctx.runner.run(["bash", "-lc", relay_native_build_tool_check_script()], check=False).returncode == 0


def ensure_relay_native_build_prerequisites(ctx: Context) -> None:
    if relay_native_build_prerequisites_present(ctx):
        return
    result = ctx.runner.run(["bash", "-lc", render_relay_native_build_prerequisite_install_script()], check=False, timeout=1800)
    if result.returncode != 0:
        raise Failed(
            "Discord relay native Node addon build prerequisites could not be installed. "
            "Ubuntu package build-essential is required for make/g++; python3 is validated separately for node-gyp. "
            "Repair apt/dpkg state, then resume with `sudo lsm-vps-init resume`."
        )
    if not relay_native_build_prerequisites_present(ctx):
        raise Failed(
            "Discord relay native Node addon build prerequisite validation failed after installation. "
            "Required commands: make, g++, python3. Fix the package state, then resume with `sudo lsm-vps-init resume`."
        )


def prepare_sadmin_user_manager(ctx: Context) -> str:
    uid = ctx.sadmin_uid()
    ctx.runner.run(["loginctl", "enable-linger", "sadmin"])
    ctx.runner.run(["systemctl", "start", f"user@{uid}.service"], check=False, timeout=120)
    verify = ctx.sadmin_user_systemd_shell(
        'test -d "$XDG_RUNTIME_DIR" '
        '&& test -S "$XDG_RUNTIME_DIR/bus" '
        "&& systemctl --user is-system-running >/dev/null",
        check=False,
        timeout=120,
        uid=uid,
    )
    if verify.returncode != 0:
        raise Failed(
            "sadmin user systemd manager is not reachable through the expected runtime bus. "
            f"Expected XDG_RUNTIME_DIR=/run/user/{uid} and DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus. "
            "Review logind/user@ service state, then resume with `sudo lsm-vps-init resume`."
        )
    return uid


def relay_native_build_failure_hint(result) -> str | None:
    text = f"{result.stdout}\n{result.stderr}".lower()
    markers = ("node-gyp", "gyp err", "no prebuilt binary", "not found: make", "better-sqlite3")
    if not any(marker in text for marker in markers):
        return None
    return (
        "Discord relay installer failed while building a native Node dependency. "
        "This commonly means node-gyp could not use make/g++/python3 even after bootstrap prerequisite validation. "
        "Verify `command -v make`, `command -v g++`, and `command -v python3`, inspect the relay npm output, then resume."
    )


def run_discord_relay_install(ctx: Context) -> StageResult:
    if not ctx.state.get("selected_modules", {}).get(RELAY_MODULE):
        return StageResult("completed", "Discord relay module was not selected.")
    ctx.require_root()
    stage_intro(ctx, "discord_relay_install")
    repo_path = ctx.layout.sadmin_home / "codex-vps-discord-relay"
    if ctx.dry_run and not ctx.layout.mock_root:
        return StageResult("blocked", "Would clone/configure relay and run its installer; functional values are required on a real VPS.", {"dry_run": True})
    if not ctx.dry_run:
        clone_script = (
            "if [ -d /home/sadmin/codex-vps-discord-relay/.git ]; then "
            "cd /home/sadmin/codex-vps-discord-relay && git pull --ff-only; "
            "else gh repo clone LoudSkyMedia/codex-vps-discord-relay /home/sadmin/codex-vps-discord-relay; fi"
        )
        ctx.sadmin_shell(clone_script, timeout=300)
    else:
        repo_path.mkdir(parents=True, exist_ok=True)
    env_path = repo_path / ".env"
    existing, existing_values = read_trusted_existing_relay_env_values(ctx, env_path)
    updates = _relay_env_updates(ctx, existing_values)
    if not updates.get("CODEX_VPS_ALLOWED_USER_IDS"):
        raise Blocked("CODEX_VPS_ALLOWED_USER_IDS must not be empty for this privileged bootstrap.")
    config_path = ctx.layout.sadmin_home / ".codex" / "config.toml"
    if not ctx.dry_run:
        verify_codex_config_defaults(ctx)
    config_text = config_path.read_text(encoding="utf-8", errors="replace") if config_path.exists() else upsert_codex_config("")
    validate_relay_codex_contract(updates, config_text)
    secure_write(env_path, merge_env_text(existing, updates), 0o600)
    if not ctx.dry_run:
        ctx.runner.run(["chown", "sadmin:sadmin", "/home/sadmin/codex-vps-discord-relay/.env"])
        uid = prepare_sadmin_user_manager(ctx)
        ensure_relay_native_build_prerequisites(ctx)
        ctx.sadmin_shell("cd /home/sadmin/codex-vps-discord-relay && chmod +x bin/*.sh bin/preflight.js bin/codex-vps-relay hooks/codex_vps_notify.py")
        try:
            ctx.sadmin_user_systemd_shell("cd /home/sadmin/codex-vps-discord-relay && bin/install-service.sh", timeout=1800, uid=uid)
        except CommandError as error:
            hint = relay_native_build_failure_hint(error.result)
            if hint:
                raise Failed(hint) from error
            raise
        ctx.sadmin_shell("cd /home/sadmin/codex-vps-discord-relay && bin/install-hook.sh", timeout=300)
        ctx.sadmin_user_systemd_shell("cd /home/sadmin/codex-vps-discord-relay && npm run preflight", timeout=300, uid=uid)
        verify_codex_config_defaults(ctx)
        ctx.sadmin_user_systemd_shell("systemctl --user is-active --quiet codex-vps-discord-relay.service", uid=uid)
    return StageResult("completed", "Discord relay repository is installed and delegated preflight/service checks passed.")


def detect_discord_relay_checkpoint(ctx: Context) -> bool:
    modules = ctx.state.get("selected_modules", {})
    if RELAY_MODULE not in modules:
        return False
    if not modules.get(RELAY_MODULE):
        return True
    return bool(ctx.state.get("checkpoints", {}).get("relay_round_trip_verified"))


def run_discord_relay_checkpoint(ctx: Context) -> StageResult:
    if not ctx.state.get("selected_modules", {}).get(RELAY_MODULE):
        return StageResult("completed", "Discord relay module was not selected.")
    stage_intro(ctx, "discord_relay_checkpoint")
    instruction = (
        "Post this in the configured Discord channel from an allowed user: "
        "`Reply with the hostname and say lsm relay checkpoint ok.` "
        "Confirm only after the relay sends the Codex response back to Discord."
    )
    if ctx.dry_run:
        raise Blocked("Functional Discord relay checkpoint is manual in v1. " + instruction)
    if ctx.confirm(instruction, default=False):
        set_checkpoint(ctx.state, "relay_round_trip_verified", True)
        return StageResult("completed", "Operator confirmed Discord -> relay -> Codex -> Discord round trip.")
    raise Blocked("Relay round trip is required before final SSH/firewall hardening.")


def detect_final_host_hardening(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "final_host_hardening")
    result = sshd_global_effective_config(ctx, check=False)
    if result.returncode != 0:
        return False
    sadmin_result = sshd_effective_for_sadmin_result(ctx, check=False)
    if sadmin_result.returncode != 0:
        return False
    try:
        validate_final_sshd_effective_config(result.stdout, sadmin_result.stdout)
    except Failed:
        return False
    status_result = ctx.runner.run(["ufw", "status", "verbose"], check=False)
    if status_result.returncode != 0 or not ufw_status_is_active(status_result.stdout):
        return False
    if ctx.state.get("selected_modules", {}).get(DOCKER_MODULE):
        try:
            if selected_docker_hosting_mode(ctx) is None:
                return True
        except Blocked:
            return False
    try:
        validate_final_ufw_status(status_result.stdout, firewall_ports_for_state(ctx))
    except Failed:
        return False
    return True


def run_final_host_hardening(ctx: Context) -> StageResult:
    ctx.require_root()
    stage_intro(ctx, "final_host_hardening")
    mode: str | None = None
    if ctx.state.get("selected_modules", {}).get(DOCKER_MODULE):
        mode = resolve_docker_hosting_mode(ctx, prompt=True)
    ports = firewall_ports_for_state(ctx)
    if ctx.dry_run and not ctx.layout.mock_root:
        if not ctx.state.get("checkpoints", {}).get("ssh_recovery_verified"):
            raise Blocked("Refusing hardening: sadmin SSH recovery on port 65500 is not verified.")
        if ctx.state.get("selected_modules", {}).get(RELAY_MODULE) and not ctx.state.get("checkpoints", {}).get("relay_round_trip_verified"):
            raise Blocked("Refusing hardening: Discord/Codex relay round trip is not verified.")
    else:
        if mode and try_reconcile_already_hardened_final_firewall(ctx, mode):
            return StageResult("completed", "Final host hardening already applied; reconciled capability-specific firewall rules.", {"firewall_ports": ports})
        revalidate_before_final_hardening(ctx)
    plan = "\n".join(
        [
            "Final hardening plan:",
            f"- SSH drop-in will keep only port {SSH_PORT}",
            "- PermitRootLogin no",
            "- PasswordAuthentication no",
            "- PubkeyAuthentication yes",
            "- UFW default deny incoming / allow outgoing",
            "- UFW remove 22/tcp",
            *(f"- UFW allow {port}" for port in ports),
            f"- fail2ban sshd jail on port {SSH_PORT}",
            "- unattended security updates enabled",
        ]
    )
    ctx.runner.log(plan)
    if ctx.dry_run and not ctx.layout.mock_root:
        return StageResult("completed", "Would apply final SSH/firewall hardening.", {"firewall_ports": ports})
    if not ctx.dry_run and not ctx.confirm(plan + "\nProceed with final hardening?", default=False):
        raise Blocked("Final hardening requires explicit operator confirmation.")
    if not ctx.dry_run:
        backup_ssh_config(ctx)
        sshd_test_config(ctx)
        sshd_global_effective_config(ctx)
        sshd_effective_for_sadmin(ctx)
    install_managed_ssh_dropin(ctx, "hardened")
    if not ctx.dry_run:
        hardened_global = sshd_global_effective_config(ctx).stdout
        hardened_sadmin = sshd_effective_for_sadmin(ctx)
        validate_final_sshd_effective_config(hardened_global, hardened_sadmin)
        reload_ssh(ctx)
        hardened_after_reload = sshd_effective_for_sadmin(ctx)
        validate_final_sshd_effective_config(sshd_global_effective_config(ctx).stdout, hardened_after_reload)
        ctx.runner.run(["apt-get", "install", "-y", "ufw", "fail2ban", "unattended-upgrades"])
        ctx.runner.run(["ufw", "default", "deny", "incoming"])
        ctx.runner.run(["ufw", "default", "allow", "outgoing"])
        reconcile_ufw_final_rules(ctx, ports)
        fail2ban = (
            "[sshd]\n"
            "enabled = true\n"
            f"port = {SSH_PORT}\n"
            "backend = systemd\n"
            "maxretry = 5\n"
            "findtime = 10m\n"
            "bantime = 1h\n"
        )
        secure_write(ctx.layout.map("/etc/fail2ban/jail.d/lsm-sshd.local"), fail2ban, 0o644)
        secure_write(
            ctx.layout.map("/etc/apt/apt.conf.d/20auto-upgrades"),
            'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',
            0o644,
        )
        ctx.runner.run(["systemctl", "enable", "--now", "fail2ban"])
        ctx.runner.run(["systemctl", "restart", "unattended-upgrades"], check=False)
        listeners = ctx.runner.run(["ss", "-tulpn"], check=False).stdout
        if ":2375" in listeners or ":2376" in listeners:
            raise Failed("Docker Engine appears exposed over TCP; close 2375/2376 before proceeding.")
    return StageResult("completed", "Final host hardening applied.", {"firewall_ports": ports})


def detect_docker_hosting_stack(ctx: Context) -> bool:
    modules = ctx.state.get("selected_modules", {})
    if DOCKER_MODULE not in modules:
        return False
    if not modules.get(DOCKER_MODULE):
        return True
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "docker_hosting_stack")
    if not detected_stage_by_state(ctx, "docker_hosting_stack"):
        return False
    return Path(DOCKER_HOSTING_REPO, ".git").exists()


def protected_sadmin_env_file_trust_error(
    ctx: Context,
    env_path: Path,
    label: str,
    *,
    required: bool = False,
    uid: int | None = None,
) -> str | None:
    if not os.path.lexists(env_path):
        if required:
            return f"{label} is missing"
        return None
    try:
        link_stat = env_path.lstat()
    except OSError:
        return f"cannot stat {label}"
    if not stat.S_ISREG(link_stat.st_mode):
        return f"{label} is not a regular file"
    mode = stat.S_IMODE(link_stat.st_mode)
    if mode != 0o600:
        return f"{label} must be mode 0600"
    expected_uid = uid if uid is not None else int(ctx.sadmin_uid())
    if link_stat.st_uid != expected_uid:
        return f"{label} must be owned by sadmin"
    return None


def docker_existing_env_trust_error(ctx: Context, env_path: Path, *, uid: int | None = None) -> str | None:
    return protected_sadmin_env_file_trust_error(ctx, env_path, "existing Docker Hosting Stack .env", uid=uid)


def docker_env_values_from_existing_text(text: str, keys: tuple[str, ...]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in keys:
        try:
            values[key] = parse_env_value(text, key) or ""
        except ValueError:
            values[key] = ""
    return values


def read_trusted_existing_docker_env_values(ctx: Context, env_path: Path, *, uid: int | None = None) -> tuple[str, dict[str, str]]:
    if not os.path.lexists(env_path):
        return "", {}
    trust_error = docker_existing_env_trust_error(ctx, env_path, uid=uid)
    if trust_error:
        raise Blocked(f"Existing Docker Hosting Stack .env is not safe to reuse: {trust_error}. Fix it or move it aside, then resume.")
    existing = env_path.read_text(encoding="utf-8")
    return existing, docker_env_values_from_existing_text(existing, DOCKER_HOSTING_MANAGED_ENV_KEYS)


def _single_line_value(value: str) -> bool:
    return bool(value) and "\x00" not in value and "\n" not in value and "\r" not in value


def docker_env_value_is_placeholder(key: str, value: str) -> bool:
    lower_value = value.lower()
    if value in {
        "example-vps",
        "server.example.com",
        "admin.example.com",
        "webmail.example.com",
        "pma.example.com",
        "pma.admin.example.com",
        "sftp.example.com",
        "sftp.admin.example.com",
    }:
        return True
    if value == "example.com" or value.endswith(".example.com"):
        return True
    if key == "CADDY_ACME_EMAIL" and lower_value.endswith("@example.com"):
        return True
    if key in {"SERVER_PUBLIC_IPV4", "MAIL_IPV4", "DEDICATED_WEB_IPV4"}:
        return any(value.startswith(prefix) for prefix in ("203.0.113.", "192.0.2.", "198.51.100."))
    return False


def validate_hostname_value(value: str) -> bool:
    candidate = value.strip().rstrip(".")
    if "://" in candidate or "/" in candidate or len(candidate) > 253:
        return False
    labels = candidate.split(".")
    if len(labels) < 2:
        return False
    return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels)


def validate_ipv4_value(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value.strip())
    except ValueError:
        return False
    return True


def validate_docker_hosting_env_value(key: str, value: str) -> bool:
    if not _single_line_value(value):
        return False
    if key in {"SUDO_PASSWORD", "CF_API_TOKEN"}:
        return True
    stripped = value.strip()
    if docker_env_value_is_placeholder(key, stripped):
        return False
    if key == "INSTANCE_NAME":
        return bool(stripped)
    if key in {"SERVER_FQDN", "ADMIN_DOMAIN", "PHPMYADMIN_HOSTNAME", "SFTPGO_ADMIN_HOSTNAME", "N8N_HOSTNAME"}:
        return validate_hostname_value(stripped)
    if key == "SERVER_PUBLIC_IPV4":
        return validate_ipv4_value(stripped)
    if key == "CADDY_ACME_EMAIL":
        return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", stripped))
    if key == "CF_ACCOUNT_ID":
        return bool(re.fullmatch(r"[A-Za-z0-9_-]{16,128}", stripped))
    return bool(stripped)


def validate_docker_n8n_env_value(key: str, value: str) -> bool:
    return validate_docker_hosting_env_value(key, value)


def docker_existing_value_valid(key: str, value: str) -> bool:
    return validate_docker_hosting_env_value(key, value)


def print_docker_hosting_guidance(mode: str) -> None:
    print()
    print(f"Docker Hosting Stack {mode} setup")
    print("Prepare the required values before continuing. Copied example placeholders are treated as missing.")
    if mode == "standalone-app":
        print("- INSTANCE_NAME: nonsecret label for this host/application capability.")
        print("- SERVER_PUBLIC_IPV4: public IPv4 for this VPS.")
        print("- This mode does not require Cloudflare, Caddy, phpMyAdmin, SFTPGo, or public 80/443 ingress.")
    elif mode == "n8n":
        print("- INSTANCE_NAME: nonsecret label for this host.")
        print("- SERVER_PUBLIC_IPV4: public IPv4 for this VPS.")
        print("- CADDY_ACME_EMAIL: email used by Caddy for ACME/certificate operations.")
        print("- CF_ACCOUNT_ID: Cloudflare account ID from the Cloudflare dashboard account URL/sidebar.")
        print("- CF_API_TOKEN: SECRET created in Cloudflare API Tokens with least privilege.")
        print("- N8N_HOSTNAME: public hostname intended for the n8n instance; DNS must be ready for validation.")
        print("- N8N_ENCRYPTION_KEY is not collected into the hosting repository .env.")
        print("  It belongs to the hosting stack's protected n8n secret workflow.")
    else:
        print("- INSTANCE_NAME, SERVER_FQDN, ADMIN_DOMAIN, and SERVER_PUBLIC_IPV4 for the hosting VPS.")
        print("- PHPMYADMIN_HOSTNAME and SFTPGO_ADMIN_HOSTNAME for admin tooling.")
        print("- CADDY_ACME_EMAIL, CF_ACCOUNT_ID, and a least-privilege CF_API_TOKEN for public HTTPS/DNS validation.")


def print_docker_n8n_guidance() -> None:
    print_docker_hosting_guidance("n8n")


def docker_derived_env_default(ctx: Context, key: str) -> str | None:
    if key == "SERVER_PUBLIC_IPV4":
        value = str(ctx.state.get("facts", {}).get("public_ipv4") or "").strip()
        if validate_docker_hosting_env_value(key, value):
            return value
    if key == "INSTANCE_NAME":
        value = str(ctx.state.get("facts", {}).get("instance_name") or "").strip()
        if validate_docker_hosting_env_value(key, value):
            return value
        value = socket.gethostname().strip()
        if validate_docker_hosting_env_value(key, value):
            return value
    return None


def docker_prompt_label(mode: str, key: str) -> str:
    labels = {
        "INSTANCE_NAME": "Docker Hosting Stack instance name",
        "SERVER_FQDN": "Server FQDN",
        "ADMIN_DOMAIN": "Admin domain",
        "SERVER_PUBLIC_IPV4": "Server public IPv4 address",
        "PHPMYADMIN_HOSTNAME": "phpMyAdmin hostname",
        "SFTPGO_ADMIN_HOSTNAME": "SFTPGo admin hostname",
        "CADDY_ACME_EMAIL": "Caddy ACME email for n8n HTTPS certificates" if mode == "n8n" else "Caddy ACME email for HTTPS certificates",
        "CF_ACCOUNT_ID": "Cloudflare account ID",
        "CF_API_TOKEN": "Cloudflare API token",
        "N8N_HOSTNAME": "n8n public hostname",
    }
    return labels.get(key, key)


def _prompt_docker_hosting_value(ctx: Context, mode: str, key: str) -> str:
    default = docker_derived_env_default(ctx, key)
    if default and key in {"INSTANCE_NAME", "SERVER_PUBLIC_IPV4"}:
        return default
    if key == "CADDY_ACME_EMAIL":
        value = ctx.prompt_text(docker_prompt_label(mode, key), default=default)
    elif key == "CF_API_TOKEN":
        value = ctx.prompt_secret(docker_prompt_label(mode, key), confirm=False)
    elif key == "N8N_HOSTNAME":
        value = ctx.prompt_text(docker_prompt_label(mode, key), default=default)
    elif key == "SUDO_PASSWORD":
        raise AssertionError("SUDO_PASSWORD is copied from /home/sadmin/.env, not prompted")
    else:
        value = ctx.prompt_text(docker_prompt_label(mode, key), default=default)
    if not validate_docker_hosting_env_value(key, value):
        raise Blocked(f"{key} is missing or invalid for Docker Hosting Stack {mode} provisioning.")
    return value


def _prompt_docker_n8n_value(ctx: Context, key: str) -> str:
    return _prompt_docker_hosting_value(ctx, "n8n", key)


def docker_hosting_mode_env_updates(ctx: Context, mode: str, existing_values: dict[str, str]) -> dict[str, str]:
    updates: dict[str, str] = {}
    required_keys = docker_hosting_required_env_keys(mode)
    missing = [key for key in required_keys if not docker_existing_value_valid(key, existing_values.get(key, ""))]
    if missing:
        print_docker_hosting_guidance(mode)
        confirm_ready_or_pause(
            ctx,
            f"Are the Docker Hosting Stack {mode} values ready now?",
            f"Paused before Docker Hosting Stack {mode} configuration.",
        )
    for key in required_keys:
        if docker_existing_value_valid(key, existing_values.get(key, "")):
            continue
        updates[key] = _prompt_docker_hosting_value(ctx, mode, key)
    return updates


def docker_n8n_env_updates(ctx: Context, existing_values: dict[str, str]) -> dict[str, str]:
    return docker_hosting_mode_env_updates(ctx, "n8n", existing_values)


def read_sadmin_sudo_password(ctx: Context, uid: int) -> str:
    trust_error = protected_sadmin_env_file_trust_error(
        ctx,
        ctx.layout.sadmin_env,
        "sadmin .env",
        required=True,
        uid=uid,
    )
    if trust_error:
        raise Blocked(f"Cannot safely read approved sadmin sudo credential: {trust_error}. Fix /home/sadmin/.env, then resume.")
    try:
        text = ctx.layout.sadmin_env.read_text(encoding="utf-8")
    except OSError as error:
        raise Blocked("Cannot safely read approved sadmin sudo credential. Fix /home/sadmin/.env, then resume.") from error
    try:
        sudo_password = parse_env_value(text, "SUDO_PASSWORD") or ""
    except ValueError as error:
        raise Blocked("Cannot parse SUDO_PASSWORD from /home/sadmin/.env safely. Fix the protected file, then resume.") from error
    if not docker_existing_value_valid("SUDO_PASSWORD", sudo_password):
        raise Blocked("SUDO_PASSWORD is missing or unsafe in /home/sadmin/.env. Fix the protected file, then resume.")
    return sudo_password


def docker_hosting_env_updates(ctx: Context, mode: str, existing_values: dict[str, str], sudo_password: str) -> dict[str, str]:
    updates: dict[str, str] = {}
    if existing_values.get("SUDO_PASSWORD") != sudo_password:
        updates["SUDO_PASSWORD"] = sudo_password
    updates.update(docker_hosting_mode_env_updates(ctx, mode, {**existing_values, **updates}))
    return updates


def ensure_docker_hosting_env(ctx: Context, repo_path: Path, mode: str) -> dict[str, str]:
    env_path = repo_path / ".env"
    uid = int(ctx.sadmin_uid())
    sudo_password = read_sadmin_sudo_password(ctx, uid)
    existing, existing_values = read_trusted_existing_docker_env_values(ctx, env_path, uid=uid)
    updates = docker_hosting_env_updates(ctx, mode, existing_values, sudo_password)
    merged_values = {**existing_values, **updates}
    if not updates:
        return merged_values
    try:
        secure_write(env_path, merge_env_text(existing, updates), 0o600)
    except ValueError as error:
        raise Blocked("Docker Hosting Stack .env update contained a value that cannot be represented safely.") from error
    if not ctx.dry_run:
        ctx.runner.run(["chown", "sadmin:sadmin", f"{DOCKER_HOSTING_REPO}/.env"])
    return merged_values


def docker_hosting_validation_failure_message(mode: str, validation: CommandResult) -> str:
    output = f"{validation.stdout}\n{validation.stderr}".lower()
    if "sudo_password" in output or "passwordless sudo" in output:
        return (
            "Docker Hosting Stack validation failed because the protected hosting-stack .env did not provide a usable sudo credential. "
            "server-bootstrap hydrates SUDO_PASSWORD from /home/sadmin/.env; verify both protected .env files are regular files, "
            "owned by sadmin, mode 0600, and resume with `sudo lsm-vps-init resume`."
        )
    if mode == "n8n" and ("cloudflare" in output or "cf_account_id" in output or "cf_api_token" in output):
        return (
            "Docker Hosting Stack n8n validation failed after bootstrap collected required values. "
            "Check Cloudflare account ID/token permissions and N8N_HOSTNAME DNS readiness, then resume with `sudo lsm-vps-init resume`."
        )
    return "Docker Hosting Stack .env validation failed. Review the repo validator output, fix configuration, then resume with `sudo lsm-vps-init resume`."


def run_docker_hosting_stack(ctx: Context) -> StageResult:
    if not ctx.state.get("selected_modules", {}).get(DOCKER_MODULE):
        return StageResult("completed", "Docker hosting stack module was not selected.")
    ctx.require_root()
    stage_intro(ctx, "docker_hosting_stack")
    if ctx.dry_run:
        return StageResult(
            "completed",
            "Would clone Docker Hosting Stack and run repo-owned audit/validation/dry-run workflows.",
            {"handoff": "LoudSkyMedia/docker-hosting-stack"},
        )
    mode = resolve_docker_hosting_mode(ctx, prompt=True)
    validation_mode = docker_hosting_validator_mode(mode)
    reconcile_legacy_final_firewall(ctx, mode)
    clone_script = (
        "if [ -d /home/sadmin/docker-hosting-stack/.git ]; then "
        "cd /home/sadmin/docker-hosting-stack && git pull --ff-only; "
        "else gh repo clone LoudSkyMedia/docker-hosting-stack /home/sadmin/docker-hosting-stack; fi"
    )
    ctx.sadmin_shell(clone_script, timeout=300)
    ctx.sadmin_shell("cd /home/sadmin/docker-hosting-stack && test -f .env || install -m 0600 .env.example .env")
    repo_path = ctx.layout.sadmin_home / "docker-hosting-stack"
    docker_env_values = ensure_docker_hosting_env(ctx, repo_path, mode)
    redactions = [docker_env_values[key] for key in DOCKER_HOSTING_SECRET_ENV_KEYS if docker_env_values.get(key)]
    ctx.sadmin_shell(
        "cd /home/sadmin/docker-hosting-stack && scripts/audit_host_baseline.sh --output docs/instances/bootstrap/audits/host-baseline-$(date -u +%F).md",
        timeout=180,
        redact_values=redactions,
    )
    validation = ctx.sadmin_shell(
        f"cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode {shlex.quote(validation_mode)}",
        check=False,
        timeout=180,
        redact_values=redactions,
    )
    if validation.returncode != 0:
        raise Blocked(docker_hosting_validation_failure_message(mode, validation))
    if mode == "n8n":
        ctx.sadmin_shell("cd /home/sadmin/docker-hosting-stack && scripts/install_n8n.sh --dry-run", timeout=180, redact_values=redactions)
    else:
        ctx.sadmin_shell("cd /home/sadmin/docker-hosting-stack && scripts/bootstrap_layout.sh --dry-run", timeout=180, redact_values=redactions)
    return StageResult("completed", f"Docker Hosting Stack handoff dry-run completed for mode: {mode}.", {"docker_hosting_mode": mode, "validator_mode": validation_mode})


STAGES: list[StageDefinition] = [
    StageDefinition(0, "bootstrap_installation", "Bootstrap installation", detect_bootstrap, run_bootstrap),
    StageDefinition(1, "system_update", "System update", detect_system_update, run_system_update),
    StageDefinition(2, "root_password", "Reset root password", detect_root_password, run_root_password),
    StageDefinition(3, "sadmin_user", "Create sadmin", detect_sadmin, run_sadmin),
    StageDefinition(4, "sadmin_ssh_key", "Install sadmin SSH public key", detect_sadmin_ssh_key, run_sadmin_ssh_key),
    StageDefinition(5, "ssh_dual_port", "Add SSH port 65500 while preserving 22", detect_ssh_dual_port, run_ssh_dual_port, ("final_host_hardening",)),
    StageDefinition(6, "firewall_phase_a", "Enable UFW with both SSH ports", detect_firewall_phase_a, run_firewall_phase_a, ("final_host_hardening",)),
    StageDefinition(7, "ssh_recovery_checkpoint", "Verify new SSH recovery path", detect_ssh_recovery, run_ssh_recovery),
    StageDefinition(8, "management_tooling", "Install management tooling", detect_management_tooling, run_management_tooling),
    StageDefinition(9, "github_auth", "Authenticate GitHub as sadmin", detect_github_auth, run_github_auth),
    StageDefinition(10, "codex_install_auth", "Install and authenticate Codex", detect_codex_install_auth, run_codex_install_auth),
    StageDefinition(11, "codex_manager_session", "Initialize VPS Server Manager Codex session", detect_codex_manager_session, run_codex_manager_session),
    StageDefinition(12, "repository_selection", "Select repository modules", detect_repository_selection, run_repository_selection),
    StageDefinition(13, "discord_relay_install", "Install Codex VPS Discord Relay", detect_discord_relay_install, run_discord_relay_install),
    StageDefinition(14, "discord_relay_checkpoint", "Verify Discord relay round trip", detect_discord_relay_checkpoint, run_discord_relay_checkpoint),
    StageDefinition(15, "final_host_hardening", "Final host hardening", detect_final_host_hardening, run_final_host_hardening),
    StageDefinition(16, "docker_hosting_stack", "Docker Hosting Stack handoff", detect_docker_hosting_stack, run_docker_hosting_stack),
]


def stage_by_slug(slug: str) -> StageDefinition:
    for stage in STAGES:
        if stage.slug == slug or str(stage.index) == slug:
            return stage
    raise KeyError(slug)
