from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import shlex
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .state import mark_reboot_pending, select_module, set_checkpoint, set_fact, set_stage, utc_now
from .util import (
    CommandError,
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


def firewall_ports_for_modules(modules: dict[str, bool]) -> list[str]:
    ports = [f"{SSH_PORT}/tcp"]
    if modules.get(DOCKER_MODULE):
        ports.extend(["80/tcp", "443/tcp"])
    return ports


def render_ufw_phase_a_plan(current_ssh_port: str | None = None) -> list[str]:
    ports = ["22/tcp", f"{SSH_PORT}/tcp"]
    if current_ssh_port and f"{current_ssh_port}/tcp" not in ports:
        raise Blocked(f"Current SSH session port {current_ssh_port} is not in the Phase A firewall allowlist.")
    return ports


def ufw_status_allows(status_text: str, port: str) -> bool:
    return bool(re.search(rf"(?m)^\s*{re.escape(port)}\s+ALLOW\b", status_text))


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
    return StageResult("completed", "sadmin authorized_keys contains a validated public key.")


def _effective_ssh_ports(ctx: Context) -> set[str]:
    if ctx.layout.mock_root and ctx.layout.ssh_dropin.exists():
        return set(re.findall(r"(?mi)^Port\s+(\d+)\s*$", ctx.layout.ssh_dropin.read_text(encoding="utf-8")))
    result = ctx.runner.run(["sshd", "-T"], check=False)
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


def sshd_effective_for_sadmin(ctx: Context) -> str:
    return ctx.runner.run(["sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA]).stdout


def ssh_listener_present(ctx: Context, port: str) -> bool:
    if ctx.dry_run and ctx.layout.mock_root:
        return port in _effective_ssh_ports(ctx)
    result = ctx.runner.run(["ss", "-tln"], check=False)
    return f":{port} " in result.stdout or f":{port}\n" in result.stdout


def run_ssh_dual_port(ctx: Context) -> StageResult:
    ctx.require_root()
    plan = render_ssh_dropin("dual-port")
    if ctx.dry_run and not ctx.layout.mock_root:
        ctx.runner.log("DRY-RUN: would render SSH dual-port drop-in")
        return StageResult("completed", "Would configure SSH to listen on ports 22 and 65500.", {"ports": ["22", SSH_PORT]})
    if not ctx.dry_run:
        backup_ssh_config(ctx)
        ctx.runner.run(["sshd", "-t"])
    secure_write(ctx.layout.ssh_dropin, plan, 0o644)
    if not ctx.dry_run:
        ctx.runner.run(["sshd", "-t"])
        ctx.runner.run(["sshd", "-T"])
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
    return result.returncode == 0 and "Status: active" in text and ufw_status_allows(text, "22/tcp") and ufw_status_allows(text, f"{SSH_PORT}/tcp")


def run_firewall_phase_a(ctx: Context) -> StageResult:
    ctx.require_root()
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
        status = ctx.runner.run(["ufw", "status", "verbose"], check=False).stdout
        for port in ports:
            if not ufw_status_allows(status, port):
                raise Failed(f"UFW Phase A did not show required allow rule before enable: {port}")
        ctx.runner.run(["ufw", "--force", "enable"])
        enabled = ctx.runner.run(["ufw", "status", "verbose"]).stdout
        for port in ports:
            if not ufw_status_allows(enabled, port):
                raise Failed(f"UFW Phase A did not retain required allow rule after enable: {port}")
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
    if ctx.state.get("selected_modules", {}).get(RELAY_MODULE):
        if not ctx.state.get("checkpoints", {}).get("relay_round_trip_verified"):
            issues.append("Discord/Codex relay round trip is not verified")
        if ctx.state.get("stages", {}).get("discord_relay_install", {}).get("status") != "completed":
            issues.append("Discord relay install stage is not completed")
        elif not ctx.dry_run and not detect_discord_relay_install(ctx):
            issues.append("Discord relay service/preflight is not currently healthy")
    if not ctx.dry_run and not detect_firewall_phase_a(ctx):
        issues.append("UFW Phase A is not currently active with both 22/tcp and 65500/tcp allowed")
    if not ctx.dry_run:
        docker_available = ctx.runner.run(["bash", "-lc", "command -v docker >/dev/null"], check=False).returncode == 0
        if docker_available:
            result = ctx.runner.run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"], check=False)
            if result.returncode == 0:
                published = parse_docker_published_ports(result.stdout)
                allowed = {80, 443} if ctx.state.get("selected_modules", {}).get(DOCKER_MODULE) else set()
                unexpected = published - allowed
                if unexpected:
                    issues.append(f"Docker has unexpected host-published public port(s): {', '.join(str(port) for port in sorted(unexpected))}")
            else:
                issues.append("Docker is installed but published-port inspection failed")
    if issues:
        raise Blocked("Refusing final hardening until current conditions are fixed: " + "; ".join(issues))


def detect_ssh_recovery(ctx: Context) -> bool:
    return bool(ctx.state.get("checkpoints", {}).get("ssh_recovery_verified"))


def run_ssh_recovery(ctx: Context) -> StageResult:
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
        f"ssh -tt -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no "
        f"-o PreferredAuthentications=publickey -p {SSH_PORT} "
        f"sadmin@{ip} {shlex.quote(remote_command)}"
    )
    message = (
        "Hard checkpoint: open a second terminal and prove key-based SSH recovery before continuing.\n"
        f"Run: {command}"
    )
    if ctx.dry_run:
        raise Blocked(message)
    raise Blocked(message)


def detect_management_tooling(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "management_tooling")
    checks = [
        "curl",
        "ca-certificates",
        "git",
        "gh",
        "jq",
        "openssl",
        "python3",
        "node",
        "npm",
        "tmux",
    ]
    script = "for c in " + " ".join(shlex.quote(c) for c in checks) + "; do command -v \"$c\" >/dev/null || exit 1; done"
    result = ctx.runner.run(["bash", "-lc", script], check=False)
    if result.returncode != 0:
        return False
    node_version = ctx.runner.run(["node", "-e", "console.log(process.versions.node.split('.')[0])"], check=False)
    return node_version.returncode == 0 and int(node_version.stdout.strip() or "0") >= 20


def run_management_tooling(ctx: Context) -> StageResult:
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


def detect_github_auth(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "github_auth")
    status = ctx.sadmin_shell("gh auth status", check=False)
    if status.returncode != 0:
        return False
    for repo in ("LoudSkyMedia/codex-vps-discord-relay", "LoudSkyMedia/docker-hosting-stack"):
        result = ctx.sadmin_shell(f"gh repo view {shlex.quote(repo)} --json nameWithOwner >/dev/null", check=False)
        if result.returncode != 0:
            return False
    return True


def run_github_auth(ctx: Context) -> StageResult:
    ctx.require_root()
    if ctx.dry_run:
        return StageResult("completed", "Would authenticate GitHub CLI as sadmin and verify private repo access.", {"dry_run": True})
    if ctx.sadmin_shell("gh auth status", check=False).returncode != 0:
        ctx.require_tty("GitHub authentication")
        if ctx.confirm("Use headless PAT/token login instead of interactive gh auth login?", default=False):
            token = ctx.prompt_secret("GitHub PAT/token", confirm=False)
            ctx.sadmin_shell("gh auth login --with-token", input_text=token + "\n", secret_stdin=True)
        else:
            ctx.sadmin_shell("gh auth login --hostname github.com --git-protocol https")
    ctx.sadmin_shell("gh auth setup-git")
    for repo in ("LoudSkyMedia/codex-vps-discord-relay", "LoudSkyMedia/docker-hosting-stack"):
        ctx.sadmin_shell(f"gh repo view {shlex.quote(repo)} --json nameWithOwner >/dev/null")
    return StageResult("completed", "GitHub CLI is authenticated as sadmin and can access required repositories.")


def detect_codex_install_auth(ctx: Context) -> bool:
    if ctx.dry_run:
        return detected_stage_by_state(ctx, "codex_install_auth")
    script = (
        "command -v codex >/dev/null && "
        "codex login status >/dev/null && "
        "codex --help | grep -q -- '--dangerously-bypass-approvals-and-sandbox' && "
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
    if not ctx.dry_run:
        if ctx.sadmin_shell("command -v codex >/dev/null", check=False).returncode != 0:
            ctx.sadmin_shell(
                "curl -fsSL https://chatgpt.com/codex/install.sh -o /tmp/openai-codex-install.sh "
                "&& sh /tmp/openai-codex-install.sh"
            )
        if ctx.sadmin_shell("codex login status", check=False).returncode != 0:
            ctx.require_tty("Codex authentication")
            ctx.sadmin_shell("codex login")
        help_result = ctx.sadmin_shell("codex --help", check=False)
        if "--dangerously-bypass-approvals-and-sandbox" not in help_result.stdout:
            raise Blocked("Installed Codex CLI does not expose --dangerously-bypass-approvals-and-sandbox. Stop and review Codex version.")
        models = ctx.sadmin_shell("codex debug models", check=False, timeout=30)
        if models.returncode == 0 and REQUIRED_CODEX_MODEL not in models.stdout:
            raise Blocked(f"Codex model catalog does not list {REQUIRED_CODEX_MODEL}; do not downgrade silently.")
    _write_codex_config(ctx)
    return StageResult("completed", f"Codex is installed/authenticated as sadmin and configured for {REQUIRED_CODEX_MODEL} {REQUIRED_CODEX_REASONING}.")


def detect_codex_manager_session(ctx: Context) -> bool:
    session_id = ctx.state.get("facts", {}).get("codex_session_id")
    return bool(session_id and re.fullmatch(r"[0-9a-f-]{36}", session_id, re.I))


def run_codex_manager_session(ctx: Context) -> StageResult:
    ctx.require_root()
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
    return RELAY_MODULE in modules and DOCKER_MODULE in modules


def run_repository_selection(ctx: Context) -> StageResult:
    env_modules = os.environ.get("LSM_VPS_INIT_MODULES", "").strip()
    if env_modules:
        selected = {item.strip() for item in env_modules.split(",") if item.strip()}
        select_module(ctx.state, RELAY_MODULE, RELAY_MODULE in selected or "relay" in selected)
        select_module(ctx.state, DOCKER_MODULE, DOCKER_MODULE in selected or "docker" in selected or "hosting" in selected)
    elif ctx.dry_run:
        select_module(ctx.state, RELAY_MODULE, True)
        select_module(ctx.state, DOCKER_MODULE, False)
    else:
        relay = ctx.confirm("Install and verify Codex VPS Discord Relay? Strongly recommended.", default=True)
        docker = ctx.confirm("Install Docker Hosting Stack module now?", default=False)
        select_module(ctx.state, RELAY_MODULE, relay)
        select_module(ctx.state, DOCKER_MODULE, docker)
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
        env_values = relay_env_values_from_text(env_path.read_text(encoding="utf-8", errors="replace"), RELAY_CONTRACT_KEYS)
        validate_relay_env_policy(env_values)
        validate_relay_codex_contract(env_values, config_path.read_text(encoding="utf-8", errors="replace"))
    except (Blocked, ValueError):
        return False
    return ctx.sadmin_shell(
        "test -d /home/sadmin/codex-vps-discord-relay/.git "
        "&& cd /home/sadmin/codex-vps-discord-relay "
        "&& npm run preflight >/dev/null "
        "&& systemctl --user is-active --quiet codex-vps-discord-relay.service",
        check=False,
        timeout=120,
    ).returncode == 0


def _relay_env_updates(ctx: Context) -> dict[str, str]:
    session_id = ctx.state.get("facts", {}).get("codex_session_id", "")
    defaults = {
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
    updates = dict(defaults)
    updates["DISCORD_BOT_TOKEN"] = ctx.prompt_secret("Discord bot token", confirm=False)
    updates["DISCORD_GUILD_ID"] = ctx.prompt_text("Discord server/guild ID")
    updates["CODEX_VPS_DEFAULT_CHANNEL_ID"] = ctx.prompt_text("Discord channel ID for the VPS session")
    updates["CODEX_VPS_DEFAULT_SESSION_ID"] = ctx.prompt_text("Codex VPS default session ID", default=session_id)
    updates["CODEX_VPS_ALLOWED_USER_IDS"] = ctx.prompt_text("Comma-separated allowed Discord user IDs")
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


def run_discord_relay_install(ctx: Context) -> StageResult:
    if not ctx.state.get("selected_modules", {}).get(RELAY_MODULE):
        return StageResult("completed", "Discord relay module was not selected.")
    ctx.require_root()
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
    existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    updates = _relay_env_updates(ctx)
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
        ctx.sadmin_shell("cd /home/sadmin/codex-vps-discord-relay && chmod +x bin/*.sh bin/preflight.js bin/codex-vps-relay hooks/codex_vps_notify.py")
        ctx.sadmin_shell("cd /home/sadmin/codex-vps-discord-relay && bin/install-service.sh", timeout=1800)
        ctx.sadmin_shell("cd /home/sadmin/codex-vps-discord-relay && bin/install-hook.sh", timeout=300)
        ctx.runner.run(["loginctl", "enable-linger", "sadmin"])
        ctx.sadmin_shell("cd /home/sadmin/codex-vps-discord-relay && npm run preflight", timeout=300)
        verify_codex_config_defaults(ctx)
        ctx.sadmin_shell("systemctl --user is-active --quiet codex-vps-discord-relay.service")
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
    result = ctx.runner.run(["sshd", "-T"], check=False)
    text = result.stdout
    ports = set(re.findall(r"(?mi)^port\s+(\d+)\s*$", text))
    sadmin_effective = ctx.runner.run(["sshd", "-T", "-C", SSHD_SADMIN_MATCH_CRITERIA], check=False).stdout
    return (
        SSH_PORT in ports
        and "22" not in ports
        and re.search(r"(?mi)^permitrootlogin\s+no$", text)
        and re.search(r"(?mi)^passwordauthentication\s+no$", text)
        and not re.search(r"(?mi)^exposeauthinfo\s+yes$", sadmin_effective)
        and ctx.runner.run(["ufw", "status"], check=False).stdout.lower().find("active") >= 0
    )


def run_final_host_hardening(ctx: Context) -> StageResult:
    ctx.require_root()
    if ctx.dry_run and not ctx.layout.mock_root:
        if not ctx.state.get("checkpoints", {}).get("ssh_recovery_verified"):
            raise Blocked("Refusing hardening: sadmin SSH recovery on port 65500 is not verified.")
        if ctx.state.get("selected_modules", {}).get(RELAY_MODULE) and not ctx.state.get("checkpoints", {}).get("relay_round_trip_verified"):
            raise Blocked("Refusing hardening: Discord/Codex relay round trip is not verified.")
    else:
        revalidate_before_final_hardening(ctx)
    ports = firewall_ports_for_modules(ctx.state.get("selected_modules", {}))
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
        ctx.runner.run(["sshd", "-t"])
        ctx.runner.run(["sshd", "-T"])
        sshd_effective_for_sadmin(ctx)
    secure_write(ctx.layout.ssh_dropin, render_ssh_dropin("hardened"), 0o644)
    if not ctx.dry_run:
        ctx.runner.run(["sshd", "-t"])
        ctx.runner.run(["sshd", "-T"])
        hardened_sadmin = sshd_effective_for_sadmin(ctx)
        if re.search(r"(?mi)^exposeauthinfo\s+yes$", hardened_sadmin):
            raise Failed("OpenSSH ExposeAuthInfo remained enabled for sadmin after final hardening.")
        reload_ssh(ctx)
        hardened_after_reload = sshd_effective_for_sadmin(ctx)
        if re.search(r"(?mi)^exposeauthinfo\s+yes$", hardened_after_reload):
            raise Failed("OpenSSH ExposeAuthInfo remained enabled for sadmin after SSH reload.")
        ctx.runner.run(["apt-get", "install", "-y", "ufw", "fail2ban", "unattended-upgrades"])
        ctx.runner.run(["ufw", "default", "deny", "incoming"])
        ctx.runner.run(["ufw", "default", "allow", "outgoing"])
        for port in ports:
            ctx.runner.run(["ufw", "allow", port])
        for _ in range(3):
            status = ctx.runner.run(["ufw", "status", "verbose"], check=False).stdout
            if not ufw_status_allows(status, "22/tcp"):
                break
            ctx.runner.run(["ufw", "delete", "allow", "22/tcp"], check=False)
        ctx.runner.run(["ufw", "--force", "enable"])
        status = ctx.runner.run(["ufw", "status", "verbose"]).stdout
        if ufw_status_allows(status, "22/tcp"):
            raise Failed("UFW still allows 22/tcp after Phase B hardening.")
        for port in ports:
            if not ufw_status_allows(status, port):
                raise Failed(f"UFW is missing required Phase B allow rule: {port}")
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
    return Path("/home/sadmin/docker-hosting-stack/.git").exists()


def run_docker_hosting_stack(ctx: Context) -> StageResult:
    if not ctx.state.get("selected_modules", {}).get(DOCKER_MODULE):
        return StageResult("completed", "Docker hosting stack module was not selected.")
    ctx.require_root()
    if ctx.dry_run:
        return StageResult(
            "completed",
            "Would clone Docker Hosting Stack and run repo-owned audit/validation/dry-run workflows.",
            {"handoff": "LoudSkyMedia/docker-hosting-stack"},
        )
    mode = ctx.prompt_text(
        "Docker hosting capability mode (base, standalone-app, n8n, website-migration)",
        default="base",
    )
    if mode not in {"base", "standalone-app", "n8n", "website-migration"}:
        raise Blocked("Unsupported Docker hosting capability mode.")
    clone_script = (
        "if [ -d /home/sadmin/docker-hosting-stack/.git ]; then "
        "cd /home/sadmin/docker-hosting-stack && git pull --ff-only; "
        "else gh repo clone LoudSkyMedia/docker-hosting-stack /home/sadmin/docker-hosting-stack; fi"
    )
    ctx.sadmin_shell(clone_script, timeout=300)
    ctx.sadmin_shell("cd /home/sadmin/docker-hosting-stack && test -f .env || install -m 0600 .env.example .env")
    ctx.sadmin_shell("cd /home/sadmin/docker-hosting-stack && scripts/audit_host_baseline.sh --output docs/instances/bootstrap/audits/host-baseline-$(date -u +%F).md", timeout=180)
    validation_mode = "n8n" if mode == "n8n" else "base"
    validation = ctx.sadmin_shell(f"cd /home/sadmin/docker-hosting-stack && scripts/validate_env.sh --mode {validation_mode}", check=False, timeout=180)
    if validation.returncode != 0:
        raise Blocked("Docker Hosting Stack .env validation is not complete. Fill /home/sadmin/docker-hosting-stack/.env and resume.")
    if mode == "n8n":
        ctx.sadmin_shell("cd /home/sadmin/docker-hosting-stack && scripts/install_n8n.sh --dry-run", timeout=180)
    else:
        ctx.sadmin_shell("cd /home/sadmin/docker-hosting-stack && scripts/bootstrap_layout.sh --dry-run", timeout=180)
    return StageResult("completed", f"Docker Hosting Stack handoff dry-run completed for mode: {mode}.")


STAGES: list[StageDefinition] = [
    StageDefinition(0, "bootstrap_installation", "Bootstrap installation", detect_bootstrap, run_bootstrap),
    StageDefinition(1, "system_update", "System update", detect_system_update, run_system_update),
    StageDefinition(2, "root_password", "Reset root password", detect_root_password, run_root_password),
    StageDefinition(3, "sadmin_user", "Create sadmin", detect_sadmin, run_sadmin),
    StageDefinition(4, "sadmin_ssh_key", "Install sadmin SSH public key", detect_sadmin_ssh_key, run_sadmin_ssh_key),
    StageDefinition(5, "ssh_dual_port", "Add SSH port 65500 while preserving 22", detect_ssh_dual_port, run_ssh_dual_port),
    StageDefinition(6, "firewall_phase_a", "Enable UFW with both SSH ports", detect_firewall_phase_a, run_firewall_phase_a),
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
