from __future__ import annotations

import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_STATE_DIR = Path("/var/lib/lsm-vps-init")
DEFAULT_LOG_FILE = Path("/var/log/lsm-vps-init/bootstrap.log")
DEFAULT_INSTALL_ROOT = Path("/usr/local/lib/lsm-vps-init")
DEFAULT_BIN_PATH = Path("/usr/local/sbin/lsm-vps-init")
SADMIN_USER = "sadmin"
SADMIN_HOME = Path("/home/sadmin")
LOCAL_ENV_ALLOWED_KEYS = {
    "N8N1_VPS_IPV4",
    "N8N1_VPS_IPV6",
    "N8N1_VPS_USERNAME",
    "N8N1_VPS_SUDO_PASSWORD",
    "N8N1_VPS_SSH_KEY",
    "VPS_SSH_HOST",
    "VPS_SSH_IDENTITY_FILE",
    "SUDO_PASSWORD",
}


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult):
        super().__init__(f"command failed with {result.returncode}: {redacted_command(result.args)}")
        self.result = result


class LocalEnvConflict(ValueError):
    pass


class PathLayout:
    def __init__(
        self,
        mock_root: Path | None = None,
        state_dir: Path | None = None,
        log_file: Path | None = None,
        install_root: Path = DEFAULT_INSTALL_ROOT,
        bin_path: Path = DEFAULT_BIN_PATH,
    ):
        self.mock_root = mock_root.resolve() if mock_root else None
        self.state_dir = state_dir or self.map(DEFAULT_STATE_DIR)
        self.state_file = self.state_dir / "state.json"
        self.log_file = log_file or (self.state_dir / "bootstrap.log" if state_dir else self.map(DEFAULT_LOG_FILE))
        self.install_root = self.map(install_root)
        self.bin_path = self.map(bin_path)

    def map(self, path: Path | str) -> Path:
        candidate = Path(path)
        if self.mock_root and candidate.is_absolute():
            return self.mock_root / str(candidate).lstrip("/")
        return candidate

    @property
    def os_release(self) -> Path:
        return self.map("/etc/os-release")

    @property
    def ssh_dropin(self) -> Path:
        return self.map("/etc/ssh/sshd_config.d/00-lsm-vps-init.conf")

    @property
    def legacy_ssh_dropin(self) -> Path:
        return self.map("/etc/ssh/sshd_config.d/99-lsm-vps-init.conf")

    @property
    def motd_file(self) -> Path:
        return self.map("/etc/update-motd.d/99-lsm-vps-init")

    @property
    def sadmin_home(self) -> Path:
        return self.map(SADMIN_HOME)

    @property
    def sadmin_env(self) -> Path:
        return self.sadmin_home / ".env"

    @property
    def authorized_keys(self) -> Path:
        return self.sadmin_home / ".ssh" / "authorized_keys"

    @property
    def reboot_required(self) -> Path:
        return self.map("/var/run/reboot-required")


def redacted_command(args: Iterable[str]) -> str:
    return " ".join(shlex.quote(str(arg)) for arg in args)


def sanitize_output(value: str, limit: int = 4000) -> str:
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    return text[:limit]


def redact_specific_values(text: str, values: Iterable[str] | None) -> str:
    redacted = text
    for value in values or []:
        if value:
            redacted = redacted.replace(value, "[REDACTED]")
    return redacted


def parse_allowed_local_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key not in LOCAL_ENV_ALLOWED_KEYS:
            continue
        value = parse_env_value(text, key)
        values[key] = value or ""
    return values


def validate_local_env_contract(values: dict[str, str]) -> None:
    canonical_password = values.get("N8N1_VPS_SUDO_PASSWORD")
    fallback_password = values.get("SUDO_PASSWORD")
    if canonical_password and fallback_password and canonical_password != fallback_password:
        raise LocalEnvConflict("N8N1_VPS_SUDO_PASSWORD differs from SUDO_PASSWORD")
    canonical_key = values.get("N8N1_VPS_SSH_KEY")
    fallback_key = values.get("VPS_SSH_IDENTITY_FILE")
    if canonical_key and fallback_key and os.path.expanduser(canonical_key) != os.path.expanduser(fallback_key):
        raise LocalEnvConflict("N8N1_VPS_SSH_KEY differs from VPS_SSH_IDENTITY_FILE")


class CommandRunner:
    def __init__(self, log_file: Path, dry_run: bool = False):
        self.log_file = log_file
        self.dry_run = dry_run
        self.log_file.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        try:
            os.chmod(self.log_file.parent, 0o700)
        except PermissionError:
            pass

    def log(self, message: str) -> None:
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(f"{message}\n")
        try:
            os.chmod(self.log_file, 0o600)
        except PermissionError:
            pass

    def run(
        self,
        args: list[str],
        *,
        input_text: str | None = None,
        check: bool = True,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
        secret_stdin: bool = False,
        redact_values: Iterable[str] | None = None,
    ) -> CommandResult:
        self.log(f"$ {redacted_command(args)}")
        if input_text is not None:
            self.log("<stdin: redacted>" if secret_stdin else f"<stdin: {len(input_text)} bytes>")
        if self.dry_run:
            return CommandResult(args=args, returncode=0, stdout="", stderr="")
        try:
            completed = subprocess.run(
                args,
                input=input_text,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                env=env,
                cwd=str(cwd) if cwd else None,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout if isinstance(error.stdout, str) else ""
            stderr = error.stderr if isinstance(error.stderr, str) else ""
            result = CommandResult(
                args=args,
                returncode=124,
                stdout=redact_specific_values(sanitize_output(stdout), redact_values),
                stderr=redact_specific_values(sanitize_output((stderr + "\ncommand timed out").strip()), redact_values),
            )
            if result.stdout:
                self.log(result.stdout.rstrip())
            if result.stderr:
                self.log(result.stderr.rstrip())
            if check:
                raise CommandError(result)
            return result
        result = CommandResult(
            args=args,
            returncode=completed.returncode,
            stdout=redact_specific_values(sanitize_output(completed.stdout), redact_values),
            stderr=redact_specific_values(sanitize_output(completed.stderr), redact_values),
        )
        if result.stdout:
            self.log(result.stdout.rstrip())
        if result.stderr:
            self.log(result.stderr.rstrip())
        if check and result.returncode != 0:
            raise CommandError(result)
        return result

    def run_interactive(
        self,
        args: list[str],
        *,
        check: bool = True,
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        cwd: Path | None = None,
    ) -> CommandResult:
        self.log(f"$ {redacted_command(args)}")
        if self.dry_run:
            return CommandResult(args=args, returncode=0, stdout="", stderr="")
        try:
            completed = subprocess.run(
                args,
                text=True,
                check=False,
                timeout=timeout,
                env=env,
                cwd=str(cwd) if cwd else None,
            )
        except subprocess.TimeoutExpired:
            result = CommandResult(args=args, returncode=124, stdout="", stderr="command timed out")
            self.log(result.stderr)
            if check:
                raise CommandError(result)
            return result
        result = CommandResult(args=args, returncode=completed.returncode, stdout="", stderr="")
        if check and result.returncode != 0:
            raise CommandError(result)
        return result


def read_os_release(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        values[key] = raw_value.strip().strip('"')
    return values


def is_ubuntu_2404(path: Path) -> bool:
    values = read_os_release(path)
    return values.get("ID") == "ubuntu" and values.get("VERSION_ID") == "24.04"


def user_exists(username: str, passwd_file: Path | None = None) -> bool:
    if passwd_file and passwd_file.exists():
        prefix = f"{username}:"
        return any(line.startswith(prefix) for line in passwd_file.read_text(encoding="utf-8").splitlines())
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def shell_quote_env_value(value: str) -> str:
    if "\x00" in value:
        raise ValueError("environment values must not contain NUL bytes")
    if "\n" in value or "\r" in value:
        raise ValueError("environment values must be single-line")
    return shlex.quote(value)


def parse_env_lines(text: str) -> tuple[list[str], dict[str, int]]:
    lines = text.splitlines()
    positions: dict[str, int] = {}
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key = stripped.split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            positions[key] = index
    return lines, positions


def merge_env_text(existing: str, updates: dict[str, str]) -> str:
    lines, positions = parse_env_lines(existing)
    for key, value in updates.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError(f"invalid env key: {key}")
        rendered = f"{key}={shell_quote_env_value(value)}"
        if key in positions:
            lines[positions[key]] = rendered
        else:
            lines.append(rendered)
    return "\n".join(lines).rstrip() + "\n"


def parse_env_value(text: str, key: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        raise ValueError(f"invalid env key: {key}")
    prefix = f"{key}="
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or not stripped.startswith(prefix):
            continue
        try:
            tokens = shlex.split(stripped, comments=True, posix=True)
        except ValueError as error:
            raise ValueError(f"invalid env assignment for {key}") from error
        if len(tokens) != 1 or not tokens[0].startswith(prefix):
            raise ValueError(f"invalid env assignment for {key}")
        return tokens[0][len(prefix):]
    return None


def secure_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    os.chmod(path, mode)


def file_mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def public_ipv4(runner: CommandRunner) -> str | None:
    commands = [
        ["curl", "-fsS4", "https://ifconfig.me"],
        ["curl", "-fsS4", "https://api.ipify.org"],
    ]
    for args in commands:
        result = runner.run(args, check=False, timeout=10)
        candidate = result.stdout.strip()
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", candidate):
            return candidate
    return None


def ensure_owner_mode(path: Path, owner: str, group: str, mode: int, runner: CommandRunner) -> None:
    runner.run(["chown", f"{owner}:{group}", str(path)])
    os.chmod(path, mode)


def append_unique_line(existing: str, line: str) -> str:
    normalized = line.strip()
    lines = [item.rstrip("\n") for item in existing.splitlines()]
    if normalized not in [item.strip() for item in lines]:
        lines.append(normalized)
    return "\n".join(lines).rstrip() + "\n"
