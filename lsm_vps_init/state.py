from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATE_SCHEMA_VERSION = 1
STAGE_STATUSES = {"pending", "in_progress", "completed", "blocked", "failed"}
SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "private_key",
    "auth_json",
    "sudo_password",
)


class StateSafetyError(ValueError):
    """Raised when a proposed state payload contains secret-shaped metadata."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def boot_id() -> str | None:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except OSError:
        return None


def default_state() -> dict[str, Any]:
    now = utc_now()
    current_boot_id = boot_id()
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "created_at": now,
        "updated_at": now,
        "last_boot_id": current_boot_id,
        "current_stage": None,
        "stages": {},
        "facts": {},
        "selected_modules": {},
        "checkpoints": {
            "ssh_recovery_verified": False,
            "relay_round_trip_verified": False,
        },
        "revalidation": {
            "boot_changed": False,
            "boot_changed_at": None,
        },
        "reboot": {
            "pending": False,
            "required_since": None,
            "last_seen_boot_id": current_boot_id,
        },
    }


def _secretish_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def assert_public_safe_state(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if path != "$.stages" and _secretish_key(str(key)):
                raise StateSafetyError(f"state key may contain sensitive data: {path}.{key}")
            assert_public_safe_state(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_public_safe_state(item, f"{path}[{index}]")


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.path.parent, 0o700)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            state = default_state()
            self.save(state)
            return state
        with self.path.open("r", encoding="utf-8") as handle:
            state = json.load(handle)
        if state.get("schema_version") != STATE_SCHEMA_VERSION:
            raise ValueError(f"unsupported state schema: {state.get('schema_version')}")
        changed_boot_id = boot_id()
        if changed_boot_id and changed_boot_id != state.get("last_boot_id"):
            state["last_boot_id"] = changed_boot_id
            state.setdefault("reboot", {})["last_seen_boot_id"] = changed_boot_id
            revalidation = state.setdefault("revalidation", {})
            revalidation["boot_changed"] = True
            revalidation["boot_changed_at"] = utc_now()
            state["updated_at"] = utc_now()
            self.save(state)
        return state

    def save(self, state: dict[str, Any]) -> None:
        state["updated_at"] = utc_now()
        assert_public_safe_state(state)
        payload = json.dumps(state, indent=2, sort_keys=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".state.",
            suffix=".json",
            dir=str(self.path.parent),
            text=True,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n")
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
            os.chmod(self.path, 0o600)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def stage_record(state: dict[str, Any], slug: str) -> dict[str, Any]:
    return state.setdefault("stages", {}).setdefault(
        slug,
        {
            "status": "pending",
            "started_at": None,
            "completed_at": None,
            "blocked_reason": None,
            "evidence": {},
        },
    )


def set_stage(
    state: dict[str, Any],
    slug: str,
    status: str,
    message: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> None:
    if status not in STAGE_STATUSES:
        raise ValueError(f"invalid stage status: {status}")
    record = stage_record(state, slug)
    record["status"] = status
    if status == "in_progress" and not record.get("started_at"):
        record["started_at"] = utc_now()
    if status == "completed":
        record["completed_at"] = utc_now()
        record["blocked_reason"] = None
    elif status == "in_progress":
        record["blocked_reason"] = None
    if status in {"blocked", "failed"}:
        record["blocked_reason"] = message or ""
    if evidence:
        record.setdefault("evidence", {}).update(evidence)
    if status == "completed":
        if state.get("current_stage") == slug:
            state["current_stage"] = None
    else:
        state["current_stage"] = slug


def set_fact(state: dict[str, Any], key: str, value: Any) -> None:
    if _secretish_key(key):
        raise StateSafetyError(f"refusing to store sensitive fact key: {key}")
    state.setdefault("facts", {})[key] = value


def set_checkpoint(state: dict[str, Any], key: str, value: bool = True) -> None:
    if _secretish_key(key):
        raise StateSafetyError(f"refusing to store sensitive checkpoint key: {key}")
    state.setdefault("checkpoints", {})[key] = bool(value)


def select_module(state: dict[str, Any], module: str, selected: bool) -> None:
    state.setdefault("selected_modules", {})[module] = bool(selected)


def mark_reboot_pending(state: dict[str, Any], pending: bool) -> None:
    reboot = state.setdefault("reboot", {})
    reboot["pending"] = bool(pending)
    if pending and not reboot.get("required_since"):
        reboot["required_since"] = utc_now()
    if not pending:
        reboot["required_since"] = None
