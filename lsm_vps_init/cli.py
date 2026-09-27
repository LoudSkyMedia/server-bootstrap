from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .state import StateStore, mark_reboot_pending, set_checkpoint, set_stage
from .stages import (
    Blocked,
    Context,
    Failed,
    STAGES,
    record_ssh_checkpoint_proof,
    ssh_checkpoint_proof_from_env,
    stage_by_slug,
)
from .util import CommandError, CommandRunner, PathLayout


def state_stage_status(ctx: Context, slug: str) -> str:
    return str(ctx.state.get("stages", {}).get(slug, {}).get("status", "pending"))


def stage_completed_in_state(ctx: Context, slug: str) -> bool:
    return state_stage_status(ctx, slug) == "completed"


def stage_superseded(ctx: Context, stage) -> bool:
    predicate = getattr(stage, "superseded_when", None)
    if predicate is not None:
        try:
            if predicate(ctx):
                return True
        except (Blocked, Failed, CommandError):
            pass
    return stage_completed_in_state(ctx, stage.slug) and any(stage_completed_in_state(ctx, slug) for slug in stage.superseded_by)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lsm-vps-init")
    parser.add_argument("command", nargs="?", default="resume", choices=["resume", "run", "status", "verify-ssh", "record-ssh-proof", "confirm-relay"])
    parser.add_argument("--state-dir", type=Path, default=None, help="Override persistent state directory.")
    parser.add_argument("--log-file", type=Path, default=None, help="Override log file path.")
    parser.add_argument("--mock-root", type=Path, default=None, help="Map absolute system paths under this root for tests.")
    parser.add_argument("--dry-run", action="store_true", help="Plan operations without executing system commands.")
    parser.add_argument("--non-interactive", action="store_true", help="Fail instead of prompting.")
    parser.add_argument("--yes", action="store_true", help="Accept confirmations except hard checkpoint proofs.")
    parser.add_argument("--stage", default=None, help="Run only one stage by slug or index.")
    parser.add_argument("--until", default=None, help="Stop after this stage slug or index.")
    parser.add_argument("--nonce", default=None, help="Nonce for verify-ssh.")
    parser.add_argument("--emit-proof", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Print status as JSON.")
    return parser


def make_context(args: argparse.Namespace) -> tuple[Context, StateStore]:
    layout = PathLayout(mock_root=args.mock_root, state_dir=args.state_dir, log_file=args.log_file)
    store = StateStore(layout.state_file)
    state = store.load()
    sync_reboot_required_marker(state, store, layout)
    runner = CommandRunner(layout.log_file, dry_run=args.dry_run)
    return (
        Context(
            layout=layout,
            state=state,
            runner=runner,
            dry_run=args.dry_run,
            non_interactive=args.non_interactive,
            assume_yes=args.yes,
        ),
        store,
    )


def sync_reboot_required_marker(state: dict[str, object], store: StateStore, layout: PathLayout) -> None:
    actual_pending = layout.reboot_required.exists()
    reboot = state.setdefault("reboot", {})
    if not isinstance(reboot, dict):
        return
    stale_timestamp = not actual_pending and reboot.get("required_since") is not None
    missing_timestamp = actual_pending and not reboot.get("required_since")
    if reboot.get("pending") != actual_pending or stale_timestamp or missing_timestamp:
        mark_reboot_pending(state, actual_pending)
        store.save(state)


def stage_status(ctx: Context) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for stage in STAGES:
        record = ctx.state.get("stages", {}).get(stage.slug, {})
        detector = False
        detect_error = None
        try:
            detector = stage.detect(ctx)
        except Exception as error:  # status must survive local command gaps
            detect_error = str(error)
        superseded = False
        try:
            superseded = stage_superseded(ctx, stage)
        except Exception as error:  # status must survive local command gaps
            detect_error = f"{detect_error}; supersession: {error}" if detect_error else f"supersession: {error}"
        rows.append(
            {
                "index": stage.index,
                "slug": stage.slug,
                "title": stage.title,
                "state_status": record.get("status", "pending"),
                "detected": detector,
                "superseded": superseded,
                "blocked_reason": record.get("blocked_reason"),
                "detect_error": detect_error,
            }
        )
        rows[-1]["satisfied"] = bool(rows[-1]["detected"] or rows[-1]["superseded"])
    return rows


def print_status(ctx: Context, *, as_json: bool = False) -> None:
    rows = stage_status(ctx)
    current = next(
        (
            row
            for row in rows
            if row["state_status"] in {"blocked", "failed", "in_progress"} and not row["superseded"]
            or (row["state_status"] == "pending" and not row["satisfied"])
        ),
        None,
    )
    if current is None:
        current = next((row for row in rows if not row["satisfied"]), None)
    report = {
        "current_stage": current["slug"] if current else None,
        "completed": [row["slug"] for row in rows if row["satisfied"]],
        "pending": [row["slug"] for row in rows if not row["satisfied"] and row["state_status"] == "pending"],
        "blocked": [row for row in rows if row["state_status"] == "blocked" and not row["superseded"]],
        "failed": [row for row in rows if row["state_status"] == "failed" and not row["superseded"]],
        "selected_modules": ctx.state.get("selected_modules", {}),
        "checkpoints": ctx.state.get("checkpoints", {}),
        "reboot": ctx.state.get("reboot", {}),
        "revalidation": ctx.state.get("revalidation", {}),
        "state_file": str(ctx.layout.state_file),
        "log_file": str(ctx.layout.log_file),
    }
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    print("Loud Sky Media VPS initialization status")
    print(f"State: {ctx.layout.state_file}")
    print(f"Log:   {ctx.layout.log_file}")
    print(f"Current stage: {report['current_stage'] or 'complete'}")
    print(f"Reboot pending: {str(report['reboot'].get('pending', False)).lower()}")
    print(f"Boot changed since previous run: {str(report['revalidation'].get('boot_changed', False)).lower()}")
    if report["reboot"].get("pending") and report["current_stage"]:
        print()
        print("Ubuntu requires a reboot.")
        print("Do not reboot yet. Bootstrap is first establishing verified SSH recovery and management access.")
    elif report["reboot"].get("pending") and not report["current_stage"]:
        print()
        print("Initialization is complete, but Ubuntu requires a reboot.")
        print("Reboot: sudo reboot")
        print("Reconnect through the final sadmin SSH path, then verify: sudo lsm-vps-init status")
    print()
    for row in rows:
        marker = "done" if row["satisfied"] else row["state_status"]
        print(f"{row['index']:02d} {row['slug']}: {marker}")
        if row.get("blocked_reason") and not row["superseded"]:
            label = "failed" if row["state_status"] == "failed" else "blocked"
            print(f"    {label}: {row['blocked_reason']}")
        if row.get("detect_error"):
            print(f"    detect note: {row['detect_error']}")


def print_stage_stop_summary(ctx: Context, stage, status: str, reason: str) -> None:
    if status == "blocked":
        print("Bootstrap paused at a required checkpoint.", file=sys.stderr)
        print(file=sys.stderr)
        print(f"Current stage: {stage.slug}", file=sys.stderr)
        print(file=sys.stderr)
        print("Required action:", file=sys.stderr)
        print(f"    {reason}", file=sys.stderr)
    else:
        print("Bootstrap stopped because a stage failed.", file=sys.stderr)
        print(file=sys.stderr)
        print(f"Current stage: {stage.slug}", file=sys.stderr)
        print(file=sys.stderr)
        print("Reason:", file=sys.stderr)
        print(f"    {reason}", file=sys.stderr)
    print(file=sys.stderr)
    print(f"Diagnostic log: {ctx.layout.log_file}", file=sys.stderr)
    print("Resume after repair: sudo lsm-vps-init resume", file=sys.stderr)


def execute_stage(ctx: Context, store: StateStore, stage_slug: str) -> str:
    stage = stage_by_slug(stage_slug)
    ctx.state["current_stage"] = stage.slug
    if stage.detect(ctx):
        set_stage(ctx.state, stage.slug, "completed", evidence={"detected": True})
        store.save(ctx.state)
        return "completed"
    set_stage(ctx.state, stage.slug, "in_progress")
    store.save(ctx.state)
    try:
        result = stage.run(ctx)
    except Blocked as error:
        set_stage(ctx.state, stage.slug, "blocked", str(error))
        store.save(ctx.state)
        print_stage_stop_summary(ctx, stage, "blocked", str(error))
        return "blocked"
    except (Failed, CommandError) as error:
        set_stage(ctx.state, stage.slug, "failed", str(error))
        store.save(ctx.state)
        print_stage_stop_summary(ctx, stage, "failed", str(error))
        return "failed"
    if result.status == "blocked":
        set_stage(ctx.state, stage.slug, "blocked", result.message, result.evidence)
        print_stage_stop_summary(ctx, stage, "blocked", result.message)
    elif result.status == "failed":
        set_stage(ctx.state, stage.slug, "failed", result.message, result.evidence)
        print_stage_stop_summary(ctx, stage, "failed", result.message)
    else:
        set_stage(ctx.state, stage.slug, "completed", result.message, result.evidence)
    store.save(ctx.state)
    print(f"{stage.index:02d} {stage.slug}: {result.message}")
    return result.status


def run_stages(ctx: Context, store: StateStore, *, only: str | None = None, until: str | None = None) -> int:
    if only:
        status = execute_stage(ctx, store, only)
        return 0 if status == "completed" else 2

    until_index = None
    if until:
        until_index = stage_by_slug(until).index

    for stage in STAGES:
        if stage_superseded(ctx, stage):
            if ctx.state.get("current_stage") == stage.slug:
                ctx.state["current_stage"] = None
                store.save(ctx.state)
            if until_index is not None and stage.index >= until_index:
                break
            continue
        status = execute_stage(ctx, store, stage.slug)
        if status != "completed":
            return 2 if status == "blocked" else 1
        if until_index is not None and stage.index >= until_index:
            break
    print("Loud Sky Media VPS initialization completed successfully.")
    if ctx.state.get("reboot", {}).get("pending"):
        identity = ctx.state.get("facts", {}).get("ssh_identity_file_hint") or "~/.ssh/lsm_vps_ed25519"
        ip = ctx.state.get("facts", {}).get("public_ipv4") or "SERVER_IP"
        print()
        print("Initialization is complete, but Ubuntu requires a reboot.")
        print()
        print("Reboot:")
        print("    sudo reboot")
        print()
        print("Reconnect:")
        print(f"    ssh -p 65500 -i {identity} sadmin@{ip}")
        print()
        print("Verify:")
        print("    sudo lsm-vps-init status")
        print("    sudo lsm-vps-init resume")
    return 0


def emit_ssh_proof(nonce: str | None) -> int:
    try:
        proof = ssh_checkpoint_proof_from_env(nonce=nonce or "")
    except Blocked as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(proof, sort_keys=True))
    return 0


def record_ssh_proof(ctx: Context, store: StateStore, nonce: str | None) -> int:
    try:
        proof = json.load(sys.stdin)
        if nonce and proof.get("nonce") != nonce:
            raise Blocked("SSH recovery nonce mismatch.")
        evidence = record_ssh_checkpoint_proof(ctx.state, proof)
    except (Blocked, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    store.save(ctx.state)
    print(
        "SSH recovery checkpoint verified: "
        f"user={evidence['user']} local_ssh_port={evidence['local_ssh_port']} "
        f"verified={str(evidence['verified']).lower()} verified_at={evidence['verified_at']}"
    )
    print("Resume with: sudo lsm-vps-init resume")
    return 0


def confirm_relay(ctx: Context, store: StateStore) -> int:
    if ctx.state.get("selected_modules", {}).get("codex-vps-discord-relay"):
        relay_install = ctx.state.get("stages", {}).get("discord_relay_install", {}).get("status")
        if relay_install != "completed":
            print("Relay install stage is not complete; do not confirm round trip yet.", file=sys.stderr)
            return 2
    set_checkpoint(ctx.state, "relay_round_trip_verified", True)
    set_stage(ctx.state, "discord_relay_checkpoint", "completed", "Operator confirmed relay round trip.")
    store.save(ctx.state)
    print("Discord relay checkpoint recorded. Resume with: sudo lsm-vps-init resume")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "verify-ssh" and args.emit_proof:
        return emit_ssh_proof(args.nonce)
    ctx, store = make_context(args)

    if args.command == "status":
        print_status(ctx, as_json=args.json)
        return 0
    if args.command == "verify-ssh":
        print("Run the generated second-session SSH command; direct root nonce submission is not accepted.", file=sys.stderr)
        return 2
    if args.command == "record-ssh-proof":
        return record_ssh_proof(ctx, store, args.nonce)
    if args.command == "confirm-relay":
        return confirm_relay(ctx, store)
    return run_stages(ctx, store, only=args.stage, until=args.until)


if __name__ == "__main__":
    raise SystemExit(main())
