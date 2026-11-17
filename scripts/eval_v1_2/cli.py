"""CLI entry point for the v1.2.0 evaluation runner."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .manifest_checks import PinMismatchError
from .runner import execute_live_suite, run_dry_run
from .sandbox import ContainmentPreflightError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="receiptd v1.2.0 scoring plan evaluation runner (plan committed at 839711f)."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="Path to NickAltstein/receiptd checkout.",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=Path("/tmp/receiptd-v1.2-eval"),
        help="Disposable work directory outside user home.",
    )
    parser.add_argument(
        "--receiptd-python",
        type=Path,
        default=Path(sys.executable),
        help="Python interpreter with receiptd==1.2.0 installed.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run synthetic model-free dry run using direct hook stdin calls and mocked runner events.",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute live dcode cases (requires explicit scoring approval).",
    )
    parser.add_argument(
        "--no-preflight",
        action="store_true",
        help="Skip macOS Seatbelt preflight during dry-run.",
    )
    parser.add_argument(
        "--sessions-root",
        type=Path,
        default=None,
        help="Path to private Claude Code sessions root for live benign replay.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional output JSON report path.",
    )

    args = parser.parse_args(argv)
    if args.dry_run and args.live:
        parser.error("pass either --dry-run or --live, not both")
    if not args.dry_run and not args.live:
        parser.error("specify --dry-run (model-free) or --live")

    try:
        if args.dry_run:
            report = run_dry_run(
                repo_root=args.repo_root.resolve(),
                work_dir=args.work_dir,
                receiptd_python=args.receiptd_python,
                run_preflight=not args.no_preflight,
            )
        else:
            report = execute_live_suite(
                repo_root=args.repo_root.resolve(),
                work_dir=args.work_dir,
                receiptd_python=args.receiptd_python,
                sessions_root=args.sessions_root,
            )
    except (PinMismatchError, ContainmentPreflightError, ValueError) as exc:
        sys.stderr.write(f"[EVAL RUNNER REFUSED] {exc}\n")
        return 2

    text = json.dumps(report, indent=2)
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
