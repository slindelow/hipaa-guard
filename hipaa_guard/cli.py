from __future__ import annotations
#!/usr/bin/env python3
"""
cli.py — HIPAA-Guard entry point

Commands:
  hipaa-guard scan <path> [path2 ...]   Scan files/directories
  hipaa-guard audit                     Full repo audit + compliance doc
  hipaa-guard fp <finding_id>           Mark finding as false positive
  hipaa-guard fn <file> <line>          Report missed finding (false negative)
  hipaa-guard install-hook              Install pre-commit git hook
  hipaa-guard report                    Generate compliance report
  hipaa-guard baa                       Check dependency BAA status
"""

import sys
import json
import argparse
import datetime
from pathlib import Path

from hipaa_guard import paths
from hipaa_guard.tools.state_manager import new_session, ScanTrigger
from hipaa_guard.tools.scanner import scan_files


def _load_config() -> dict:
    cfg_path = paths.get_project_config()
    if cfg_path:
        return json.loads(cfg_path.read_text())
    # Fall back to bundled default
    default = paths.get_package_data_path("hipaa-guard.config.json")
    if default.exists():
        return json.loads(default.read_text())
    return {}


def _load_rule_config() -> dict:
    cfg_path = paths.get_rule_config_path()
    if cfg_path.exists():
        return json.loads(cfg_path.read_text())
    return {}


def _collect_files(file_paths: list[str], config: dict) -> list[str]:
    """Expand directories to file lists respecting config inclusions/exclusions."""
    include_exts = set(config.get("scan", {}).get("include_extensions", []))
    exclude_paths = set(config.get("scan", {}).get("exclude_paths", []))

    files = []
    for path_str in file_paths:
        p = Path(path_str)
        if p.is_file():
            files.append(str(p))
        elif p.is_dir():
            for child in p.rglob("*"):
                if child.is_file():
                    skip = False
                    for excl in exclude_paths:
                        if excl in str(child):
                            skip = True
                            break
                    if skip:
                        continue
                    if include_exts and child.suffix not in include_exts:
                        continue
                    files.append(str(child))
    return sorted(set(files))


def _severity_color(severity: str) -> str:
    colors = {
        'critical': '\033[91m',
        'high':     '\033[31m',
        'medium':   '\033[33m',
        'low':      '\033[34m',
        'info':     '\033[37m',
    }
    return colors.get(severity, '')


RESET = '\033[0m'
BOLD = '\033[1m'


def cmd_scan(args, config: dict, rule_config: dict) -> int:
    """Run a scan on specified paths. Returns exit code."""
    files = _collect_files(args.paths, config)

    if not files:
        print("No files found to scan.")
        return 0

    onboarding = config.get("scan", {}).get("onboarding_mode", True)
    trigger = ScanTrigger.MANUAL

    print(f"{BOLD}HIPAA-Guard{RESET} scanning {len(files)} file(s)...")
    if onboarding:
        print(f"\033[33m⚠  Onboarding mode active — findings reported but not blocking.{RESET}\n")

    state = new_session(trigger, files)
    findings = scan_files(files)

    if not findings:
        print(f"\033[32m✅ No findings.{RESET}")
        return 0

    analyst_threshold = rule_config.get("confidence_threshold_analyst", 0.85)
    block_severities = set(rule_config.get("severity_block_thresholds", {}).get("manual", []))

    confirmed = [f for f in findings if f.confidence >= analyst_threshold]
    needs_analyst = [f for f in findings if f.confidence < analyst_threshold]

    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}Scan Results{RESET}")
    print(f"{'=' * 60}")
    print(f"  Files scanned : {len(files)}")
    print(f"  Total findings: {len(findings)}")
    print(f"  High-confidence: {len(confirmed)}")
    print(f"  Needs review  : {len(needs_analyst)}")
    print()

    if confirmed:
        print(f"{BOLD}── Confirmed Violations ───────────────────────────────{RESET}")
        for f in confirmed:
            color = _severity_color(f.severity.value)
            print(f"  {color}[{f.severity.value.upper()}]{RESET} {f.rule_id} | {Path(f.file_path).name}:{f.line_number}")
            print(f"         {f.rule_name}")
            print(f"         ID: {f.finding_id}  Confidence: {f.confidence:.0%}")
            print()

    if needs_analyst:
        print(f"{BOLD}── Possible Issues (lower confidence) ─────────────────{RESET}")
        for f in needs_analyst:
            color = _severity_color(f.severity.value)
            print(f"  {color}[{f.severity.value.upper()}]{RESET} {f.rule_id} | {Path(f.file_path).name}:{f.line_number}")
            print(f"         {f.rule_name}")
            print(f"         ID: {f.finding_id}  Confidence: {f.confidence:.0%}")
            print()

    anthropic_key = _get_anthropic_key()
    if anthropic_key and confirmed:
        print(f"{BOLD}── Running AI Analysis Pipeline ────────────────────────{RESET}")
        try:
            from hipaa_guard.agent.orchestrator import run_pipeline
            run_pipeline(state, confirmed + needs_analyst, anthropic_key, config, rule_config)
        except ImportError:
            print("\033[33m  (AI pipeline not yet initialized — showing raw scanner results)\033[0m")
    elif confirmed and not anthropic_key:
        print("\033[33m  Tip: Set ANTHROPIC_API_KEY to enable AI-powered analysis, auto-fix, and regulatory explanations.\033[0m")

    print()
    print(f"  To mark a finding as false positive: {BOLD}hipaa-guard fp <finding_id>{RESET}")
    print(f"  To report a missed violation:        {BOLD}hipaa-guard fn <file> <line> --type <rule_id>{RESET}")
    print()

    has_blockers = any(f.severity.value in block_severities for f in confirmed)
    if has_blockers and not onboarding:
        return 1
    return 0


def cmd_fp(args) -> int:
    """Record a false positive."""
    fp_log = paths.get_fp_log()
    entry = {
        "finding_id": args.finding_id,
        "reason": args.reason or "not provided",
        "reported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reporter": args.reporter or "anonymous",
    }
    with fp_log.open("a") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"✅ False positive recorded for finding {args.finding_id}.")
    print(f"   Reason: {entry['reason']}")
    print(f"   This will be factored into rule confidence after 30-day analysis.")
    return 0


def cmd_fn(args) -> int:
    """Record a false negative (missed finding)."""
    fn_log = paths.get_fn_log()
    entry = {
        "file": args.file,
        "line": args.line,
        "phi_type": args.type or "unknown",
        "reason": args.reason or "not provided",
        "reported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    with fn_log.open("a") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"✅ Missed finding recorded for {args.file}:{args.line}.")
    print(f"   This will be used to expand detection rules.")
    return 0


def cmd_audit(args, config: dict, rule_config: dict) -> int:
    """Full repo audit — scans all files and generates compliance report."""
    repo_root = Path.cwd()
    print(f"{BOLD}HIPAA-Guard Full Audit{RESET} — {repo_root}")
    print("Collecting files...")

    files = _collect_files([str(repo_root)], config)
    print(f"Found {len(files)} files. Running scan...")

    state = new_session(ScanTrigger.MANUAL, files)
    findings = scan_files(files)

    try:
        from hipaa_guard.tools.baa_checker import check_baa
        baa_results = check_baa(str(repo_root))
    except ImportError:
        baa_results = None

    try:
        from hipaa_guard.tools.compliance_doc_generator import generate
        output_path = repo_root / ".tmp" / "hipaa_compliance_report.md"
        output_path.parent.mkdir(exist_ok=True)
        generate(findings, baa_results, str(output_path))
        print(f"\n📄 Compliance report generated: {output_path}")
    except ImportError:
        pass

    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    print(f"\n{BOLD}Audit Summary{RESET}")
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = by_severity.get(sev, 0)
        if count:
            color = _severity_color(sev)
            print(f"  {color}{sev.upper():8}{RESET} {count}")

    return 0


def cmd_install_hook(args) -> int:
    """Install the pre-commit git hook."""
    from hipaa_guard.tools.git_hook_installer import install
    try:
        install()
        return 0
    except Exception as e:
        print(f"Error installing hook: {e}")
        return 1


def cmd_baa(args, config: dict) -> int:
    """Check BAA status of project dependencies."""
    from hipaa_guard.tools.baa_checker import check_baa, print_baa_report
    try:
        results = check_baa(str(Path.cwd()))
        print_baa_report(results)
        return 0
    except Exception as e:
        print(f"BAA check failed: {e}")
        return 1


def _get_anthropic_key() -> str | None:
    import os
    return os.environ.get("ANTHROPIC_API_KEY")


def main():
    parser = argparse.ArgumentParser(
        prog="hipaa-guard",
        description="HIPAA-Guard: AI-powered HIPAA compliance scanner for healthcare software teams",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan files or directories for HIPAA violations")
    scan_parser.add_argument("paths", nargs="+", help="Files or directories to scan")

    subparsers.add_parser("audit", help="Full repo audit + compliance document generation")

    fp_parser = subparsers.add_parser("fp", help="Mark a finding as false positive")
    fp_parser.add_argument("finding_id", help="Finding ID (shown in scan output)")
    fp_parser.add_argument("--reason", help="Why this is a false positive")
    fp_parser.add_argument("--reporter", help="Your name/handle")

    fn_parser = subparsers.add_parser("fn", help="Report a missed finding (false negative)")
    fn_parser.add_argument("file", help="File path")
    fn_parser.add_argument("line", type=int, help="Line number")
    fn_parser.add_argument("--type", help="PHI type or rule ID")
    fn_parser.add_argument("--reason", help="Description of what was missed")

    subparsers.add_parser("install-hook", help="Install pre-commit git hook")
    subparsers.add_parser("baa", help="Check BAA status of project dependencies")

    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()
    config = _load_config()
    rule_config = _load_rule_config()

    if args.command == "scan":
        sys.exit(cmd_scan(args, config, rule_config))
    elif args.command == "audit":
        sys.exit(cmd_audit(args, config, rule_config))
    elif args.command == "fp":
        sys.exit(cmd_fp(args))
    elif args.command == "fn":
        sys.exit(cmd_fn(args))
    elif args.command == "install-hook":
        sys.exit(cmd_install_hook(args))
    elif args.command == "baa":
        sys.exit(cmd_baa(args, config))
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    main()
