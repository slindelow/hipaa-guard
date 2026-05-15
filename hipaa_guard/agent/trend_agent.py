from __future__ import annotations
"""
trend_agent.py

Tracks compliance posture over time, detects drift, generates weekly reports.
Read-only — never writes to codebase. Writes only to scan_history/ and report files.

Triggered: after every scan + weekly cron.
"""

import json
import datetime
from pathlib import Path

from hipaa_guard.tools.state_manager import ScanState
from hipaa_guard import paths


def record_scan(state: ScanState) -> None:
    """Append scan summary to scan_history/ after every completed scan."""
    history_dir = paths.get_scan_history_dir()

    entry = {
        "session_id": state.session_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "trigger": state.trigger.value if hasattr(state.trigger, 'value') else state.trigger,
        "files_scanned": len(state.target_files),
        "raw_findings": len(state.scanner_output),
        "confirmed_violations": sum(1 for t in state.analyst_output if t.is_real_violation),
        "applied_fixes": len(state.applied_fixes),
        "pending_human_review": len(state.pending_fixes),
        "by_severity": _count_by_severity(state),
        "by_rule": _count_by_rule(state),
        "errors": len(state.errors),
    }

    log_file = history_dir / "scan_log.jsonl"
    with log_file.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def detect_drift() -> dict | None:
    """
    Compare today's scan against last known clean state.
    Returns drift info if new HIGH/CRITICAL findings appeared.
    """
    history = _load_history()
    if len(history) < 2:
        return None

    latest = history[-1]
    previous = history[-2]

    latest_critical_high = (
        latest.get("by_severity", {}).get("critical", 0) +
        latest.get("by_severity", {}).get("high", 0)
    )
    prev_critical_high = (
        previous.get("by_severity", {}).get("critical", 0) +
        previous.get("by_severity", {}).get("high", 0)
    )

    if latest_critical_high > prev_critical_high:
        return {
            "drift_detected": True,
            "new_critical_high": latest_critical_high - prev_critical_high,
            "previous_scan": previous["timestamp"],
            "current_scan": latest["timestamp"],
        }
    return None


def generate_weekly_report() -> str:
    """
    Generate a weekly compliance posture report.
    Returns the report as a markdown string.
    """
    history = _load_history(days=30)

    if not history:
        return "# HIPAA-Guard Weekly Report\n\nNo scan history found. Run `hipaa-guard scan .` to begin tracking.\n"

    # Compute metrics
    total_scans = len(history)
    total_findings = sum(e.get("confirmed_violations", 0) for e in history)
    total_fixed = sum(e.get("applied_fixes", 0) for e in history)

    severity_totals: dict[str, int] = {}
    rule_totals: dict[str, int] = {}
    for entry in history:
        for sev, count in entry.get("by_severity", {}).items():
            severity_totals[sev] = severity_totals.get(sev, 0) + count
        for rule, count in entry.get("by_rule", {}).items():
            rule_totals[rule] = rule_totals.get(rule, 0) + count

    top_rules = sorted(rule_totals.items(), key=lambda x: x[1], reverse=True)[:5]

    # FP rate
    fp_log = paths.get_fp_log()
    fp_count = 0
    if fp_log.exists():
        fp_count = sum(1 for line in fp_log.read_text().splitlines() if line.strip())

    fp_rate = (fp_count / max(total_findings + fp_count, 1)) * 100

    # Build report
    lines = [
        f"# HIPAA-Guard Compliance Report",
        f"**Period:** Last 30 days  |  **Generated:** {datetime.date.today().isoformat()}",
        "",
        "## Summary",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Scans run | {total_scans} |",
        f"| Confirmed violations | {total_findings} |",
        f"| Auto-fixed | {total_fixed} |",
        f"| False positives reported | {fp_count} |",
        f"| Scanner precision | {100 - fp_rate:.0f}% |",
        "",
        "## Findings by Severity",
    ]
    for sev in ["critical", "high", "medium", "low"]:
        count = severity_totals.get(sev, 0)
        if count:
            lines.append(f"- **{sev.upper()}**: {count}")

    if top_rules:
        lines += ["", "## Most Frequent Violations"]
        for rule_id, count in top_rules:
            lines.append(f"- `{rule_id}`: {count} occurrence(s)")

    # Drift check
    drift = detect_drift()
    if drift:
        lines += [
            "",
            "## ⚠️ Compliance Drift Detected",
            f"New CRITICAL/HIGH findings since last scan: **{drift['new_critical_high']}**",
            f"Previous scan: {drift['previous_scan']}",
            f"Current scan: {drift['current_scan']}",
        ]

    lines += [
        "",
        "## Recommendations",
        "- Address all CRITICAL and HIGH findings before next release.",
        "- Review false positives to improve scanner precision.",
        "- Run `hipaa-guard audit` before any major deployment.",
        "",
        "_Generated by HIPAA-Guard. This report is informational — not a certified compliance audit._",
    ]

    report = "\n".join(lines)

    # Save report
    report_path = Path.cwd() / ".tmp" / "weekly_report.md"
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(report)
    print(f"📊 Weekly report saved to {report_path}")

    return report


def _load_history(days: int = 30) -> list[dict]:
    log_file = paths.get_scan_history_dir() / "scan_log.jsonl"
    if not log_file.exists():
        return []
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    entries = []
    for line in log_file.read_text().splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            ts = datetime.datetime.fromisoformat(entry["timestamp"])
            if ts >= cutoff:
                entries.append(entry)
        except Exception:
            continue
    return entries


def _count_by_severity(state: ScanState) -> dict[str, int]:
    counts: dict[str, int] = {}
    for t in state.analyst_output:
        if t.is_real_violation:
            sev = t.analyst_severity.value
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_by_rule(state: ScanState) -> dict[str, int]:
    counts: dict[str, int] = {}
    for t in state.analyst_output:
        if t.is_real_violation:
            rule = t.raw_finding.rule_id
            counts[rule] = counts.get(rule, 0) + 1
    return counts
