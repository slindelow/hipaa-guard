from __future__ import annotations
"""
rule_config_updater.py

Adjusts rule confidence thresholds based on false positive feedback.
Run weekly by the Trend Agent. Reads false_positives.jsonl,
computes 30-day FP rate per rule, and updates config/rule_config.json.
"""

import json
import datetime

from hipaa_guard import paths


def update_rule_confidence() -> dict:
    """
    Read FP log, compute 30-day rates, update rule_config.json.
    Returns a summary of changes made.
    """
    config_path = paths.get_rule_config_path()
    if not config_path.exists():
        return {"error": "rule_config.json not found"}

    config = json.loads(config_path.read_text())
    fp_log = paths.get_fp_log()

    # Load FP entries from last 30 days
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    fp_by_finding: list[dict] = []

    if fp_log.exists():
        for line in fp_log.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                ts = datetime.datetime.fromisoformat(entry["reported_at"])
                if ts >= cutoff:
                    fp_by_finding.append(entry)
            except Exception:
                continue

    # We need scan history to compute FP rate (TP + FP = total scanner findings)
    scan_log = paths.get_scan_history_dir() / "scan_log.jsonl"
    rule_totals_30d: dict[str, int] = {}

    if scan_log.exists():
        for line in scan_log.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                ts = datetime.datetime.fromisoformat(entry["timestamp"])
                if ts >= cutoff:
                    for rule_id, count in entry.get("by_rule", {}).items():
                        rule_totals_30d[rule_id] = rule_totals_30d.get(rule_id, 0) + count
            except Exception:
                continue

    # Count FPs by rule (approximation: use rule_id from finding ID prefix if available)
    # FP entries don't currently store rule_id — this is a limitation to improve later
    # For now: count total FPs and distribute proportionally (simple heuristic)
    total_fp = len(fp_by_finding)
    changes = []

    threshold = config.get("fp_rate_auto_downgrade_threshold", 0.30)
    alert_threshold = config.get("fp_rate_alert_threshold", 0.20)

    for rule_id, rule_cfg in config.get("rules", {}).items():
        total_findings = rule_totals_30d.get(rule_id, 0)
        if total_findings == 0:
            continue

        # Simple heuristic: apply total FP count proportionally
        estimated_fp = round(total_fp * (total_findings / max(sum(rule_totals_30d.values()), 1)))
        fp_rate = estimated_fp / max(total_findings + estimated_fp, 1)

        rule_cfg["fp_count_30d"] = estimated_fp
        rule_cfg["fp_rate_30d"] = round(fp_rate, 3)

        if fp_rate >= threshold:
            # Auto-downgrade: reduce confidence by 0.15
            old_adjustment = rule_cfg.get("confidence_adjustment", 0.0)
            new_adjustment = max(old_adjustment - 0.15, -0.40)  # cap at -0.40 total
            if new_adjustment != old_adjustment:
                rule_cfg["confidence_adjustment"] = round(new_adjustment, 2)
                changes.append({
                    "rule_id": rule_id,
                    "action": "confidence_downgrade",
                    "old_adjustment": old_adjustment,
                    "new_adjustment": new_adjustment,
                    "fp_rate": fp_rate,
                })
        elif fp_rate >= alert_threshold:
            changes.append({
                "rule_id": rule_id,
                "action": "fp_rate_alert",
                "fp_rate": fp_rate,
                "message": f"FP rate {fp_rate:.0%} approaching threshold — consider rule review",
            })

    config_path.write_text(json.dumps(config, indent=2))
    return {"changes": changes, "total_fp_30d": total_fp}
