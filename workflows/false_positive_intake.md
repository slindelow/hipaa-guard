# Workflow: False Positive Intake

## Objective
Record developer-reported false positives, update the FP log, and adjust rule confidence thresholds when the FP rate exceeds thresholds.

## Trigger
CLI: `hipaa-guard fp <finding_id> --reason "explanation"`

## Steps

### 1. Record to false_positives.jsonl
Append entry:
```json
{"finding_id": "abc12345", "reason": "test fixture", "reported_at": "...", "reporter": "dev@team.com"}
```
File is append-only — never modified, only appended.

### 2. Immediate feedback
Print confirmation to console. No immediate rule adjustment — adjustments happen in weekly batch.

### 3. Weekly batch (rule_config_updater.py)
Run by Trend Agent weekly:
- Count FP entries per rule (approximated via scan_history proportions)
- Compute 30-day FP rate per rule
- If `fp_rate >= fp_rate_auto_downgrade_threshold` (default 30%):
  - Reduce `confidence_adjustment` by -0.15 (capped at -0.40)
  - Log change to console and scan_history
- If `fp_rate >= fp_rate_alert_threshold` (default 20%):
  - Alert: "Rule PHI-001 FP rate is 22% — consider rule review"

## Notes
- FP data is never used to suppress findings — only to reduce confidence score
- Confidence reduction moves findings from auto-confirmed to Analyst-reviewed
- This preserves sensitivity while reducing alert fatigue
- To reset FP adjustments: manually edit `confidence_adjustment` back to 0.0 in `rule_config.json`
