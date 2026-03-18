# Workflow: Weekly Trend Report

## Objective
Generate a 30-day compliance posture summary, detect drift, update rule confidence thresholds based on FP feedback, and alert on degradation.

## Trigger
Scheduled: weekly cron (Saturday 08:00 local time, or manual `hipaa-guard report`).
Also triggered automatically after any full audit scan.

## Steps

### 1. Load scan history
Read last 30 days from `scan_history/scan_log.jsonl`.
If fewer than 2 entries: skip drift detection, generate partial report.

### 2. Compute posture metrics (agent/trend_agent.py)
- Total scans, confirmed violations, applied fixes
- Findings by severity (30-day totals)
- Top 5 most frequent rules
- False positive rate from `false_positives.jsonl`
- Scanner precision: `(total_findings - fp_count) / total_findings`

### 3. Detect drift (agent/trend_agent.detect_drift)
Compare latest scan against previous:
- If new CRITICAL/HIGH findings appeared: flag as drift
- Include: how many new findings, when last clean, what rules

### 4. Update rule confidence (tools/rule_config_updater.py)
- Compute per-rule FP rates
- Apply confidence adjustments where threshold exceeded
- Log changes

### 5. Generate report (agent/trend_agent.generate_weekly_report)
Output: `.tmp/weekly_report.md`
Sections: summary table, by-severity breakdown, top violations, drift alert (if any), recommendations.

### 6. Send notifications
If `notifications.slack_webhook_env_var` is set:
- POST report summary to Slack
- Always include: total findings count, drift alert if present

## Outputs
- `.tmp/weekly_report.md`: full report
- `config/rule_config.json`: updated confidence adjustments
- Console: report printed
- Slack (optional): summary notification

## Self-Healing
- If scan_history is empty: generate empty report with setup instructions
- If Slack webhook fails: log warning, continue
- Trend Agent failure: non-blocking, just log error
