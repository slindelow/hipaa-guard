# Workflow: Manual Audit

## Objective
Full repository audit on demand. Scans all files, runs the complete AI pipeline, generates a HIPAA compliance document draft, and checks dependency BAA status.

## Trigger
CLI: `hipaa-guard audit`
Also run before major releases or on release tags.

## Steps

### 1. Collect all repo files
Use `cli._collect_files([repo_root], config)` with `include_extensions` and `exclude_paths` from config.
Typical run: 50-500 files depending on repo size.

### 2. Run Scanner
Full `scan_files(all_files)` — same scanner as pre-commit but on entire repo.

### 3. Run AI Pipeline
Same as pre_commit_scan but with `trigger = ScanTrigger.MANUAL`:
- No commit blocking — output only
- All risk tiers default to PROPOSE (no auto-apply in audit mode)

### 4. Run BAA Checker (tools/baa_checker.py)
- Parse `requirements.txt`, `package.json`, `pyproject.toml`
- Cross-reference `config/baa_registry.json`
- Identify PHI-touching packages using import analysis
- Output: BAA inventory with action-required items

### 5. Generate Compliance Document (tools/compliance_doc_generator.py)
Input: confirmed findings + BAA results
Output: `HIPAA_Technical_Safeguards_Summary_YYYY-MM-DD.md` saved to `.tmp/`

Document sections:
- Executive Summary
- Technical Safeguard Status by CFR category
- Implementation checklist per category
- Third-party BAA inventory
- Required next steps

### 6. Record to scan_history
Append session summary to `scan_history/scan_log.jsonl`.

## Outputs
- Console: full finding list + BAA report
- `.tmp/hipaa_compliance_report.md`: compliance document draft
- `.tmp/weekly_report.md`: updated posture trend
- `scan_history/scan_log.jsonl`: updated

## Notes
- Audit mode never blocks or auto-applies fixes
- Runtime varies: 30 seconds (small repo, no API key) to 3-5 minutes (large repo with full AI pipeline)
- First audit should be run with `onboarding_mode: true` to triage false positives before enforcement
