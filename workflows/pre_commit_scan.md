# Workflow: Pre-Commit Scan

## Objective
Scan staged git files for HIPAA violations before a commit is finalized. Block the commit if CRITICAL or HIGH violations are confirmed. Allow MEDIUM/LOW to pass with a warning (unless `onboarding_mode: false`).

## Trigger
Git pre-commit hook, installed by `tools/git_hook_installer.py`.

## Required Inputs
- List of staged files (from `git diff --cached --name-only --diff-filter=ACM`)
- `hipaa-guard.config.json` (project root)
- `config/rule_config.json`
- `ANTHROPIC_API_KEY` environment variable (optional — enables AI pipeline)

## Steps

### 1. Collect staged files
```bash
STAGED=$(git diff --cached --name-only --diff-filter=ACM)
```
Skip binary files, images, compiled artifacts. Use `scan.include_extensions` from config.

### 2. Run Scanner (tools/scanner.py)
- Execute `scan_files(staged_file_list)`
- No LLM calls — must complete in under 10 seconds
- Output: `list[RawFinding]` written to session state

### 3. Route by confidence
- `confidence >= 0.85`: auto-confirmed, proceed to fix loop
- `confidence < 0.85`: send to Analyst Agent (LLM)
- If `ANTHROPIC_API_KEY` not set: treat all findings as confirmed (conservative)

### 4. Run AI Pipeline (if API key available)
Invoke `agent/orchestrator.py:run_pipeline()` with confirmed findings.
Pipeline: Analyst → Fix + Educator (parallel) → Reviewer → Verifier

### 5. Output and block decision
Check `severity_block_thresholds.pre_commit` from `rule_config.json` (default: `["critical", "high"]`).
- If confirmed violations match block list AND `onboarding_mode: false`: exit code 1 (block commit)
- Otherwise: exit code 0 (allow commit, print warning)

## Edge Cases
- **Scanner times out (>30s)**: Abort scan, block commit with message "HIPAA-Guard timed out — manual review required."
- **All findings are FP-adjusted below threshold**: Allow commit, log to scan_history.
- **No staged files match include_extensions**: Skip scan, allow commit.
- **onboarding_mode: true**: Never block, always allow. Log findings to scan_history.

## Outputs
- Console output: severity-colored finding list
- `scan_history/scan_log.jsonl`: appended with session summary
- Applied fixes (LOW risk, auto-applied): written to staged files before commit completes

## Self-Healing
- If Analyst fails: conservative fallback (all ambiguous → confirmed)
- If Fix/Reviewer fails: skip auto-fix, output violations for manual remediation
- If Verifier fails: escalate fix to MEDIUM risk
- All errors logged to state file `errors[]`
