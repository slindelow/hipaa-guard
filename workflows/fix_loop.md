# Workflow: Fix Loop

## Objective
For each confirmed HIPAA violation, propose a minimal fix, have it adversarially reviewed, verify it resolves the issue, and apply it at the appropriate risk tier. Maximum 3 iterations before escalating to human review.

## Trigger
Called as sub-workflow by `pre_commit_scan.md` and `ci_full_scan.md` when confirmed violations exist.

## Steps

### 1. Fix Agent (agent/fix_agent.py)
For each confirmed `TriagedFinding`:
- Read redacted file context (±15 lines via `phi_safe_handler.read_file_safe`)
- Call Claude: propose minimal unified diff fix
- Output: `FixProposal` with `proposed_diff`, `fix_rationale`, `risk_tier`, `test_suggestion`

### 2. Educator Agent (agent/educator_agent.py) — PARALLEL
Runs in a `threading.Thread` simultaneously with Fix Agent:
- Generates plain-English regulatory explanation
- Looks up CFR citation from `_CFR_MAP`
- Falls back to static explanations in `_STATIC` if LLM unavailable
- Non-blocking — Educator failure never stops the fix loop

### 3. Reviewer Agent (agent/reviewer_agent.py) — ADVERSARIAL
For each `FixProposal`:
- System prompt: "Find problems, not validate"
- Checks: does fix actually resolve? does it break functionality? is diff syntactically correct?
- Output: `ReviewDecision` (APPROVE / REJECT / MODIFY)
- MODIFY: reviewer provides corrected diff, which replaces original proposal

### 4. Verifier (agent/verifier.py)
For each APPROVED proposal:
- Apply diff in memory to temp file (never writes to disk yet)
- Re-run `scanner.scan_files([temp_file])`
- Check: original rule_id no longer fires AND no new findings
- If new findings: reject proposal, re-enter loop

### 5. Convergence check
- `state.loop_count` increments each iteration
- If `loop_count >= max_fix_loop_iterations` (default 3): mark finding `HUMAN_REQUIRED`, add to `state.pending_fixes`, move on
- Prevents infinite loops

### 6. Apply approved fixes
Based on `risk_tier` from `rule_config.json`:
- **LOW**: auto-apply (write to disk), add to `state.applied_fixes`
- **MEDIUM**: print diff + rationale, prompt `[y/N]`, apply if confirmed
- **HIGH**: print diff + rationale, do NOT apply, add to `state.pending_fixes`

## Risk Tier Escalation Rules
- Reviewer returns REJECT on iteration 2 → escalate risk tier by one level
- Verifier fails → escalate to MEDIUM
- Fix Agent fails → skip to manual remediation

## Outputs
- `state.applied_fixes`: list of finding_ids where fix was written to disk
- `state.pending_fixes`: list of finding_ids requiring human action
- `state.educator_output`: regulatory explanations printed after loop completes
- Console: color-coded summary of what was fixed, proposed, and escalated
