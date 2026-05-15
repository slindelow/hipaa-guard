from __future__ import annotations
"""
fix_agent.py

Proposes minimal, targeted code fixes for confirmed HIPAA violations.
Principle: fewest lines changed, no refactoring beyond the violation scope.

Input:  list[TriagedFinding]
Output: list[FixProposal]
"""

import json
from pathlib import Path

from hipaa_guard.tools.state_manager import TriagedFinding, FixProposal, RiskTier
from hipaa_guard.tools.phi_safe_handler import read_file_safe


_SYSTEM_PROMPT = """You are a HIPAA compliance fix engineer. Given a confirmed HIPAA violation, propose the minimal code fix.

Rules:
- Change the fewest lines possible
- Never refactor beyond the violation scope
- For hardcoded credentials: replace with os.getenv("VAR_NAME") and note what env var to set
- For PHI in logs: replace the PHI variable with a safe non-PHI identifier (e.g., patient_id instead of patient_name)
- For broad FHIR scopes: suggest the minimum necessary scope string
- For missing audit logs: inject audit_log.record(user_id, resource_type, resource_id, action) at the PHI access point
- For HTTP FHIR URLs: replace http:// with https://

Respond with JSON only:
{
  "finding_id": "...",
  "proposed_diff": "--- a/file.py\\n+++ b/file.py\\n@@ ... @@\\n-old line\\n+new line",
  "fix_rationale": "one sentence explaining what was changed and why",
  "risk_tier": "low|medium|high",
  "test_suggestion": "optional: specific test command to verify the fix (for medium/high risk only)"
}

Risk tier guide:
- low: deterministic, safe replacement (scope string narrowing, http→https)
- medium: requires context knowledge (credential externalization, audit log injection)
- high: touches auth/encryption logic or high blast-radius files"""


def propose_fixes(
    confirmed: list[TriagedFinding],
    api_key: str,
    config: dict,
    rule_config: dict,
) -> list[FixProposal]:
    """Generate fix proposals for confirmed violations."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    model = config.get("llm", {}).get("model", "claude-sonnet-4-6")
    proposals: list[FixProposal] = []

    for finding in confirmed:
        f = finding.raw_finding
        # Read redacted file context (±15 lines around finding)
        try:
            context = read_file_safe(f.file_path, context_lines=15, center_line=f.line_number)
        except Exception:
            context = f.code_context  # fall back to scanner context

        # Get risk tier from rule_config
        rule_cfg = rule_config.get("rules", {}).get(f.rule_id, {})
        default_risk = rule_cfg.get("risk_tier", "medium")

        payload = {
            "finding_id": f.finding_id,
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "severity": finding.analyst_severity.value,
            "file": Path(f.file_path).name,
            "line": f.line_number,
            "code_context": context,
            "analyst_reasoning": finding.reasoning,
            "default_risk_tier": default_risk,
        }

        try:
            resp = client.messages.create(
                model=model,
                max_tokens=1024,
                system=_SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": f"Propose a fix for this violation:\n{json.dumps(payload, indent=2)}"
                }],
            )
            raw = resp.content[0].text.strip()
            start, end = raw.find("{"), raw.rfind("}") + 1
            fix_data = json.loads(raw[start:end])

            proposals.append(FixProposal(
                finding_id=fix_data.get("finding_id", f.finding_id),
                violation_type=f.rule_id,
                original_file=f.file_path,
                proposed_diff=fix_data.get("proposed_diff", ""),
                fix_rationale=fix_data.get("fix_rationale", ""),
                risk_tier=RiskTier(fix_data.get("risk_tier", default_risk)),
                test_suggestion=fix_data.get("test_suggestion"),
            ))
        except Exception as e:
            # Can't propose a fix — will be flagged for manual remediation
            print(f"    ⚠  Fix Agent could not propose fix for {f.finding_id}: {e}")

    return proposals
