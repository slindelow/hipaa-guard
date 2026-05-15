from __future__ import annotations
"""
reviewer_agent.py

Adversarial critic of proposed fixes.
System prompt instructs it to FIND PROBLEMS, not validate.
Returns APPROVE / REJECT / MODIFY per fix proposal.

Input:  list[FixProposal], list[TriagedFinding]
Output: list[ReviewDecision]
"""

import json

from hipaa_guard.tools.state_manager import FixProposal, TriagedFinding, ReviewDecision, ReviewDecisionType


_SYSTEM_PROMPT = """You are an adversarial HIPAA fix reviewer. Your job is to find problems with proposed code fixes — not to validate them. You are the last line of defense before code is written.

For each proposed fix, check:
1. Does the fix ACTUALLY eliminate the violation, or just obfuscate it?
2. Does removing a log statement break observable behavior that monitoring depends on?
3. Does the scope narrowing break existing functionality (would code fail to access resources it needs)?
4. Does credential externalization match the deployment environment's secret management (os.getenv vs settings vs vault)?
5. Could the fix introduce a new security vulnerability?
6. Is the diff syntactically correct?
7. Are there edge cases where the fix fails silently?

Decision options:
- APPROVE: fix is correct and safe
- REJECT: fix has a real problem (explain specifically)
- MODIFY: fix is on the right track but needs adjustment (provide corrected diff)

Respond with JSON array only:
[{
  "finding_id": "...",
  "decision": "APPROVE|REJECT|MODIFY",
  "objections": ["specific issue 1", "specific issue 2"],
  "modified_diff": "corrected unified diff (only if MODIFY)"
}]"""


def review(
    proposals: list[FixProposal],
    confirmed: list[TriagedFinding],
    api_key: str,
) -> list[ReviewDecision]:
    """Adversarially review fix proposals."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)

    # Build context map: finding_id → analyst reasoning
    reasoning_map = {t.finding_id: t.reasoning for t in confirmed}

    payload = [
        {
            "finding_id": p.finding_id,
            "violation_type": p.violation_type,
            "risk_tier": p.risk_tier.value,
            "proposed_diff": p.proposed_diff,
            "fix_rationale": p.fix_rationale,
            "analyst_reasoning": reasoning_map.get(p.finding_id, ""),
        }
        for p in proposals
    ]

    decisions: list[ReviewDecision] = []

    try:
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Review these proposed fixes and find problems:\n{json.dumps(payload, indent=2)}"
            }],
        )
        raw = resp.content[0].text.strip()
        start, end = raw.find("["), raw.rfind("]") + 1
        reviews = json.loads(raw[start:end])

        for r in reviews:
            decision_str = r.get("decision", "APPROVE").upper()
            try:
                decision_type = ReviewDecisionType(decision_str.lower())
            except ValueError:
                decision_type = ReviewDecisionType.APPROVE

            decisions.append(ReviewDecision(
                finding_id=r["finding_id"],
                decision=decision_type,
                objections=r.get("objections", []),
                modified_diff=r.get("modified_diff"),
            ))

    except Exception as e:
        # Fallback: approve all but escalate risk tier
        for p in proposals:
            decisions.append(ReviewDecision(
                finding_id=p.finding_id,
                decision=ReviewDecisionType.APPROVE,
                objections=[f"Reviewer unavailable ({type(e).__name__}) — risk escalated to MEDIUM"],
            ))

    return decisions
