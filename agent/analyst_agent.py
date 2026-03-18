from __future__ import annotations
"""
analyst_agent.py

Disambiguates ambiguous Scanner findings using Claude.
Only invoked when finding confidence < analyst_threshold (default 0.85).
High-confidence findings pass through directly as confirmed.

Input:  list[RawFinding]
Output: list[TriagedFinding]
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from state_manager import RawFinding, TriagedFinding, Severity


_SYSTEM_PROMPT = """You are a HIPAA compliance analyst. Your job is to review potential HIPAA violations found by an automated scanner and determine whether they are real violations or false positives.

You will receive findings with redacted code context (PHI values replaced with placeholders like [REDACTED_SSN]).

Determine for each finding:
- is_real_violation: true/false
- confidence: 0.0 to 1.0
- reasoning: 1-2 sentences, no PHI values
- severity: critical|high|medium|low|info

Key questions:
- Is the code inside a test fixture, mock, or example? (test_*, mock_*, fake_*)
- Is the pattern in a comment or docstring?
- Is the credential a placeholder (YOUR_KEY, REPLACE_ME, ${VAR})?
- Does the file path suggest test infrastructure (tests/, spec/, __fixtures__/)?

Respond with a JSON array only. No prose outside the JSON.
[{"finding_id":"...","is_real_violation":true,"confidence":0.9,"reasoning":"...","severity":"high"}]"""


def analyze(
    findings: list[RawFinding],
    api_key: str,
    config: dict,
    analyst_threshold: float = 0.85,
) -> list[TriagedFinding]:
    """Triage findings. High-confidence are auto-confirmed; ambiguous go to Claude."""
    import anthropic

    triaged: list[TriagedFinding] = []
    high_confidence = [f for f in findings if f.confidence >= analyst_threshold]
    needs_analysis = [f for f in findings if f.confidence < analyst_threshold]

    for f in high_confidence:
        triaged.append(TriagedFinding(
            finding_id=f.finding_id,
            raw_finding=f,
            is_real_violation=True,
            confidence=f.confidence,
            reasoning="High-confidence match — auto-confirmed.",
            analyst_severity=f.severity,
        ))

    if not needs_analysis:
        return triaged

    client = anthropic.Anthropic(api_key=api_key)
    model = config.get("llm", {}).get("model", "claude-sonnet-4-6")

    # Batch up to 5 findings per API call
    for i in range(0, len(needs_analysis), 5):
        batch = needs_analysis[i:i + 5]
        payload = [
            {
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "scanner_confidence": f.confidence,
                "file": Path(f.file_path).name,
                "line": f.line_number,
                "context": f.code_context,
            }
            for f in batch
        ]

        try:
            resp = client.messages.create(
                model=model,
                max_tokens=1024,
                system=_SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": f"Analyze these findings:\n{json.dumps(payload, indent=2)}"
                }],
            )
            raw = resp.content[0].text.strip()
            start, end = raw.find("["), raw.rfind("]") + 1
            analyses = json.loads(raw[start:end])

            for a in analyses:
                orig = next((f for f in batch if f.finding_id == a.get("finding_id")), None)
                if not orig:
                    continue
                triaged.append(TriagedFinding(
                    finding_id=a["finding_id"],
                    raw_finding=orig,
                    is_real_violation=a.get("is_real_violation", True),
                    confidence=float(a.get("confidence", orig.confidence)),
                    reasoning=a.get("reasoning", ""),
                    analyst_severity=Severity(a.get("severity", orig.severity.value)),
                ))
        except Exception as e:
            for f in batch:
                triaged.append(TriagedFinding(
                    finding_id=f.finding_id,
                    raw_finding=f,
                    is_real_violation=True,
                    confidence=f.confidence,
                    reasoning=f"Analyst error ({type(e).__name__}) — conservative fallback.",
                    analyst_severity=f.severity,
                ))

    return triaged
