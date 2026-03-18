from __future__ import annotations
"""
educator_agent.py

Generates plain-English regulatory explanations paired with each confirmed finding.
Runs in parallel with the Fix Agent — non-blocking, informational only.

Input:  list[TriagedFinding]
Output: list[Education]
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from state_manager import TriagedFinding, Education
from phi_pattern_library import get_rule_by_id


# CFR citation map — supplement what's in phi_pattern_library
_CFR_MAP = {
    "PHI-001": ("45 CFR §164.312(a)(1)", "Access Control — Unique user identification"),
    "PHI-002": ("45 CFR §164.312(a)(1)", "Access Control — PHI in source code"),
    "PHI-003": ("45 CFR §164.312(a)(1)", "Access Control — MRN exposure"),
    "PHI-004": ("45 CFR §164.312(b)", "Audit Controls — PHI in application logs"),
    "PHI-005": ("45 CFR §164.312(a)(1)", "Access Control — NPI exposure"),
    "PHI-006": ("45 CFR §164.312(b)", "Audit Controls — PHI interpolated into strings"),
    "CRED-001": ("45 CFR §164.312(a)(2)(iv)", "Encryption — Hardcoded FHIR credentials"),
    "CRED-002": ("45 CFR §164.312(a)(2)(iv)", "Encryption — Hardcoded API credentials"),
    "CRED-003": ("45 CFR §164.312(e)(1)", "Transmission Security — Credentials in URL"),
    "FHIR-001": ("45 CFR §164.502(b)", "Minimum Necessary — Overly broad patient scope"),
    "FHIR-002": ("45 CFR §164.502(b)", "Minimum Necessary — Overly broad user scope"),
    "FHIR-003": ("45 CFR §164.312(e)(1)", "Transmission Security — Unencrypted FHIR endpoint"),
    "AUDIT-001": ("45 CFR §164.312(b)", "Audit Controls — Missing access log on PHI"),
    "AUDIT-002": ("45 CFR §164.312(e)(1)", "Transmission Security — PHI in unencrypted response"),
    "ENC-001": ("45 CFR §164.312(a)(2)(iv)", "Encryption — PHI written to unencrypted file"),
}

_REMEDIATION_MAP = {
    "PHI-001": [
        "Remove the SSN from source code immediately.",
        "If this is test data, use a clearly fake SSN like 000-00-0000 or store in a .env.test file.",
        "If real, delete from git history with: git filter-branch or BFG Repo Cleaner.",
    ],
    "PHI-004": [
        "Replace patient_name/full_name with a non-PHI identifier in log statements.",
        "Use patient.id or an internal reference ID that cannot be linked to a person without additional data.",
        "Consider structured logging with explicit PHI field exclusion.",
    ],
    "CRED-001": [
        "Move client_secret to an environment variable: os.getenv('FHIR_CLIENT_SECRET')",
        "Add FHIR_CLIENT_SECRET to your .env file (gitignored) and your deployment secret manager.",
        "Rotate the exposed credential immediately — assume it is compromised.",
        "Search git history for the credential: git log -S 'the_secret_value'",
    ],
    "CRED-002": [
        "Move the API key to an environment variable.",
        "Rotate the exposed key immediately.",
        "Add the key name to .env.example for documentation without exposing the value.",
    ],
    "FHIR-001": [
        "Replace patient/*.read with the minimum necessary scope.",
        "Example: if only reading Observations, use patient/Observation.read",
        "See SMART on FHIR scope documentation for available resource-level scopes.",
    ],
    "FHIR-003": [
        "Replace http:// with https:// in the FHIR base URL.",
        "Ensure your FHIR server has a valid TLS certificate.",
        "For local development, use a self-signed cert or a tool like mkcert.",
    ],
    "AUDIT-001": [
        "Add an audit log call whenever PHI is accessed: audit_log.record(user_id, 'Patient', patient_id, 'read')",
        "Ensure your audit log is append-only and tamper-evident.",
        "HIPAA requires audit logs to be retained for 6 years.",
    ],
}


_SYSTEM_PROMPT = """You are a HIPAA educator for software engineers. Given a confirmed HIPAA violation, write a clear, plain-English explanation that a developer who has never read HIPAA can understand.

Include:
1. What regulation is violated and why it exists (1-2 sentences)
2. What the real-world risk is if this is exploited (1 sentence)
3. Why this pattern specifically violates the rule (1 sentence)

Keep it under 100 words. No legal jargon. Write like you're explaining to a colleague, not a compliance officer.
Do not include the CFR citation in the plain_english field — that's provided separately.

Respond with JSON only:
{"finding_id": "...", "plain_english": "..."}"""


def educate(confirmed: list[TriagedFinding], api_key: str) -> list[Education]:
    """Generate regulatory explanations for all confirmed findings."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    results: list[Education] = []

    for finding in confirmed:
        rule_id = finding.raw_finding.rule_id
        cfr, cfr_desc = _CFR_MAP.get(rule_id, ("45 CFR §164.312", "HIPAA Security Rule"))
        remediation = _REMEDIATION_MAP.get(rule_id, ["Review and remediate per HIPAA Security Rule guidelines."])

        # Try to get LLM explanation; fall back to static if it fails
        plain_english = _static_explanation(rule_id)
        try:
            resp = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=300,
                system=_SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": json.dumps({
                        "finding_id": finding.finding_id,
                        "rule_id": rule_id,
                        "rule_name": finding.raw_finding.rule_name,
                        "severity": finding.analyst_severity.value,
                        "analyst_reasoning": finding.reasoning,
                    })
                }],
            )
            raw = resp.content[0].text.strip()
            start, end = raw.find("{"), raw.rfind("}") + 1
            data = json.loads(raw[start:end])
            plain_english = data.get("plain_english", plain_english)
        except Exception:
            pass  # Use static fallback

        results.append(Education(
            finding_id=finding.finding_id,
            rule_id=rule_id,
            plain_english=plain_english,
            cfr_citation=f"{cfr} ({cfr_desc})",
            remediation_steps=remediation,
        ))

    return results


def _static_explanation(rule_id: str) -> str:
    _STATIC = {
        "PHI-001": "HIPAA requires that patient Social Security Numbers be treated as Protected Health Information (PHI). Storing an SSN in source code means anyone with repo access can read it — and it persists in git history even after deletion. A breach of SSN data triggers mandatory notification to affected patients and HHS.",
        "PHI-004": "HIPAA's Audit Controls standard requires that access to PHI be logged, but it does NOT mean PHI should appear in the logs themselves. Logging a patient's name creates an uncontrolled secondary record of PHI that may be sent to external log aggregators, violating the Minimum Necessary principle.",
        "CRED-001": "Hardcoding a FHIR OAuth client_secret in source code violates HIPAA's requirement for unique user authentication and encryption of ePHI. Anyone who reads the code — or the git history — can impersonate your application and access patient data from the FHIR server without authorization.",
        "FHIR-001": "HIPAA's Minimum Necessary standard requires that applications only request access to the PHI they actually need. A wildcard FHIR scope (patient/*.read) grants access to ALL patient data — medications, diagnoses, lab results — when your app may only need one resource type.",
        "FHIR-003": "HIPAA's Transmission Security standard requires that ePHI be encrypted in transit. An HTTP FHIR endpoint sends patient data in plaintext — anyone on the network path can intercept and read it. FHIR over HTTP is never acceptable in a production or staging environment.",
        "AUDIT-001": "HIPAA requires that access to ePHI be logged for audit purposes. This function reads patient data but does not call an audit logging function. Without this log, your organization cannot demonstrate who accessed patient records — a requirement for HIPAA compliance and breach investigations.",
    }
    return _STATIC.get(rule_id, f"This finding violates HIPAA Security Rule requirements. Review the CFR citation for details and remediate promptly.")
