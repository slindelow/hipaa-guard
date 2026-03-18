from __future__ import annotations
"""
phi_pattern_library.py

PHI detection rules for the Scanner.
Kept separate from scanner.py so rules can be updated independently.

Each rule is a dict with:
  id          - unique rule identifier (used in reports and config)
  name        - human-readable name
  description - what this rule catches
  severity    - default severity if matched
  confidence  - default confidence score (0.0 – 1.0); Analyst may adjust
  pattern     - compiled regex OR None (AST-based rules have None here)
  category    - "phi_value" | "credential" | "fhir_scope" | "audit_gap" | "encryption"
  cfr         - relevant HIPAA CFR citation
  ast_check   - function name in scanner.py to call for AST-based rules (optional)
  false_positive_hints - patterns that, if present in context, reduce confidence
"""

import re

RULES = [
    # ── PHI Values ──────────────────────────────────────────────────────────

    {
        "id": "PHI-001",
        "name": "SSN in source code",
        "description": "Social Security Number pattern detected in non-comment code",
        "severity": "high",
        "confidence": 0.75,
        "pattern": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "category": "phi_value",
        "cfr": "45 CFR §164.312(a)(1)",
        "false_positive_hints": [
            re.compile(r'#.*\d{3}-\d{2}-\d{4}'),       # SSN in comment
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
            re.compile(r'format|pattern|regex|placeholder', re.I),
        ],
    },
    {
        "id": "PHI-002",
        "name": "Date of birth in string literal",
        "description": "DOB assigned to a PHI-adjacent variable or field",
        "severity": "medium",
        "confidence": 0.65,
        "pattern": re.compile(
            r'(?i)(dob|date_of_birth|birth_date|birthdate)\s*[=:]\s*["\']'
            r'(19|20)\d{2}[/-](0[1-9]|1[0-2])[/-](0[1-9]|[12]\d|3[01])["\']'
        ),
        "category": "phi_value",
        "cfr": "45 CFR §164.312(a)(1)",
        "false_positive_hints": [
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },
    {
        "id": "PHI-003",
        "name": "MRN in string literal",
        "description": "Medical Record Number detected near patient-context code",
        "severity": "high",
        "confidence": 0.80,
        "pattern": re.compile(
            r'(?i)(mrn|medical_record_number|medical_record_no|chart_number)\s*[=:"\s]+\d{6,12}'
        ),
        "category": "phi_value",
        "cfr": "45 CFR §164.312(a)(1)",
        "false_positive_hints": [
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },
    {
        "id": "PHI-004",
        "name": "Patient name in log statement",
        "description": "Patient name field passed directly to a logger",
        "severity": "high",
        "confidence": 0.70,
        "pattern": re.compile(
            r'(?i)(log|logger|logging|print)\s*[\.(].*'
            r'(patient_name|patient\.name|first_name|last_name|full_name)'
        ),
        "category": "phi_value",
        "cfr": "45 CFR §164.312(b)",
        "false_positive_hints": [
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },
    {
        "id": "PHI-005",
        "name": "NPI number in source code",
        "description": "National Provider Identifier (10-digit) detected",
        "severity": "medium",
        "confidence": 0.70,
        "pattern": re.compile(r'(?i)(npi|national_provider)\s*[=:"\s]+\d{10}\b'),
        "category": "phi_value",
        "cfr": "45 CFR §164.312(a)(1)",
        "false_positive_hints": [
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },
    {
        "id": "PHI-006",
        "name": "PHI in f-string or format string",
        "description": "Patient identifier interpolated into a string (likely logged or returned)",
        "severity": "medium",
        "confidence": 0.60,
        "pattern": re.compile(
            r'f["\'].*\{.*(patient_id|patient_name|ssn|mrn|dob|date_of_birth).*\}.*["\']'
        ),
        "category": "phi_value",
        "cfr": "45 CFR §164.312(b)",
        "false_positive_hints": [
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },

    # ── Credentials ──────────────────────────────────────────────────────────

    {
        "id": "CRED-001",
        "name": "Hardcoded FHIR client_secret",
        "description": "FHIR OAuth2 client_secret found hardcoded in source",
        "severity": "critical",
        "confidence": 0.90,
        "pattern": re.compile(
            r'(?i)(client_secret|clientsecret)\s*=\s*["\'][A-Za-z0-9\-_\.\/+]{8,}["\']'
        ),
        "category": "credential",
        "cfr": "45 CFR §164.312(a)(2)(iv)",
        "false_positive_hints": [
            re.compile(r'os\.environ|os\.getenv|environ\.get', re.I),
            re.compile(r'YOUR_SECRET|REPLACE_ME|<.*>|\$\{|\$\(', re.I),
        ],
    },
    {
        "id": "CRED-002",
        "name": "Hardcoded API key or bearer token",
        "description": "API key or bearer token hardcoded in source",
        "severity": "critical",
        "confidence": 0.85,
        "pattern": re.compile(
            r'(?i)(api_key|apikey|access_token|bearer)\s*=\s*["\'][A-Za-z0-9\-_\.\/+]{16,}["\']'
        ),
        "category": "credential",
        "cfr": "45 CFR §164.312(a)(2)(iv)",
        "false_positive_hints": [
            re.compile(r'os\.environ|os\.getenv|environ\.get', re.I),
            re.compile(r'YOUR_KEY|REPLACE_ME|<.*>|\$\{|\$\(', re.I),
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },
    {
        "id": "CRED-003",
        "name": "FHIR server URL with embedded credentials",
        "description": "FHIR base URL contains embedded username/password",
        "severity": "critical",
        "confidence": 0.95,
        "pattern": re.compile(
            r'https?://[A-Za-z0-9\-_\.]+:[A-Za-z0-9\-_\.@!#$%^&*()]+@'
            r'[A-Za-z0-9\-_\.]+/fhir'
        ),
        "category": "credential",
        "cfr": "45 CFR §164.312(e)(1)",
        "false_positive_hints": [],
    },

    # ── FHIR Scope ────────────────────────────────────────────────────────────

    {
        "id": "FHIR-001",
        "name": "Overly broad FHIR patient scope",
        "description": "SMART on FHIR scope uses wildcard resource access",
        "severity": "high",
        "confidence": 0.90,
        "pattern": re.compile(r'patient/\*\.(read|write|\*)'),
        "category": "fhir_scope",
        "cfr": "45 CFR §164.502(b) (Minimum Necessary)",
        "false_positive_hints": [
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },
    {
        "id": "FHIR-002",
        "name": "Overly broad FHIR user scope",
        "description": "SMART on FHIR user scope uses wildcard resource access",
        "severity": "high",
        "confidence": 0.90,
        "pattern": re.compile(r'user/\*\.(read|write|\*)'),
        "category": "fhir_scope",
        "cfr": "45 CFR §164.502(b) (Minimum Necessary)",
        "false_positive_hints": [
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },
    {
        "id": "FHIR-003",
        "name": "FHIR endpoint over HTTP (not HTTPS)",
        "description": "FHIR base URL uses unencrypted HTTP",
        "severity": "critical",
        "confidence": 0.85,
        "pattern": re.compile(r'http://[A-Za-z0-9\-_\.]+(/fhir|/R4|/api/FHIR)', re.I),
        "category": "encryption",
        "cfr": "45 CFR §164.312(e)(1) (Transmission Security)",
        "false_positive_hints": [
            re.compile(r'localhost|127\.0\.0\.1|0\.0\.0\.0'),  # local dev is OK
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },

    # ── Audit Gaps (AST-based — pattern is None; ast_check triggers) ─────────

    {
        "id": "AUDIT-001",
        "name": "PHI access without audit log",
        "description": "Function accesses PHI-adjacent resource without audit_log call",
        "severity": "high",
        "confidence": 0.65,
        "pattern": None,
        "ast_check": "check_audit_log_presence",
        "category": "audit_gap",
        "cfr": "45 CFR §164.312(b) (Audit Controls)",
        "false_positive_hints": [],
    },
    {
        "id": "AUDIT-002",
        "name": "PHI returned in HTTP response without encryption check",
        "description": "Endpoint returns PHI fields without TLS/encryption assertion",
        "severity": "medium",
        "confidence": 0.55,
        "pattern": None,
        "ast_check": "check_phi_response_encryption",
        "category": "audit_gap",
        "cfr": "45 CFR §164.312(e)(1)",
        "false_positive_hints": [],
    },

    # ── Encryption ────────────────────────────────────────────────────────────

    {
        "id": "ENC-001",
        "name": "PHI written to unencrypted file",
        "description": "PHI field written to a file path without encryption context",
        "severity": "high",
        "confidence": 0.60,
        "pattern": re.compile(
            r'(?i)(open\(|with open\(|write\(|to_csv\(|to_json\()'
            r'.*'
            r'(patient|phi|ssn|mrn|dob|medical_record)',
            re.DOTALL
        ),
        "category": "encryption",
        "cfr": "45 CFR §164.312(a)(2)(iv)",
        "false_positive_hints": [
            re.compile(r'encrypt|cipher|fernet|aes|pgp|gpg', re.I),
            re.compile(r'test|mock|fake|dummy|example|fixture|sample', re.I),
        ],
    },
]


def get_rule_by_id(rule_id: str) -> dict | None:
    return next((r for r in RULES if r["id"] == rule_id), None)


def get_rules_by_category(category: str) -> list[dict]:
    return [r for r in RULES if r["category"] == category]
