from __future__ import annotations
"""
phi_safe_handler.py

All file I/O in HIPAA-Guard routes through this module.
PHI values are redacted before being written to logs, state files, or LLM prompts.
Code structure (variable names, line numbers, function calls) is preserved.
Raw PHI never leaves this process in readable form.
"""

import re
import hashlib
from pathlib import Path
from typing import Optional

# ── PHI redaction patterns ────────────────────────────────────────────────────
# Matches the VALUE only; surrounding code structure is preserved.

_PHI_VALUE_PATTERNS = [
    # SSN  (123-45-6789 or 123456789)
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    (re.compile(r'\b\d{9}\b(?=\s*[,\)\]\}\"\'])'), '[REDACTED_SSN]'),

    # Date of birth — ISO and common formats
    (re.compile(r'\b(19|20)\d{2}[/-](0[1-9]|1[0-2])[/-](0[1-9]|[12]\d|3[01])\b'), '[REDACTED_DOB]'),
    (re.compile(r'\b(0[1-9]|1[0-2])[/-](0[1-9]|[12]\d|3[01])[/-](19|20)\d{2}\b'), '[REDACTED_DOB]'),

    # MRN — typical formats (6-10 digits preceded by MRN keyword or context)
    (re.compile(r'\b(MRN|mrn|medical_record_number|patient_id)[:\s#="\']+([\d\-]{6,12})\b'), '[REDACTED_MRN]'),

    # NPI — exactly 10 digits preceded by NPI keyword
    (re.compile(r'\b(NPI|npi)[:\s#="\']+([\d]{10})\b'), '[REDACTED_NPI]'),

    # DEA number (2 letters + 7 digits)
    (re.compile(r'\b[A-Z]{2}\d{7}\b'), '[REDACTED_DEA]'),

    # Healthcare email in string literals — redact local part only
    (re.compile(r'(?<=["\'])([a-zA-Z0-9._%+\-]+)(?=@(?:hospital|health|clinic|med|care|doctor|patient)[a-z.]*["\'])'), '[REDACTED_EMAIL_LOCAL]'),

    # Phone numbers in clinical context
    (re.compile(r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[REDACTED_PHONE]'),

    # Bearer tokens / FHIR access tokens (long alphanumeric strings after "Bearer")
    (re.compile(r'(?i)(bearer\s+)[A-Za-z0-9\-_\.]{20,}'), r'\1[REDACTED_TOKEN]'),

    # FHIR client_secret / client_id values in string literals
    (re.compile(r'(?i)(client_secret|client_id|api_key|api_secret|access_token|refresh_token)\s*[=:]\s*["\'][A-Za-z0-9\-_\.]{8,}["\']'),
     r'\1=[REDACTED_CREDENTIAL]'),
]

# Fingerprint cache: sha256(original_value) → placeholder
# Lets us track which redactions correspond to the same original value
# without storing the original value.
_fingerprint_cache: dict[str, str] = {}


def redact(content: str) -> str:
    """
    Apply all PHI redaction patterns to `content`.
    Returns the redacted string. The original is never stored or logged.
    """
    result = content
    for pattern, replacement in _PHI_VALUE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_with_fingerprints(content: str) -> tuple[str, dict[str, str]]:
    """
    Like redact(), but also returns a fingerprint map:
      { sha256(original_matched_value)[:8] → placeholder_used }
    Allows downstream agents to refer to "the same PHI instance" without
    ever reconstructing the original value.
    """
    result = content
    fingerprints: dict[str, str] = {}

    for pattern, placeholder in _PHI_VALUE_PATTERNS:
        for match in pattern.finditer(content):
            raw = match.group(0)
            fp = hashlib.sha256(raw.encode()).hexdigest()[:8]
            fingerprints[fp] = placeholder if isinstance(placeholder, str) else placeholder

        result = pattern.sub(placeholder, result)

    return result, fingerprints


def read_file_safe(path: str | Path, context_lines: int = 0,
                   center_line: Optional[int] = None) -> str:
    """
    Read a file and immediately redact PHI from its content.

    Args:
        path: File to read.
        context_lines: If > 0 and center_line is set, return only
                       [center_line - context_lines : center_line + context_lines].
                       Line numbers are 1-indexed.
        center_line: Center of the context window (1-indexed).

    Returns:
        Redacted file content (or a redacted context window).
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {path}")

    raw = p.read_text(encoding='utf-8', errors='replace')

    if context_lines > 0 and center_line is not None:
        lines = raw.splitlines(keepends=True)
        start = max(0, center_line - 1 - context_lines)
        end = min(len(lines), center_line + context_lines)
        raw = ''.join(lines[start:end])

    return redact(raw)


def safe_log_value(value: str) -> str:
    """
    Produce a safe representation of any value for logging.
    If the value contains PHI patterns, redact it first.
    """
    return redact(str(value))


def assert_no_phi_in_string(text: str, label: str = "") -> None:
    """
    Raise AssertionError if any PHI pattern matches in `text`.
    Used in integration tests to verify PHI never escapes to LLM prompts or logs.
    """
    redacted = redact(text)
    if redacted != text:
        raise AssertionError(
            f"PHI detected in {'`' + label + '`' if label else 'string'} after redaction. "
            f"Content was modified — raw PHI was present."
        )
