from __future__ import annotations
"""
scanner.py

Core detection engine — no LLM calls.
Runs regex patterns from phi_pattern_library.py and AST-based checks.
Must complete in under 10 seconds for typical PR diffs.

Output: list[RawFinding] written to state_manager.scanner_output
"""

import ast
import sys
import uuid
import hashlib
from pathlib import Path

from hipaa_guard.tools.phi_pattern_library import RULES
from hipaa_guard.tools.phi_safe_handler import redact
from hipaa_guard.tools.state_manager import RawFinding, Severity


# ── Context extraction ────────────────────────────────────────────────────────

def _extract_context(lines: list[str], line_idx: int, window: int = 5) -> str:
    """Return ±window lines around line_idx, redacted."""
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window + 1)
    snippet = ''.join(lines[start:end])
    return redact(snippet)


def _phi_fingerprint(matched_value: str) -> str:
    return hashlib.sha256(matched_value.encode()).hexdigest()[:8]


# ── False positive pre-filter ─────────────────────────────────────────────────

def _is_likely_false_positive(rule: dict, line: str, context: str) -> bool:
    """
    Check false_positive_hints against the matched line and surrounding context.
    Returns True if any hint matches — confidence should be reduced or finding skipped.
    """
    for hint_pattern in rule.get("false_positive_hints", []):
        if hint_pattern.search(line) or hint_pattern.search(context):
            return True
    return False


# ── Regex-based scanning ──────────────────────────────────────────────────────

def scan_file_regex(file_path: str) -> list[RawFinding]:
    """Scan a single file using all regex-based rules."""
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return []

    try:
        raw_content = p.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return []

    lines = raw_content.splitlines(keepends=True)
    findings: list[RawFinding] = []

    for rule in RULES:
        if rule.get("pattern") is None:
            continue  # AST-based rule; handled separately

        pattern = rule["pattern"]

        for line_idx, line in enumerate(lines):
            for match in pattern.finditer(line):
                context = _extract_context(lines, line_idx)

                # Apply false positive hints — reduce confidence but don't drop
                base_confidence = rule["confidence"]
                if _is_likely_false_positive(rule, line, context):
                    adjusted_confidence = base_confidence * 0.4  # well below 0.85 → Analyst handles
                else:
                    adjusted_confidence = base_confidence

                matched_value = match.group(0)
                finding = RawFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=Severity(rule["severity"]),
                    confidence=adjusted_confidence,
                    file_path=str(p),
                    line_number=line_idx + 1,
                    column=match.start(),
                    matched_pattern=rule["id"],  # pattern ID, not matched PHI
                    code_context=context,
                    phi_fingerprint=_phi_fingerprint(matched_value) if rule["category"] == "phi_value" else None,
                )
                findings.append(finding)

    return findings


# ── AST-based checks ──────────────────────────────────────────────────────────

_PHI_VAR_NAMES = {
    'patient_name', 'patient_id', 'ssn', 'mrn', 'dob', 'date_of_birth',
    'birth_date', 'first_name', 'last_name', 'full_name', 'patient',
    'medical_record_number', 'npi', 'patient_email', 'patient_phone',
}

_LOGGER_NAMES = {'log', 'logger', 'logging', 'print', 'console'}
_AUDIT_NAMES = {'audit_log', 'audit', 'audit_trail', 'access_log', 'hipaa_log'}


def check_audit_log_presence(file_path: str, lines: list[str]) -> list[RawFinding]:
    """
    AST check: find functions that access PHI variables but don't call an audit logger.
    Rule AUDIT-001.
    """
    findings = []
    try:
        tree = ast.parse(''.join(lines), filename=file_path)
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Check if this function touches PHI names
        phi_accesses = []
        audit_calls = []

        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in _PHI_VAR_NAMES:
                phi_accesses.append(child)
            if isinstance(child, ast.Attribute) and child.attr in {'info', 'debug', 'warning', 'error', 'critical'}:
                if isinstance(child.value, ast.Name) and child.value.id in _LOGGER_NAMES:
                    # This is a log call — check if the argument is a PHI var
                    pass  # handled by regex PHI-004
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name) and child.func.id in _AUDIT_NAMES:
                    audit_calls.append(child)
                if isinstance(child.func, ast.Attribute) and child.func.attr in {'record', 'log_access', 'track'}:
                    if isinstance(child.func.value, ast.Name) and child.func.value.id in _AUDIT_NAMES:
                        audit_calls.append(child)

        if phi_accesses and not audit_calls:
            context = _extract_context(lines, node.lineno - 1)
            findings.append(RawFinding(
                finding_id=str(uuid.uuid4())[:8],
                rule_id="AUDIT-001",
                rule_name="PHI access without audit log",
                severity=Severity.HIGH,
                confidence=0.65,
                file_path=file_path,
                line_number=node.lineno,
                column=0,
                matched_pattern="AUDIT-001",
                code_context=context,
            ))

    return findings


def check_phi_response_encryption(file_path: str, lines: list[str]) -> list[RawFinding]:
    """
    AST check: find HTTP response functions that return PHI fields without encryption markers.
    Rule AUDIT-002.
    """
    findings = []
    try:
        tree = ast.parse(''.join(lines), filename=file_path)
    except SyntaxError:
        return []

    _RESPONSE_FUNCS = {'jsonify', 'Response', 'JSONResponse', 'make_response', 'return'}
    _ENCRYPT_MARKERS = {'encrypt', 'cipher', 'fernet', 'aes', 'pgp', 'gpg', 'tls', 'ssl'}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        has_phi = any(
            isinstance(child, ast.Name) and child.id in _PHI_VAR_NAMES
            for child in ast.walk(node)
        )
        has_return_phi = False
        has_encryption = False

        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                # Check if return value references PHI
                for subchild in ast.walk(child.value):
                    if isinstance(subchild, ast.Name) and subchild.id in _PHI_VAR_NAMES:
                        has_return_phi = True
            if isinstance(child, ast.Name) and child.id in _ENCRYPT_MARKERS:
                has_encryption = True
            if isinstance(child, ast.Attribute) and child.attr in _ENCRYPT_MARKERS:
                has_encryption = True

        if has_phi and has_return_phi and not has_encryption:
            context = _extract_context(lines, node.lineno - 1)
            findings.append(RawFinding(
                finding_id=str(uuid.uuid4())[:8],
                rule_id="AUDIT-002",
                rule_name="PHI returned in HTTP response without encryption check",
                severity=Severity.MEDIUM,
                confidence=0.55,
                file_path=file_path,
                line_number=node.lineno,
                column=0,
                matched_pattern="AUDIT-002",
                code_context=context,
            ))

    return findings


# ── Main scan entry point ─────────────────────────────────────────────────────

def scan_files(file_paths: list[str]) -> list[RawFinding]:
    """
    Scan a list of files. Returns all raw findings across all files.
    Deduplicates findings at the same file:line:rule.
    """
    all_findings: list[RawFinding] = []
    seen: set[tuple] = set()

    for file_path in file_paths:
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            continue

        # Skip non-text files and known safe extensions
        _SKIP_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip',
                            '.tar', '.gz', '.pyc', '.pem', '.key', '.crt'}
        if p.suffix.lower() in _SKIP_EXTENSIONS:
            continue

        # Regex scan
        regex_findings = scan_file_regex(file_path)
        for f in regex_findings:
            key = (f.file_path, f.line_number, f.rule_id)
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

        # AST scan (Python files only)
        if p.suffix == '.py':
            try:
                lines = p.read_text(encoding='utf-8', errors='replace').splitlines(keepends=True)
                ast_findings = check_audit_log_presence(file_path, lines)
                ast_findings += check_phi_response_encryption(file_path, lines)
                for f in ast_findings:
                    key = (f.file_path, f.line_number, f.rule_id)
                    if key not in seen:
                        seen.add(key)
                        all_findings.append(f)
            except Exception:
                pass

    # Sort: critical/high first, then by file + line
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_findings.sort(key=lambda f: (severity_order.get(f.severity.value, 5), f.file_path, f.line_number))
    return all_findings


if __name__ == "__main__":
    # Quick CLI test: python scanner.py <file1> [file2 ...]
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <file1> [file2 ...]")
        sys.exit(1)

    results = scan_files(sys.argv[1:])
    if not results:
        print("✅ No findings.")
    else:
        for f in results:
            print(f"[{f.severity.value.upper()}] {f.rule_id} | {f.file_path}:{f.line_number} | {f.rule_name} (confidence: {f.confidence:.0%})")
            print(f"  Context:\n{f.code_context}")
            print()
