"""
Scanner rule tests — zero LLM calls, uses the bundled test fixture.
"""
from pathlib import Path
import pytest

from hipaa_guard.tools.scanner import scan_files

FIXTURE = str(Path(__file__).parent.parent / ".tmp" / "test_phi_sample.py")


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_fixture_exists():
    assert Path(FIXTURE).exists(), f"Test fixture not found at {FIXTURE}"


def test_cred001_hardcoded_secret():
    findings = scan_files([FIXTURE])
    assert "CRED-001" in _rule_ids(findings), "Should detect hardcoded FHIR client_secret"


def test_phi001_ssn():
    findings = scan_files([FIXTURE])
    assert "PHI-001" in _rule_ids(findings), "Should detect SSN pattern"


def test_fhir001_wildcard_scope():
    findings = scan_files([FIXTURE])
    assert "FHIR-001" in _rule_ids(findings), "Should detect patient/* wildcard scope"


def test_returns_raw_findings_with_required_fields():
    findings = scan_files([FIXTURE])
    assert len(findings) > 0
    for f in findings:
        assert f.finding_id
        assert f.rule_id
        assert f.file_path
        assert f.line_number > 0
        assert 0.0 <= f.confidence <= 1.0


def test_no_findings_on_clean_file(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("def add(a, b):\n    return a + b\n")
    findings = scan_files([str(clean)])
    assert findings == [], f"Expected no findings on clean file, got {findings}"
