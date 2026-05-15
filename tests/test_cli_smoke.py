"""
CLI smoke tests — verify the entry point works end-to-end without API calls.
"""
import subprocess
import sys
from pathlib import Path

FIXTURE = str(Path(__file__).parent.parent / ".tmp" / "test_phi_sample.py")


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "hipaa_guard.cli", *args],
        capture_output=True, text=True
    )


def test_help_exits_zero():
    result = _run("--help")
    assert result.returncode == 0
    assert "hipaa-guard" in result.stdout.lower() or "usage" in result.stdout.lower()


def test_scan_finds_violations_in_fixture():
    result = _run("scan", FIXTURE)
    # Should find violations and print them; exit 0 because onboarding_mode defaults to True
    assert "Finding" in result.stdout or "CRED" in result.stdout or "PHI" in result.stdout or "FHIR" in result.stdout


def test_scan_clean_file_exits_zero(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1\n")
    result = _run("scan", str(clean))
    assert result.returncode == 0
    assert "No findings" in result.stdout
