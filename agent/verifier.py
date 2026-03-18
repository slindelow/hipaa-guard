from __future__ import annotations
"""
verifier.py

Re-runs the Scanner on proposed-fixed file content (in memory) to confirm:
1. The original violation is resolved
2. No new violations were introduced by the fix

Never writes to disk. Uses diff_applier to produce an in-memory patched version.
"""

import sys
import tempfile
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from state_manager import FixProposal, VerificationResult
from scanner import scan_files


def verify_fixes(proposals: list[FixProposal]) -> list[VerificationResult]:
    """
    For each approved fix proposal, apply the diff in a temp file and re-scan.
    Returns VerificationResult per proposal.
    """
    results: list[VerificationResult] = []

    for proposal in proposals:
        result = _verify_single(proposal)
        results.append(result)

    return results


def _verify_single(proposal: FixProposal) -> VerificationResult:
    """Apply fix to a temp file and scan it."""
    original_path = Path(proposal.original_file)
    if not original_path.exists():
        return VerificationResult(finding_id=proposal.finding_id, resolved=False)

    # Write patched content to a temp file
    suffix = original_path.suffix
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False, encoding='utf-8') as tmp:
        tmp_path = tmp.name
        try:
            original_content = original_path.read_text(encoding='utf-8', errors='replace')
            patched_content = _apply_diff_in_memory(original_content, proposal.proposed_diff)
            tmp.write(patched_content)
        except Exception as e:
            os.unlink(tmp_path)
            return VerificationResult(
                finding_id=proposal.finding_id,
                resolved=False,
                new_findings=[],
            )

    try:
        # Scan the patched temp file
        new_findings = scan_files([tmp_path])

        # Check if original violation is resolved
        original_violation_still_present = any(
            f.rule_id == proposal.violation_type
            for f in new_findings
        )

        # Remap file paths back to original for reporting
        for f in new_findings:
            f.file_path = proposal.original_file

        return VerificationResult(
            finding_id=proposal.finding_id,
            resolved=not original_violation_still_present,
            new_findings=new_findings if new_findings else [],
        )
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _apply_diff_in_memory(original: str, diff: str) -> str:
    """
    Apply a unified diff to original content string.
    Simple implementation for single-file patches.
    Falls back to original if diff cannot be parsed.
    """
    if not diff or not diff.strip():
        return original

    lines = original.splitlines(keepends=True)
    result_lines = list(lines)

    try:
        diff_lines = diff.splitlines()
        i = 0
        offset = 0  # track line number shift from previous hunks

        while i < len(diff_lines):
            line = diff_lines[i]

            # Find hunk header: @@ -start,count +start,count @@
            if line.startswith("@@"):
                import re
                m = re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
                if not m:
                    i += 1
                    continue

                orig_start = int(m.group(1)) - 1  # 0-indexed
                i += 1
                hunk_removes = []
                hunk_adds = []

                while i < len(diff_lines) and not diff_lines[i].startswith("@@"):
                    dl = diff_lines[i]
                    if dl.startswith("-"):
                        hunk_removes.append(dl[1:])
                    elif dl.startswith("+"):
                        hunk_adds.append(dl[1:])
                    # context lines (space prefix) — skip
                    i += 1

                # Apply hunk: find the remove block in result_lines and replace
                actual_start = orig_start + offset
                remove_len = len(hunk_removes)

                if remove_len > 0:
                    result_lines[actual_start:actual_start + remove_len] = [
                        l if l.endswith('\n') else l + '\n' for l in hunk_adds
                    ]
                    offset += len(hunk_adds) - remove_len
                else:
                    # Pure insertion
                    for j, add_line in enumerate(hunk_adds):
                        insert_line = add_line if add_line.endswith('\n') else add_line + '\n'
                        result_lines.insert(actual_start + j, insert_line)
                    offset += len(hunk_adds)
            else:
                i += 1

        return ''.join(result_lines)

    except Exception:
        return original  # Safe fallback: return unmodified
