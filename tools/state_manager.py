from __future__ import annotations
"""
state_manager.py

Typed shared state for HIPAA-Guard scan sessions.
All agents read from and write to this state through this module.
Routing logic lives in the orchestrator, not here.
"""

import json
import uuid
import tempfile
import shutil
import atexit
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone


# ── Enums ─────────────────────────────────────────────────────────────────────

class ScanTrigger(str, Enum):
    PRE_COMMIT = "pre_commit"
    CI = "ci"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class ScanStatus(str, Enum):
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    FIXING = "fixing"
    REVIEWING = "reviewing"
    VERIFYING = "verifying"
    EDUCATING = "educating"
    TRENDING = "trending"
    COMPLETE = "complete"
    FAILED = "failed"
    HUMAN_REQUIRED = "human_required"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskTier(str, Enum):
    LOW = "low"        # auto-apply after Verifier confirms clean
    MEDIUM = "medium"  # propose + single-keypress confirmation
    HIGH = "high"      # propose only, require explicit approval


class ReviewDecisionType(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    MODIFY = "modify"


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class RawFinding:
    finding_id: str
    rule_id: str
    rule_name: str
    severity: Severity
    confidence: float          # 0.0 – 1.0
    file_path: str
    line_number: int
    column: int
    matched_pattern: str       # the rule pattern name, NOT the matched PHI value
    code_context: str          # redacted ±5 lines around the finding
    phi_fingerprint: Optional[str] = None  # sha256[:8] of matched value, if PHI


@dataclass
class TriagedFinding:
    finding_id: str
    raw_finding: RawFinding
    is_real_violation: bool
    confidence: float
    reasoning: str             # analyst's reasoning (no PHI values)
    analyst_severity: Severity  # may differ from scanner severity after analysis


@dataclass
class FixProposal:
    finding_id: str
    violation_type: str
    original_file: str
    proposed_diff: str         # unified diff format
    fix_rationale: str
    risk_tier: RiskTier
    test_suggestion: Optional[str] = None  # for MEDIUM/HIGH risk fixes


@dataclass
class ReviewDecision:
    finding_id: str
    decision: ReviewDecisionType
    objections: list[str] = field(default_factory=list)
    modified_diff: Optional[str] = None   # only set if decision == MODIFY
    iteration: int = 1


@dataclass
class VerificationResult:
    finding_id: str
    resolved: bool
    new_findings: list[RawFinding] = field(default_factory=list)


@dataclass
class Education:
    finding_id: str
    rule_id: str
    plain_english: str
    cfr_citation: str          # e.g., "45 CFR §164.312(b)"
    remediation_steps: list[str] = field(default_factory=list)
    reference_url: Optional[str] = None


@dataclass
class AgentError:
    agent_name: str
    error_type: str
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    traceback: Optional[str] = None


@dataclass
class ScanState:
    session_id: str
    trigger: ScanTrigger
    target_files: list[str]
    created_at: str
    status: ScanStatus = ScanStatus.SCANNING
    loop_count: int = 0

    # Pipeline outputs (each agent writes its section)
    scanner_output: list[RawFinding] = field(default_factory=list)
    analyst_output: list[TriagedFinding] = field(default_factory=list)
    fix_proposals: list[FixProposal] = field(default_factory=list)
    reviewer_decisions: list[ReviewDecision] = field(default_factory=list)
    verifier_output: list[VerificationResult] = field(default_factory=list)
    educator_output: list[Education] = field(default_factory=list)

    # Applied fixes (diffs written to disk after approval)
    applied_fixes: list[str] = field(default_factory=list)   # finding_ids
    pending_fixes: list[str] = field(default_factory=list)   # finding_ids awaiting human input

    errors: list[AgentError] = field(default_factory=list)

    # Summary computed at completion
    summary: dict = field(default_factory=dict)


# ── State file I/O ─────────────────────────────────────────────────────────────

_SESSION_DIR: Optional[Path] = None
_STATE_FILE: Optional[Path] = None


def _nested_to_dataclass(d, cls):
    """Recursively reconstruct dataclasses from dicts (simple version)."""
    if not isinstance(d, dict):
        return d
    hints = cls.__dataclass_fields__
    kwargs = {}
    for key, val in d.items():
        if key not in hints:
            continue
        field_type = hints[key].type
        # Handle list of dataclass
        if isinstance(val, list) and val and isinstance(val[0], dict):
            # Best-effort: map known field types
            inner_map = {
                'scanner_output': RawFinding,
                'analyst_output': TriagedFinding,
                'fix_proposals': FixProposal,
                'reviewer_decisions': ReviewDecision,
                'verifier_output': VerificationResult,
                'educator_output': Education,
                'errors': AgentError,
                'new_findings': RawFinding,
                'remediation_steps': None,
            }
            inner_cls = inner_map.get(key)
            if inner_cls:
                val = [_nested_to_dataclass(item, inner_cls) for item in val]
        elif isinstance(val, dict):
            inner_map = {'raw_finding': RawFinding}
            inner_cls = inner_map.get(key)
            if inner_cls:
                val = _nested_to_dataclass(val, inner_cls)
        kwargs[key] = val
    return cls(**kwargs)


def new_session(trigger: ScanTrigger, target_files: list[str]) -> ScanState:
    """Create a new scan session. Sets up the ephemeral temp directory."""
    global _SESSION_DIR, _STATE_FILE

    session_id = str(uuid.uuid4())
    _SESSION_DIR = Path(tempfile.mkdtemp(prefix=f"hipaa_guard_{session_id[:8]}_"))
    _STATE_FILE = _SESSION_DIR / "scan_state.json"

    # Clean up temp dir on exit
    atexit.register(_cleanup_session)

    state = ScanState(
        session_id=session_id,
        trigger=trigger,
        target_files=target_files,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    _write(state)
    return state


def load() -> ScanState:
    """Load current session state from disk."""
    if _STATE_FILE is None or not _STATE_FILE.exists():
        raise RuntimeError("No active scan session. Call new_session() first.")
    raw = json.loads(_STATE_FILE.read_text())
    return _nested_to_dataclass(raw, ScanState)


def save(state: ScanState) -> None:
    """Persist state to disk."""
    _write(state)


def update_status(status: ScanStatus) -> ScanState:
    """Convenience: load, update status, save, return updated state."""
    state = load()
    state.status = status
    save(state)
    return state


def append_error(error: AgentError) -> None:
    """Append an agent error to the current session state."""
    state = load()
    state.errors.append(error)
    save(state)


def get_state_file_path() -> Optional[Path]:
    return _STATE_FILE


def _write(state: ScanState) -> None:
    if _STATE_FILE is None:
        raise RuntimeError("No active scan session.")

    def _serialize(obj):
        if hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)
        if isinstance(obj, Enum):
            return obj.value
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    _STATE_FILE.write_text(json.dumps(asdict(state), indent=2, default=lambda o: o.value if isinstance(o, Enum) else o))


def _cleanup_session() -> None:
    global _SESSION_DIR, _STATE_FILE
    if _SESSION_DIR and _SESSION_DIR.exists():
        shutil.rmtree(_SESSION_DIR, ignore_errors=True)
    _SESSION_DIR = None
    _STATE_FILE = None


def attach_to_session(state_file_path: str) -> ScanState:
    """
    Attach to an existing session (e.g., when orchestrator spawns sub-processes).
    """
    global _STATE_FILE, _SESSION_DIR
    _STATE_FILE = Path(state_file_path)
    _SESSION_DIR = _STATE_FILE.parent
    return load()
