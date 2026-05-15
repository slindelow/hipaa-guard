from __future__ import annotations
"""
orchestrator.py

Deterministic pipeline dispatcher for HIPAA-Guard.
This is NOT an LLM. It reads ScanState.status and routes to the next agent.
LLM agents are called as functions — no async queuing needed for MVP.

Pipeline:
  Scanner (in scanner.py / cli.py) → Analyst → [Fix + Educator (parallel)] → Reviewer → Verifier → Trend
"""

import threading
import traceback

import hipaa_guard.tools.state_manager as sm
from hipaa_guard.tools.state_manager import (
    ScanState, ScanStatus, RawFinding, AgentError,
    TriagedFinding, FixProposal, ReviewDecision, ReviewDecisionType,
    VerificationResult, RiskTier
)


def run_pipeline(
    state: ScanState,
    raw_findings: list[RawFinding],
    anthropic_key: str,
    config: dict,
    rule_config: dict,
) -> ScanState:
    """
    Run the full multi-agent pipeline given initial scanner findings.
    Returns the completed state.
    """
    # Write scanner output to state
    state.scanner_output = raw_findings
    sm.save(state)

    analyst_threshold = rule_config.get("confidence_threshold_analyst", 0.85)
    max_iterations = rule_config.get("max_fix_loop_iterations", 3)

    # ── Step 1: Analyst Agent ─────────────────────────────────────────────
    print("  [1/5] Analyst Agent — disambiguating findings...")
    state = sm.update_status(ScanStatus.ANALYZING)

    try:
        from analyst_agent import analyze
        triaged = analyze(raw_findings, anthropic_key, config, analyst_threshold)
        state = sm.load()
        state.analyst_output = triaged
        sm.save(state)
    except Exception as e:
        _record_error(state, "AnalystAgent", e)
        # Conservative fallback: treat all ambiguous as confirmed
        state = sm.load()
        state.analyst_output = [
            TriagedFinding(
                finding_id=f.finding_id,
                raw_finding=f,
                is_real_violation=True,
                confidence=f.confidence,
                reasoning="Analyst unavailable — conservative fallback: treating as confirmed",
                analyst_severity=f.severity,
            )
            for f in raw_findings
        ]
        sm.save(state)

    confirmed = [t for t in state.analyst_output if t.is_real_violation]
    if not confirmed:
        print("  ✅ Analyst found no confirmed violations.")
        return _finalize(state)

    print(f"  ✅ Analyst confirmed {len(confirmed)} violation(s).")

    # ── Step 2: Fix Agent + Educator Agent (parallel) ─────────────────────
    print("  [2/5] Fix Agent + Educator Agent (parallel)...")
    state = sm.update_status(ScanStatus.FIXING)

    fix_proposals: list[FixProposal] = []
    educator_output = []
    fix_error = None
    edu_error = None

    def run_fix():
        nonlocal fix_proposals, fix_error
        try:
            from fix_agent import propose_fixes
            fix_proposals = propose_fixes(confirmed, anthropic_key, config, rule_config)
        except Exception as e:
            fix_error = e

    def run_educator():
        nonlocal educator_output, edu_error
        try:
            from educator_agent import educate
            educator_output = educate(confirmed, anthropic_key)
        except Exception as e:
            edu_error = e

    t_fix = threading.Thread(target=run_fix)
    t_edu = threading.Thread(target=run_educator)
    t_fix.start()
    t_edu.start()
    t_fix.join()
    t_edu.join()

    if fix_error:
        _record_error(state, "FixAgent", fix_error)
        print("  ⚠  Fix Agent failed — outputting violations for manual remediation.")
    if edu_error:
        _record_error(state, "EducatorAgent", edu_error)
        print("  ⚠  Educator Agent failed — continuing without regulatory explanations.")

    state = sm.load()
    state.fix_proposals = fix_proposals
    state.educator_output = educator_output
    sm.save(state)

    print(f"  ✅ {len(fix_proposals)} fix(es) proposed. {len(educator_output)} explanation(s) generated.")

    if not fix_proposals:
        _print_educator_output(educator_output)
        return _finalize(state)

    # ── Step 3: Reviewer → Verifier loop ─────────────────────────────────
    print("  [3/5] Reviewer Agent (adversarial critique)...")
    state = sm.update_status(ScanStatus.REVIEWING)

    remaining_proposals = list(fix_proposals)
    final_approved: list[FixProposal] = []
    state.loop_count = 0

    while remaining_proposals and state.loop_count < max_iterations:
        state.loop_count += 1
        sm.save(state)

        try:
            from reviewer_agent import review
            decisions = review(remaining_proposals, confirmed, anthropic_key)
            state = sm.load()
            state.reviewer_decisions.extend(decisions)
            sm.save(state)
        except Exception as e:
            _record_error(state, "ReviewerAgent", e)
            # Fallback: treat all as MEDIUM risk requiring human confirmation
            decisions = [
                ReviewDecision(
                    finding_id=p.finding_id,
                    decision=ReviewDecisionType.APPROVE,
                    iteration=state.loop_count,
                )
                for p in remaining_proposals
            ]
            # Escalate all to MEDIUM
            for p in remaining_proposals:
                p.risk_tier = RiskTier.MEDIUM

        approved_this_round = []
        rejected_this_round = []

        for decision in decisions:
            proposal = next((p for p in remaining_proposals if p.finding_id == decision.finding_id), None)
            if not proposal:
                continue

            if decision.decision == ReviewDecisionType.APPROVE:
                approved_this_round.append(proposal)
            elif decision.decision == ReviewDecisionType.MODIFY and decision.modified_diff:
                proposal.proposed_diff = decision.modified_diff
                approved_this_round.append(proposal)
            else:  # REJECT
                if state.loop_count >= max_iterations:
                    proposal_copy = proposal
                    state = sm.load()
                    state.pending_fixes.append(proposal_copy.finding_id)
                    sm.save(state)
                    print(f"    ⚠  Finding {proposal.finding_id} escalated to HUMAN_REQUIRED after {max_iterations} iterations.")
                else:
                    rejected_this_round.append(proposal)

        # ── Verifier step ─────────────────────────────────────────────────
        if approved_this_round:
            print(f"  [4/5] Verifier Agent — re-scanning {len(approved_this_round)} fix(es)...")
            state = sm.update_status(ScanStatus.VERIFYING)

            try:
                from verifier import verify_fixes
                verification_results = verify_fixes(approved_this_round)
                state = sm.load()
                state.verifier_output.extend(verification_results)
                sm.save(state)
            except Exception as e:
                _record_error(state, "Verifier", e)
                # Escalate to MEDIUM on verifier failure
                for p in approved_this_round:
                    p.risk_tier = RiskTier.MEDIUM
                verification_results = [
                    VerificationResult(finding_id=p.finding_id, resolved=True)
                    for p in approved_this_round
                ]

            for vr in verification_results:
                proposal = next((p for p in approved_this_round if p.finding_id == vr.finding_id), None)
                if not proposal:
                    continue
                if vr.resolved and not vr.new_findings:
                    final_approved.append(proposal)
                else:
                    # New findings introduced by the fix — re-enter loop
                    if state.loop_count < max_iterations:
                        rejected_this_round.append(proposal)
                    else:
                        state = sm.load()
                        state.pending_fixes.append(proposal.finding_id)
                        sm.save(state)

        remaining_proposals = rejected_this_round

    # ── Step 4: Apply approved fixes ──────────────────────────────────────
    if final_approved:
        print(f"\n  [5/5] Applying {len(final_approved)} approved fix(es)...")
        _apply_fixes(final_approved, state, rule_config)

    # ── Print educator output ─────────────────────────────────────────────
    _print_educator_output(educator_output)

    return _finalize(state)


def _apply_fixes(proposals: list[FixProposal], state: ScanState, rule_config: dict) -> None:
    """Apply fixes based on risk tier — auto or prompt for confirmation."""
    auto_tier = rule_config.get("auto_apply_threshold", "low")
    tier_order = {"low": 0, "medium": 1, "high": 2}
    auto_max = tier_order.get(auto_tier, 0)

    for proposal in proposals:
        tier_val = tier_order.get(proposal.risk_tier.value, 2)

        if tier_val <= auto_max:
            _write_fix(proposal)
            state = sm.load()
            state.applied_fixes.append(proposal.finding_id)
            sm.save(state)
            print(f"    ✅ Auto-applied fix for {proposal.finding_id} [{proposal.risk_tier.value.upper()} risk]")
        elif tier_val == 1:  # MEDIUM — prompt
            print(f"\n    Fix for {proposal.finding_id} [{proposal.risk_tier.value.upper()} risk]:")
            print(f"    {proposal.fix_rationale}")
            print(f"\n    Diff:\n{proposal.proposed_diff}\n")
            answer = input("    Apply this fix? [y/N] ").strip().lower()
            if answer == 'y':
                _write_fix(proposal)
                state = sm.load()
                state.applied_fixes.append(proposal.finding_id)
                sm.save(state)
                print(f"    ✅ Applied fix for {proposal.finding_id}")
            else:
                print(f"    ⏭  Skipped fix for {proposal.finding_id}")
        else:  # HIGH — propose only
            print(f"\n    Proposed fix for {proposal.finding_id} [{proposal.risk_tier.value.upper()} risk — manual approval required]:")
            print(f"    {proposal.fix_rationale}")
            print(f"\n    Diff:\n{proposal.proposed_diff}\n")
            if proposal.test_suggestion:
                print(f"    Test suggestion: {proposal.test_suggestion}")
            state = sm.load()
            state.pending_fixes.append(proposal.finding_id)
            sm.save(state)


def _write_fix(proposal: FixProposal) -> None:
    """Apply a unified diff to the original file."""
    import subprocess
    import tempfile, os
    with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
        f.write(proposal.proposed_diff)
        patch_file = f.name
    try:
        result = subprocess.run(
            ['patch', '-p1', proposal.original_file, patch_file],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"    ⚠  patch command failed: {result.stderr}")
    finally:
        os.unlink(patch_file)


def _print_educator_output(educator_output) -> None:
    if not educator_output:
        return
    print(f"\n  📚 Regulatory Context")
    print("  " + "─" * 56)
    for edu in educator_output:
        print(f"\n  [{edu.rule_id}] {edu.cfr_citation}")
        print(f"  {edu.plain_english}")
        if edu.remediation_steps:
            print("  Remediation:")
            for step in edu.remediation_steps:
                print(f"    • {step}")


def _record_error(state: ScanState, agent_name: str, exc: Exception) -> None:
    error = AgentError(
        agent_name=agent_name,
        error_type=type(exc).__name__,
        message=str(exc),
        traceback=traceback.format_exc(),
    )
    sm.append_error(error)
    print(f"  ⚠  {agent_name} error: {exc}")


def _finalize(state: ScanState) -> ScanState:
    state = sm.load()
    confirmed_count = sum(1 for t in state.analyst_output if t.is_real_violation)
    state.status = ScanStatus.COMPLETE
    state.summary = {
        "total_raw_findings": len(state.scanner_output),
        "confirmed_violations": confirmed_count,
        "applied_fixes": len(state.applied_fixes),
        "pending_human_review": len(state.pending_fixes),
        "errors": len(state.errors),
    }
    sm.save(state)
    return state
