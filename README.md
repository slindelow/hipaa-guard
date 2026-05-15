# HIPAA-Guard

A multi-agent AI system that scans healthcare software codebases for HIPAA violations at commit time. Catches PHI exposure, hardcoded FHIR credentials, overly broad OAuth scopes, missing audit controls, and more — before code ships.

---

## How It Works

HIPAA-Guard runs a 7-agent pipeline triggered by git pre-commit hooks, CI/CD events, or manual CLI commands:

```
[Trigger] → Scanner → Analyst → Fix Agent ──────────────────→ Verifier
                                     │                              │
                               Reviewer Agent ← REJECT/MODIFY      │
                               (adversarial)                        │
                                     │                              │
                               APPROVE ────────────────────→ [Clean? Loop max 3x]

                    Educator Agent (parallel — regulatory citations)
                    Trend Agent (weekly posture reports + drift detection)
```

| Agent | Role | LLM? |
|-------|------|------|
| **Scanner** | Regex + AST detection across 15 HIPAA rules | No — pure Python, <10s |
| **Analyst** | Disambiguates ambiguous findings (test fixture vs real PHI?) | Yes |
| **Fix Agent** | Proposes minimal diffs for confirmed violations | Yes |
| **Reviewer** | Adversarially critiques proposed fixes — finds problems, not validates | Yes |
| **Verifier** | Re-scans fixed file in memory to confirm resolution, no new issues | No |
| **Educator** | Plain-English regulatory explanation with CFR citation per finding | Yes |
| **Trend** | 30-day posture tracking, drift detection, weekly reports | Yes |

---

## What It Detects

| Rule | Description | Severity |
|------|-------------|----------|
| CRED-001 | Hardcoded FHIR `client_secret` | CRITICAL |
| CRED-002 | Hardcoded API key or bearer token | CRITICAL |
| CRED-003 | FHIR URL with embedded credentials | CRITICAL |
| FHIR-003 | FHIR endpoint over HTTP (not HTTPS) | CRITICAL |
| PHI-001 | SSN pattern in source code | HIGH |
| PHI-003 | MRN in string literal | HIGH |
| PHI-004 | Patient name passed directly to logger | HIGH |
| FHIR-001 | SMART on FHIR `patient/*` wildcard scope | HIGH |
| FHIR-002 | SMART on FHIR `user/*` wildcard scope | HIGH |
| AUDIT-001 | PHI accessed in function without audit log call | HIGH |
| PHI-002 | Date of birth in string literal | MEDIUM |
| PHI-006 | PHI interpolated in f-string | MEDIUM |
| AUDIT-002 | PHI returned in HTTP response without encryption check | MEDIUM |
| ENC-001 | PHI written to unencrypted file | HIGH |
| PHI-005 | NPI number in source code | MEDIUM |

---

## Quick Start

**Requirements:** Python 3.9+

```bash
pip install hipaa-guard
```

```bash
# Scan a directory
hipaa-guard scan /path/to/your/healthcare/app

# Install pre-commit hook (blocks commits with CRITICAL/HIGH violations)
hipaa-guard install-hook

# Full repo audit + compliance document
hipaa-guard audit

# Check dependency BAA status
hipaa-guard baa
```

**Enable AI pipeline** (Analyst, Fix Agent, Educator, Reviewer):
```bash
pip install hipaa-guard[ai]
export ANTHROPIC_API_KEY=your_key_here
hipaa-guard scan /path/to/your/app
```

Without an API key, the scanner runs standalone — fast, no API calls, catches all high-confidence violations.

Scan history and feedback logs are stored in `~/.hipaa-guard/`. Per-project config lives in `hipaa-guard.config.json` at your repo root.

---

## PHI Safety Architecture

The system reads source code that may contain PHI. Three layers prevent leakage:

1. **`phi_safe_handler.py` wraps all file I/O** — PHI values are replaced with typed placeholders (`[REDACTED_SSN]`, `[REDACTED_MRN]`) before reaching any log, state file, or LLM prompt. Code structure is preserved; values are not.
2. **Ephemeral session state** — scan state lives in a UUID-scoped temp directory, deleted on completion. Never committed, never uploaded.
3. **LLM prompts use minimum context** — agents receive ±50 lines around a finding with PHI redacted. The system prompt for all LLM agents explicitly prohibits PHI reconstruction.

> **HIPAA BAA note:** If your Anthropic account does not have a signed HIPAA BAA, set `"has_hipaa_baa": false` in `hipaa-guard.config.json`. The system will route all LLM analysis through a local Ollama endpoint instead, keeping all data on-premise.

---

## Differentiating Features

### Dependency BAA Checker
Parses your `requirements.txt` / `package.json` / `pyproject.toml`, cross-references a maintained BAA registry, and identifies which packages actually touch PHI-handling code. No existing tool does this automatically.

```bash
python3 cli.py baa
```

### FHIR Vendor Profile Validation
Validates FHIR resource structures against Epic, Cerner, and base R4 profiles. Catches vendor-specific extension gaps at commit time instead of during EHR sandbox testing (where they cost days to debug).

### Auto-Generated Compliance Documentation
On demand or on release tag, generates a structured HIPAA Technical Safeguards Summary — PHI access points, encryption usage, audit log coverage, FHIR endpoints — mapped to CFR sections. A compliance officer-ready draft in seconds.

### False Positive Learning Loop
Mark a finding as a false positive:
```bash
python3 cli.py fp <finding_id> --reason "test fixture"
```
After 30 days, rules with >30% FP rate have their confidence thresholds automatically adjusted. The scanner self-calibrates without any model fine-tuning.

---

## Configuration

**`hipaa-guard.config.json`** — project-level settings (commit this):
```json
{
  "fhir_targets": ["epic", "cerner"],
  "llm": {
    "provider": "anthropic",
    "model": "claude-sonnet-4-6",
    "has_hipaa_baa": false
  },
  "scan": {
    "onboarding_mode": true
  }
}
```

Set `onboarding_mode: true` on first run — findings are reported but commits are not blocked while you triage false positives.

**`config/rule_config.json`** — per-rule severity, risk tier, confidence thresholds. Updated automatically by the FP feedback loop.

---

## CLI Reference

```
python3 cli.py scan <path> [path2 ...]   Scan files or directories
python3 cli.py audit                     Full repo audit + compliance doc
python3 cli.py fp <finding_id>           Mark finding as false positive
python3 cli.py fn <file> <line>          Report a missed finding
python3 cli.py install-hook              Install pre-commit git hook
python3 cli.py baa                       Check dependency BAA status
```

---

## Project Structure

```
cli.py                      Entry point
hipaa-guard.config.json     Project config (commit this)
config/
  rule_config.json          Rule thresholds and risk tiers
  baa_registry.json         Package → BAA status registry
tools/
  scanner.py                Core detection engine (no LLM)
  phi_pattern_library.py    15 HIPAA detection rules
  phi_safe_handler.py       PHI redaction for all file I/O
  state_manager.py          Typed shared state between agents
  baa_checker.py            Dependency BAA analysis
  compliance_doc_generator.py  HIPAA safeguard summary generator
  git_hook_installer.py     Pre-commit hook setup
  rule_config_updater.py    FP feedback → confidence adjustment
agent/
  orchestrator.py           Deterministic pipeline dispatcher
  analyst_agent.py          LLM: disambiguates ambiguous findings
  fix_agent.py              LLM: proposes minimal diffs
  reviewer_agent.py         LLM: adversarial fix critique
  educator_agent.py         LLM: CFR citations + plain-English explanations
  verifier.py               Re-scans fixed files to confirm resolution
  trend_agent.py            Posture tracking + weekly reports
workflows/
  pre_commit_scan.md        SOP: pre-commit trigger
  fix_loop.md               SOP: Fix → Reviewer → Verifier loop
  manual_audit.md           SOP: full repo audit
  false_positive_intake.md  SOP: FP recording and feedback
  weekly_trend_report.md    SOP: weekly posture report
```

---

## Architecture: WAT Framework

Built on the WAT (Workflows, Agents, Tools) pattern:
- **Workflows** (`workflows/`) — Markdown SOPs defining what to do and how
- **Agents** (`agent/`) — AI orchestration and reasoning
- **Tools** (`tools/`) — Deterministic Python scripts for execution

Probabilistic AI handles reasoning; deterministic code handles execution. Agent failures fall conservatively (e.g., Analyst failure → treat all findings as confirmed violations).

---

## Disclaimer

HIPAA-Guard identifies code-level compliance gaps. It is not a certified HIPAA compliance audit and does not constitute legal advice. Consult a qualified HIPAA compliance officer before certifying compliance. Scan results should be retained per 45 CFR §164.316(b)(2) requirements.
