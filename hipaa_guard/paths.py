from __future__ import annotations
"""
paths.py — single source of truth for all HIPAA-Guard file paths.

User data (~/.hipaa-guard/):
  false_positives.jsonl, false_negatives.jsonl, scan_history/, rule_config.json

Project config (searched upward from cwd):
  hipaa-guard.config.json

Bundled defaults (read-only, inside the installed wheel):
  hipaa_guard/data/hipaa-guard.config.json, rule_config.json, baa_registry.json
"""

import shutil
from pathlib import Path
import importlib.resources

_USER_DATA_DIR = Path.home() / ".hipaa-guard"


def get_user_data_dir() -> Path:
    _USER_DATA_DIR.mkdir(exist_ok=True)
    return _USER_DATA_DIR


def get_fp_log() -> Path:
    return get_user_data_dir() / "false_positives.jsonl"


def get_fn_log() -> Path:
    return get_user_data_dir() / "false_negatives.jsonl"


def get_scan_history_dir() -> Path:
    d = get_user_data_dir() / "scan_history"
    d.mkdir(exist_ok=True)
    return d


def get_rule_config_path() -> Path:
    """Writable rule_config.json in user data dir; seeded from bundled default on first use."""
    path = get_user_data_dir() / "rule_config.json"
    if not path.exists():
        src = get_package_data_path("rule_config.json")
        shutil.copy(src, path)
    return path


def get_project_config(start_dir: Path | None = None) -> Path | None:
    """Walk upward from start_dir (default: cwd) looking for hipaa-guard.config.json."""
    search = start_dir or Path.cwd()
    for parent in [search, *search.parents]:
        candidate = parent / "hipaa-guard.config.json"
        if candidate.exists():
            return candidate
    return None


def get_package_data_path(filename: str) -> Path:
    """Return path to a bundled data file inside the installed package."""
    with importlib.resources.path("hipaa_guard.data", filename) as p:
        return Path(p)
