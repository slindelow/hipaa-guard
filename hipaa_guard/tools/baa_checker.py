from __future__ import annotations
"""
baa_checker.py

Checks project dependencies against the BAA registry.
Parses requirements.txt, package.json, pyproject.toml.
Cross-references config/baa_registry.json for BAA status.
Only flags packages that actually appear in PHI-handling code.
"""

import json
import re
from pathlib import Path

from hipaa_guard import paths


def _load_registry() -> dict:
    registry_path = paths.get_package_data_path("baa_registry.json")
    if registry_path.exists():
        return json.loads(registry_path.read_text()).get("packages", {})
    return {}


def _parse_requirements_txt(path: Path) -> list[str]:
    packages = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip version specifiers
        pkg = re.split(r'[>=<!;\[]', line)[0].strip().lower()
        if pkg:
            packages.append(pkg)
    return packages


def _parse_package_json(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text())
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        return [k.lower() for k in deps.keys()]
    except Exception:
        return []


def _parse_pyproject_toml(path: Path) -> list[str]:
    packages = []
    in_deps = False
    for line in path.read_text().splitlines():
        if "[tool.poetry.dependencies]" in line or "[project.dependencies]" in line or "dependencies = [" in line:
            in_deps = True
            continue
        if in_deps and line.startswith("["):
            in_deps = False
        if in_deps:
            m = re.match(r'\s*["\']?([a-zA-Z0-9\-_]+)["\']?\s*[=<>!]', line)
            if m:
                packages.append(m.group(1).lower())
    return packages


def _find_phi_touching_packages(project_root: str, packages: list[str]) -> set[str]:
    """
    Find which packages appear in files that also contain PHI-related variable names.
    Simple heuristic: grep for import statements in files with PHI variable names.
    """
    _PHI_MARKERS = {'patient', 'phi', 'ssn', 'mrn', 'dob', 'hipaa', 'fhir', 'ehr', 'medical_record'}
    phi_touching = set()

    root = Path(project_root)
    for py_file in root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding='utf-8', errors='replace').lower()
        except Exception:
            continue

        has_phi = any(marker in content for marker in _PHI_MARKERS)
        if not has_phi:
            continue

        for pkg in packages:
            pkg_import = pkg.replace("-", "_")
            if f"import {pkg_import}" in content or f"from {pkg_import}" in content:
                phi_touching.add(pkg)

    return phi_touching


def check_baa(project_root: str) -> dict:
    """
    Main entry point. Returns structured BAA check results.
    """
    registry = _load_registry()
    root = Path(project_root)

    all_packages: list[str] = []
    sources: dict[str, str] = {}

    # Collect from all dependency files
    for dep_file, parser in [
        (root / "requirements.txt", _parse_requirements_txt),
        (root / "requirements-dev.txt", _parse_requirements_txt),
        (root / "package.json", _parse_package_json),
        (root / "pyproject.toml", _parse_pyproject_toml),
    ]:
        if dep_file.exists():
            pkgs = parser(dep_file)
            for p in pkgs:
                if p not in sources:
                    sources[p] = dep_file.name
            all_packages.extend(pkgs)

    all_packages = list(set(all_packages))
    phi_touching = _find_phi_touching_packages(project_root, all_packages)

    results = {
        "total_dependencies": len(all_packages),
        "phi_touching": len(phi_touching),
        "findings": [],
    }

    for pkg in sorted(all_packages):
        registry_entry = registry.get(pkg, {})
        status = registry_entry.get("status", "UNKNOWN")
        touches_phi = pkg in phi_touching
        source_file = sources.get(pkg, "unknown")

        finding = {
            "package": pkg,
            "source_file": source_file,
            "baa_status": status,
            "touches_phi": touches_phi,
            "notes": registry_entry.get("notes", "Not in BAA registry — research required."),
            "baa_url": registry_entry.get("baa_url"),
            "action_required": (
                touches_phi and status in ("NOT_AVAILABLE", "UNKNOWN") and status != "NOT_REQUIRED"
            ),
        }
        results["findings"].append(finding)

    results["action_required_count"] = sum(1 for f in results["findings"] if f["action_required"])
    return results


def print_baa_report(results: dict) -> None:
    print("\n\033[1mBAA Dependency Check\033[0m")
    print(f"  Total dependencies: {results['total_dependencies']}")
    print(f"  PHI-touching:       {results['phi_touching']}")
    print(f"  Action required:    {results['action_required_count']}")
    print()

    action_items = [f for f in results["findings"] if f["action_required"]]
    if action_items:
        print("\033[31mPackages requiring BAA investigation:\033[0m")
        for f in action_items:
            status_color = "\033[33m" if f["baa_status"] == "UNKNOWN" else "\033[31m"
            print(f"  {status_color}{f['baa_status']:12}\033[0m {f['package']} ({f['source_file']})")
            print(f"               {f['notes']}")
            if f["baa_url"]:
                print(f"               BAA info: {f['baa_url']}")
            print()
    else:
        print("\033[32m✅ All PHI-touching packages have known BAA status.\033[0m")

    # Show not-required (informational)
    not_required = [f for f in results["findings"] if f["baa_status"] == "NOT_REQUIRED" and f["touches_phi"]]
    if not_required:
        print("ℹ  BAA not required for these PHI-adjacent libraries (vendor handles compliance):")
        for f in not_required:
            print(f"   • {f['package']}: {f['notes']}")
