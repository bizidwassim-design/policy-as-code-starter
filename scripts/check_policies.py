#!/usr/bin/env python3
"""Structural checks for the policy-as-code starter, plus example evaluation.

Always (no external tools needed):

* every OPA policy under ``policies/opa/<area>/`` has a sibling ``*_test.rego``
  in the same package with at least three ``test_`` rules;
* policy and test files use ``import rego.v1``, tab indentation, no trailing
  whitespace, a ``Controls:`` header comment and a ``deny contains msg if`` rule;
* the package name matches ``<area>.<file-stem>`` (``lib.<stem>`` for helpers);
* every policy package is listed in ``docs/policy-catalogue.md``;
* ``examples/expected.json`` references existing inputs and packages, and the
  example YAML / JSON inputs parse;
* the Checkov YAML policies and ``.checkov.yaml`` parse and carry the
  mandatory metadata with unique ids;
* the Sentinel policies carry the "UNTESTED" marker.

When ``opa`` is on PATH, every row of ``examples/expected.json`` is evaluated
with ``opa eval`` and the number of deny messages must match. CI installs OPA,
so the evaluation always runs there.

Run from anywhere: ``python scripts/check_policies.py``.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OPA_DIR = ROOT / "policies" / "opa"
CHECKOV_DIR = ROOT / "policies" / "checkov"
SENTINEL_DIR = ROOT / "policies" / "sentinel"
EXAMPLES = ROOT / "examples"
CATALOGUE = ROOT / "docs" / "policy-catalogue.md"

PACKAGE_RE = re.compile(r"^package\s+([A-Za-z0-9_.]+)\s*$", re.MULTILINE)
TEST_RULE_RE = re.compile(r"^test_[a-z0-9_]+\s+if\s*\{", re.MULTILINE)
DENY_RE = re.compile(r"^deny contains msg if \{", re.MULTILINE)

CHECKOV_CATEGORIES = {
    "GENERAL_SECURITY",
    "ENCRYPTION",
    "NETWORKING",
    "LOGGING",
    "IAM",
    "BACKUP_AND_RECOVERY",
    "CONVENTION",
    "SECRETS",
    "KUBERNETES",
    "APPLICATION_SECURITY",
    "SUPPLY_CHAIN",
    "API_SECURITY",
}


def report(label: str, problems: list[str]) -> int:
    status = "OK " if not problems else "ERR"
    print(f"[{status}] {label}")
    for problem in problems:
        print(f"      - {problem}")
    return len(problems)


def rego_style_problems(path: Path, text: str) -> list[str]:
    problems: list[str] = []
    if "import rego.v1" not in text:
        problems.append("missing `import rego.v1`")
    for line_no, line in enumerate(text.splitlines(), start=1):
        if line.startswith(" "):
            problems.append(f"line {line_no}: indented with spaces (opa fmt uses tabs)")
        if line != line.rstrip():
            problems.append(f"line {line_no}: trailing whitespace")
    if not text.endswith("\n"):
        problems.append("file must end with a newline")
    if path.read_bytes().count(b"\r"):
        problems.append("must use LF line endings")
    return problems


def package_of(text: str) -> str | None:
    match = PACKAGE_RE.search(text)
    return match.group(1) if match else None


def check_opa() -> tuple[int, dict[str, Path]]:
    failures = 0
    policies: dict[str, Path] = {}

    for lib in sorted((OPA_DIR / "lib").glob("*.rego")):
        text = lib.read_text(encoding="utf-8")
        problems = rego_style_problems(lib, text)
        if package_of(text) != f"lib.{lib.stem}":
            problems.append(f"package must be lib.{lib.stem}")
        failures += report(lib.relative_to(ROOT).as_posix(), problems)

    for area_dir in sorted(p for p in OPA_DIR.iterdir() if p.is_dir() and p.name != "lib"):
        for policy in sorted(area_dir.glob("*.rego")):
            if policy.name.endswith("_test.rego"):
                continue
            text = policy.read_text(encoding="utf-8")
            problems = rego_style_problems(policy, text)
            expected_package = f"{area_dir.name}.{policy.stem}"
            package = package_of(text)
            if package != expected_package:
                problems.append(f"package must be {expected_package} (found {package})")
            if not DENY_RE.search(text):
                problems.append("no `deny contains msg if {` rule")
            if "Controls:" not in text:
                problems.append("header comment must list the controls (Controls: ...)")

            test_path = policy.with_name(f"{policy.stem}_test.rego")
            if not test_path.exists():
                problems.append(f"missing test file {test_path.name}")
            else:
                test_text = test_path.read_text(encoding="utf-8")
                problems.extend(f"{test_path.name}: {p}" for p in rego_style_problems(test_path, test_text))
                if package_of(test_text) != expected_package:
                    problems.append(f"{test_path.name}: package must be {expected_package}")
                tests = TEST_RULE_RE.findall(test_text)
                if len(tests) < 3:
                    problems.append(f"{test_path.name}: needs at least 3 test_ rules (found {len(tests)})")

            if package:
                policies[package] = policy
            failures += report(policy.relative_to(ROOT).as_posix(), problems)

    catalogue = CATALOGUE.read_text(encoding="utf-8")
    missing = [pkg for pkg in policies if pkg not in catalogue]
    failures += report(CATALOGUE.relative_to(ROOT).as_posix(), [f"policy {pkg} not listed" for pkg in missing])
    return failures, policies


def load_input(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        if path.suffix in {".yaml", ".yml"}:
            return yaml.safe_load(handle)
        return json.load(handle)


def check_expected(policies: dict[str, Path]) -> tuple[int, list[dict[str, object]]]:
    expected_path = EXAMPLES / "expected.json"
    problems: list[str] = []
    rows: list[dict[str, object]] = json.loads(expected_path.read_text(encoding="utf-8"))
    for row in rows:
        input_path = ROOT / str(row["input"])
        if not input_path.exists():
            problems.append(f"input {row['input']} does not exist")
            continue
        try:
            load_input(input_path)
        except (ValueError, yaml.YAMLError) as exc:
            problems.append(f"input {row['input']} does not parse: {exc}")
        if row["package"] not in policies:
            problems.append(f"package {row['package']} is not a policy")
        if not isinstance(row["deny"], int) or row["deny"] < 0:
            problems.append(f"deny count for {row['input']} / {row['package']} must be a non-negative integer")
    for policy in policies:
        if not any(r["package"] == policy for r in rows):
            problems.append(f"policy {policy} has no row in expected.json")
    return report(expected_path.relative_to(ROOT).as_posix(), problems), rows


def evaluate_examples(rows: list[dict[str, object]]) -> int:
    opa = shutil.which("opa")
    if opa is None:
        print("[SKIP] opa not on PATH - example evaluation skipped (CI runs it)")
        return 0
    failures = 0
    for row in rows:
        input_path = ROOT / str(row["input"])
        payload = json.dumps(load_input(input_path))
        query = f"data.{row['package']}.deny"
        completed = subprocess.run(
            [opa, "eval", "--format", "json", "--stdin-input", "--data", str(OPA_DIR), query],
            input=payload,
            capture_output=True,
            text=True,
            cwd=ROOT,
            check=False,
        )
        label = f"opa eval {row['input']} {row['package']}"
        if completed.returncode != 0:
            failures += report(label, [completed.stderr.strip() or "opa eval failed"])
            continue
        result = json.loads(completed.stdout)
        value = result["result"][0]["expressions"][0]["value"]
        actual = len(value)
        problems = [] if actual == row["deny"] else [f"expected {row['deny']} deny message(s), got {actual}: {value}"]
        failures += report(label, problems)
    return failures


def check_checkov() -> int:
    failures = 0
    seen_ids: set[str] = set()
    for policy in sorted(CHECKOV_DIR.glob("*.yaml")):
        problems: list[str] = []
        try:
            data = yaml.safe_load(policy.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            failures += report(policy.relative_to(ROOT).as_posix(), [f"does not parse: {exc}"])
            continue
        metadata = data.get("metadata", {}) if isinstance(data, dict) else {}
        for key in ("id", "name", "category"):
            if not metadata.get(key):
                problems.append(f"metadata.{key} is required")
        policy_id = str(metadata.get("id", ""))
        if not re.fullmatch(r"CKV2?_[A-Z]+_\d+", policy_id):
            problems.append(f"id {policy_id!r} must look like CKV2_CUSTOM_1")
        if policy_id in seen_ids:
            problems.append(f"duplicate id {policy_id}")
        seen_ids.add(policy_id)
        if metadata.get("category") not in CHECKOV_CATEGORIES:
            problems.append(f"category {metadata.get('category')!r} is not a Checkov category")
        if "definition" not in data:
            problems.append("definition is required")
        if not str(data.get("scope", {}).get("provider", "")):
            problems.append("scope.provider is required")
        if policy.read_bytes().count(b"\r"):
            problems.append("must use LF line endings")
        failures += report(policy.relative_to(ROOT).as_posix(), problems)

    config = ROOT / ".checkov.yaml"
    problems = []
    try:
        data = yaml.safe_load(config.read_text(encoding="utf-8"))
        listed = set(data.get("check", []))
        for policy_id in seen_ids:
            if policy_id not in listed:
                problems.append(f"{policy_id} is not in the check list")
    except yaml.YAMLError as exc:
        problems.append(f"does not parse: {exc}")
    failures += report(config.relative_to(ROOT).as_posix(), problems)
    return failures


def check_sentinel() -> int:
    failures = 0
    for policy in sorted(SENTINEL_DIR.glob("*.sentinel")):
        text = policy.read_text(encoding="utf-8")
        problems = []
        if "UNTESTED" not in text.splitlines()[0]:
            problems.append("first line must carry the UNTESTED marker")
        if 'import "tfplan/v2"' not in text:
            problems.append("must import tfplan/v2")
        if "main = rule" not in text:
            problems.append("must define `main = rule`")
        failures += report(policy.relative_to(ROOT).as_posix(), problems)
    return failures


def main() -> int:
    failures, policies = check_opa()
    expected_failures, rows = check_expected(policies)
    failures += expected_failures
    failures += check_checkov()
    failures += check_sentinel()
    if not failures:
        failures += evaluate_examples(rows)
    print(f"\n{len(policies)} OPA policies checked, {failures} problem(s).")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
