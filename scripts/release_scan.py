#!/usr/bin/env python3
"""Gate 7 OSS release-readiness scan (deterministic, non-network).

Performs the Gate 7 review checks against the current repository only. No
network access, no third-party tooling, deterministic output for a given tree.

Checks:

1. license        dual-license files exist and are declared in ``pyproject.toml``
2. dependencies   no third-party runtime imports; no third-party runtime deps
                  declared in ``pyproject.toml`` (stdlib-only runtime)
3. secrets        no credential-like literals in tracked files
4. proprietary    no imports of private BugZero/Graphify packages and no
                  third-party top-level imports outside the stdlib
5. customer-data  no personal/customer data patterns in fixtures, examples, docs
6. packaging      no tracked build artifacts and no machine-local absolute paths
7. api            every public export in ``__all__`` resolves to a real object

Usage:

    python3 scripts/release_scan.py            # human report, exit 0/1
    python3 scripts/release_scan.py --json     # machine-readable report

The same checks are exercised by ``tests/test_release_readiness.py`` so they
run in CI without any external service.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

CUSTOMER_DATA_PATHS = ("tests/fixtures", "examples", "docs", "README.md")


@dataclasses.dataclass(frozen=True)
class Finding:
    kind: str
    severity: str  # "fail" or "warn"
    path: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.kind}: {self.path}: {self.message}"


# --- patterns --------------------------------------------------------------

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer-credential", re.compile(r"\bBearer [A-Za-z0-9._~+/=-]{20,}\b")),
    (
        "credential-assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret|password|passwd|authorization"
            r"|access[_-]?token|bearer)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"
        ),
    ),
)

# Test files deliberately carry fake API keys and bearer headers to prove
# redaction. Only high-entropy values (mixed case plus digits, or punctuation
# typical of real tokens) are treated as credential-like, so synthetic test
# values such as "tenant-a-key" or "super-secret-token-abc" are allowed while
# real-world tokens are still flagged.

def _high_entropy(value: str) -> bool:
    if len(value) < 12:
        return False
    has_lower = any(ch.islower() for ch in value)
    has_upper = any(ch.isupper() for ch in value)
    has_digit = any(ch.isdigit() for ch in value)
    has_symbol = any(ch in "_~+/=-." for ch in value)
    if has_digit and has_lower and has_upper:
        return True
    if has_digit and has_symbol:
        return True
    return False


def _secret_scan_text(rel: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if name in ("credential-assignment", "bearer-credential"):
                # credential-assignment captures 'name = "value"'; evaluate
                # the quoted value, bearer-credential evaluates the token.
                quote_match = re.search(r"[\"']([^\"']*)[\"']$", value)
                candidate = quote_match.group(1) if quote_match else value.split(" ")[-1]
                if not _high_entropy(candidate):
                    continue
            findings.append(Finding("secret", "fail", rel, f"{name} ({pattern.pattern})"))
            break
    return findings

_CUSTOMER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email-address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    # The first separator is required so bare hex runs inside commit SHAs
    # (e.g. "104050130300bff") are not mistaken for phone numbers; groups of
    # 2-4 digits cover +371 29 123 456 style numbers.
    ("phone-number", re.compile(r"\+?[0-9]{2,3}[-. ][0-9]{2,4}([-. ]?[0-9]{2,4}){2,3}")),
    ("card-number", re.compile(r"[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}[- ][0-9]{4}")),
    (
        "private-ip",
        re.compile(r"\b(10|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]+\.[0-9]+\b"),
    ),
)

_MACHINE_PATH_PATTERNS = (
    re.compile(r"/(sharedssd|home|Users|workspace|mnt)/", re.I),
    re.compile(r"^([A-Za-z]:\\|/Users/|/home/)"),
    re.compile(r"\b[A-Za-z]:[\\/]"),
)

_ARTIFACT_PATH_PATTERNS = (
    re.compile(r"(^|/)(__pycache__|build|dist|graphify-out)(/|$)"),
    re.compile(r"(^|/)\.egg-info(/|$)"),
    re.compile(r"\.py[co]$"),
)

_LICENSE_FILES = ("LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE")

_PYPROJECT_DEPENDENCIES_PATTERN = re.compile(r"(?m)^dependencies\s*=\s*\[")


# --- repository access -----------------------------------------------------

def tracked_files(root: Path) -> list[str]:
    """Return git-tracked paths relative to ``root`` (deterministic).

    Falls back to a working-tree walk (skipping ignored dirs) when the tree is
    not a git checkout, so the scan also works from a source distribution.
    """
    try:
        tracked = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        untracked = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        skip = {".git", "__pycache__", ".pytest_cache", "build", "dist",
                "graphify-out", ".venv"}
        paths: list[str] = []
        for path in root.rglob("*"):
            if path.is_file() and not any(part in skip for part in path.relative_to(root).parts):
                paths.append(str(path.relative_to(root)))
        return sorted(paths)
    files = [
        line.strip()
        for line in tracked.stdout.splitlines() + untracked.stdout.splitlines()
        if line.strip()
    ]
    return sorted(set(files))


def read_text(root: Path, rel: str, limit: int = 4 * 1024 * 1024) -> str | None:
    """Read a tracked file as text, or None when it is not text or too large."""
    path = root / rel
    try:
        if path.stat().st_size > limit:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def scan_text(rel: str, text: str, *, customer_data: bool = False) -> list[Finding]:
    """Run the regex checks over one file's text."""
    findings: list[Finding] = []
    findings.extend(_secret_scan_text(rel, text))
    if customer_data:
        for name, pattern in _CUSTOMER_PATTERNS:
            match = pattern.search(text)
            if match:
                findings.append(Finding("customer-data", "fail", rel, f"{name} ({pattern.pattern})"))
    # The scanner's own source is exempt from the machine-path check: it must
    # contain the pattern definitions themselves. Every other file is checked.
    if rel != Path(__file__).resolve().relative_to(ROOT).as_posix():
        for pattern in _MACHINE_PATH_PATTERNS:
            if pattern.search(text):
                findings.append(
                    Finding("packaging", "fail", rel, f"machine-local absolute path ({pattern.pattern})")
                )
    return findings


# --- individual checks -----------------------------------------------------

def check_license(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    missing = [name for name in _LICENSE_FILES if not (root / name).is_file()]
    if missing:
        findings.append(Finding("license", "fail", ", ".join(missing), "license file missing"))
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8")
        if 'license = "MIT OR Apache-2.0"' not in text:
            findings.append(Finding("license", "fail", "pyproject.toml",
                                    "SPDX license expression missing"))
        for name in _LICENSE_FILES:
            if f'"{name}"' not in text:
                findings.append(Finding("license", "fail", "pyproject.toml",
                                        f"license file {name} not declared"))
    return findings


def check_dependencies(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8")
        if _PYPROJECT_DEPENDENCIES_PATTERN.search(text):
            findings.append(Finding("dependencies", "fail", "pyproject.toml",
                                    "third-party runtime dependencies declared (runtime must be stdlib-only)"))
    return findings


def _strip_python_strings(text: str) -> str:
    """Blank strings and comments so import parsing only sees real code.

    Docstring prose such as ``from environment, secure config, or vault`` or
    test fixtures that contain ``from bugzero...`` inside a string literal
    must not be parsed as imports.
    """
    text = re.sub(r'""".*?"""|\'\'\'.*?\'\'\'', "", text, flags=re.S)
    text = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', "", text, flags=re.S)
    return re.sub(r"#[^\n]*", "", text)


# Non-stdlib imports allowed outside the runtime package. ``pytest`` is the
# declared test runner; ``runtime_code_helpers`` is this repo's local test
# helper module.
TEST_IMPORT_ALLOWLIST = {"pytest", "runtime_code_helpers", "release_scan"}


def check_proprietary_imports(root: Path, files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in files:
        if not rel.endswith(".py"):
            continue
        text = read_text(root, rel)
        if text is None:
            continue
        is_runtime = rel.startswith("src/")
        for lineno, line in enumerate(_strip_python_strings(text).splitlines(), start=1):
            stripped = line.strip()
            match = re.match(r"^(?:from|import)\s+([A-Za-z_][A-Za-z0-9_\.]*)", stripped)
            if not match:
                continue
            module = match.group(1)
            if module.startswith("."):
                continue
            top = module.split(".", 1)[0]
            if top == "incident_context" or top in sys.stdlib_module_names:
                continue
            if not is_runtime and top in TEST_IMPORT_ALLOWLIST:
                continue
            findings.append(
                Finding("proprietary", "fail", f"{rel}:{lineno}",
                        f"non-stdlib top-level import {top!r} (module {module!r})")
            )
    return findings


def check_customer_data(root: Path, files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in files:
        if not any(rel.startswith(prefix) for prefix in CUSTOMER_DATA_PATHS):
            continue
        text = read_text(root, rel)
        if text is None:
            continue
        findings.extend(scan_text(rel, text, customer_data=True))
    return findings


def check_packaging(files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in files:
        for pattern in _ARTIFACT_PATH_PATTERNS:
            if pattern.search(rel):
                findings.append(Finding("packaging", "fail", rel,
                                        f"tracked build artifact ({pattern.pattern})"))
                break
    return findings


def check_api(root: Path) -> list[Finding]:
    """Verify every public export resolves to a real object (no network)."""
    findings: list[Finding] = []
    sys.path.insert(0, str(root / "src"))
    try:
        import incident_context  # noqa: PLC0415
        import incident_context.runtime_code  # noqa: PLC0415, F401

        for package in (incident_context, incident_context.runtime_code):
            exports = getattr(package, "__all__", ())
            for name in exports:
                if not hasattr(package, name):
                    findings.append(Finding("api", "fail", package.__name__,
                                            f"exported name {name!r} does not resolve"))
    except Exception as exc:  # pragma: no cover - exercised by the API itself
        findings.append(Finding("api", "fail", "src/incident_context",
                                f"import failed: {exc}"))
    finally:
        if str(root / "src") in sys.path:
            sys.path.remove(str(root / "src"))
    return findings


# --- driver ----------------------------------------------------------------

def scan(root: Path | None = None) -> list[Finding]:
    root = Path(root or ROOT).resolve()
    files = tracked_files(root)
    findings: list[Finding] = []
    findings.extend(check_license(root))
    findings.extend(check_dependencies(root))
    for rel in files:
        text = read_text(root, rel)
        if text is not None:
            findings.extend(scan_text(rel, text, customer_data=False))
    findings.extend(check_proprietary_imports(root, files))
    findings.extend(check_customer_data(root, files))
    findings.extend(check_packaging(files))
    findings.extend(check_api(root))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="machine-readable JSON report")
    parser.add_argument("--root", default=str(ROOT), help="repository root to scan")
    args = parser.parse_args(argv)

    findings = scan(Path(args.root))
    failures = [f for f in findings if f.severity == "fail"]

    if args.json:
        payload = {
            "ok": not failures,
            "failures": [dataclasses.asdict(f) for f in failures],
            "warnings": [dataclasses.asdict(f) for f in findings if f.severity == "warn"],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        if findings:
            for finding in findings:
                print(finding)
        print(f"release scan: {len(failures)} failure(s), "
              f"{len(findings) - len(failures)} warning(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
