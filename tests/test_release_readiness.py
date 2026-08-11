"""Deterministic Gate 7 release-readiness checks (no network).

Runs ``scripts/release_scan.py`` against the repository in-process. The scan
performs the license, dependency, secret, customer-data, proprietary-import,
packaging, and public-API checks from the Gate 7 review. Every check is
local and deterministic; nothing here opens a network connection.

Secret-like strings in this file are built by concatenation on purpose so the
repo-wide secret scan (which includes this file) never sees a literal that
matches its own patterns.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import release_scan  # noqa: E402


def test_release_scan_passes_on_repository() -> None:
    findings = release_scan.scan(REPO)
    failures = [f for f in findings if f.severity == "fail"]
    assert failures == [], "release scan failures:\n" + "\n".join(str(f) for f in failures)


def test_scan_detects_planted_secret(tmp_path: Path) -> None:
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    rel = "planted.txt"
    findings = release_scan.scan_text(rel, f"value={aws}\n")
    kinds = {f.kind for f in findings}
    assert "secret" in kinds


def test_scan_detects_planted_high_entropy_credential(tmp_path: Path) -> None:
    token = "sk-proj-" + "AbC1" + "dEf2" + "GhI3" + "JkL4" + "MnO5"
    findings = release_scan.scan_text("planted.env", f'api_key = "{token}"\n')
    assert any(f.kind == "secret" for f in findings)


def test_scan_allows_low_entropy_test_credential() -> None:
    # Synthetic test values used by the redaction tests must not trip the scan.
    findings = release_scan.scan_text("test_redaction.py", 'api_key = "tenant-a-key"\n')
    assert not any(f.kind == "secret" for f in findings)


def test_scan_detects_customer_data_pattern() -> None:
    findings = release_scan.scan_text(
        "fixtures/x.jsonl", "customer@example.com phone +371 29 123 456\n", customer_data=True
    )
    kinds = {f.kind for f in findings}
    assert "customer-data" in kinds
    assert any("email" in f.message for f in findings)
    assert any("phone" in f.message for f in findings)


def test_scan_detects_commit_sha_hex_is_not_phone() -> None:
    # Bare hex runs inside commit SHAs must not be flagged as phone numbers.
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    findings = release_scan.scan_text("graph.json", f'"built_at_commit": "{sha}"\n',
                                      customer_data=True)
    assert not any(f.kind == "customer-data" for f in findings)


def test_scan_detects_proprietary_import(tmp_path: Path) -> None:
    src = tmp_path / "repo" / "src"
    src.mkdir(parents=True)
    (src / "bad.py").write_text(
        "from bugzero.private import thing\n"
        "import os\n"
        "from incident_context import BuildRequest\n"
        "\n"
        '# docstring prose: "from environment, secure config, or vault"\n',
        encoding="utf-8",
    )
    findings = release_scan.check_proprietary_imports(tmp_path / "repo", ["src/bad.py"])
    assert any(f.kind == "proprietary" and "bugzero" in f.message for f in findings)
    assert not any(f.kind == "proprietary" and "environment" in f.message for f in findings)


def test_scan_detects_tracked_artifact() -> None:
    findings = release_scan.check_packaging(["graphify-out/graph.json", "ok.py"])
    assert any(f.path == "graphify-out/graph.json" for f in findings)
    assert not any(f.path == "ok.py" for f in findings)


def test_scan_cli_exits_zero(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "release_scan.py"), "--json", "--root", str(REPO)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = __import__("json").loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["failures"] == []


def test_every_public_export_resolves() -> None:
    findings = release_scan.check_api(REPO)
    assert findings == [], "\n".join(str(f) for f in findings)
