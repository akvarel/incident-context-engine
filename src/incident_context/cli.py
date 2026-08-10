from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .builder import IncidentContextBuilder
from .models import BuildRequest, LogEvent


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _load_events(path: Path) -> list[LogEvent]:
    events: list[LogEvent] = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                events.append(
                    LogEvent(
                        timestamp=_timestamp(item["timestamp"]),
                        service=str(item["service"]),
                        severity=str(item.get("severity", "INFO")),
                        message=str(item["message"]),
                        fields=dict(item.get("fields", {})),
                        evidence=dict(item["evidence"]),
                    )
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise ValueError(f"invalid event on line {line_number}: {error}") from error
    return events


def run(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="incident-context")
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build an incident snapshot from JSON Lines")
    build.add_argument("--input", required=True, type=Path)
    build.add_argument("--scope", required=True)
    build.add_argument("--budget", type=int, default=2_000)
    args = parser.parse_args(argv)

    events = _load_events(args.input)
    snapshot = IncidentContextBuilder().build(
        BuildRequest(scope=args.scope, token_budget=args.budget, events=events)
    )
    print(json.dumps(snapshot.to_dict(), indent=2, sort_keys=True))
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
