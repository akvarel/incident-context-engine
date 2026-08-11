import json
from datetime import datetime, timedelta, timezone

import pytest

from incident_context import (
    BuildRequest,
    ExpansionDirective,
    IncidentContextBuilder,
    JcodeContextCompiler,
    LogEvent,
)


BASE = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
EVIDENCE = {
    "source": "loki",
    "query_ref": "LQ-COMPILER",
    "start": "2026-08-10T11:59:00Z",
    "end": "2026-08-10T12:01:00Z",
}



def _event(service, second, message, *, severity="ERROR", fields=None):
    return LogEvent(
        timestamp=BASE + timedelta(seconds=second),
        service=service,
        severity=severity,
        message=message,
        fields=fields or {},
        evidence=dict(EVIDENCE),
    )


def _build_context(*, token_budget=500, baseline_events=None):
    events = [
        _event(
            "payments",
            1,
            "java.lang.RuntimeException: processing failed\\n"
            "at com.example.api.InvoiceService.create(InvoiceService.java:57)\\n"
            "at com.example.api.PaymentController.run(PaymentController.java:120)",
            fields={"trace_id": "t-1"},
        ),
        _event(
            "workers",
            2,
            "java.lang.RuntimeException: processing failed\\n"
            "at com.example.api.InvoiceService.create(InvoiceService.java:58)\\n"
            "at com.example.api.PaymentController.run(PaymentController.java:121)",
            fields={"trace_id": "t-1"},
        ),
        _event("payments", 3, "validation timeout order_id=100 severity=high", severity="WARN", fields={"request_id": "r-1"}),
        _event("payments", 4, "validation timeout order_id=101 severity=high", severity="WARN", fields={"request_id": "r-1"}),
        _event("payments", 5, "validation timeout failed for order_id=102", severity="WARN", fields={"request_id": "r-1"}),
    ]
    return IncidentContextBuilder().build(
        BuildRequest(
            scope="payments",
            token_budget=token_budget,
            events=events,
            baseline_events=baseline_events,
        )
    )


def _build_context_with_baseline():
    incident = [
        _event("payments", 1, "timeout while reading basket", severity="ERROR", fields={"session_id": "s-1"}),
        _event("payments", 2, "timeout while reading basket", severity="ERROR", fields={"session_id": "s-1"}),
    ]
    baseline = [
        _event("payments", 0, "timeout while reading basket", severity="ERROR", fields={"session_id": "s-2"}),
    ]
    return IncidentContextBuilder().build(
        BuildRequest(
            scope="payments",
            token_budget=1000,
            events=incident,
            baseline_events=baseline,
            incident_window_seconds=60,
            baseline_window_seconds=60,
        )
    )


def test_compile_l0_contains_only_summary_and_state():
    context = _build_context()
    published = JcodeContextCompiler().compile(context, level="L0", token_budget=400)

    assert published.disclosure_level == "L0"
    assert published.summary["rawEventCount"] == len(context.patterns) + 0 * 0
    assert len(published.patterns) == 0
    assert published.timeline == ()
    assert published.stack_fingerprints == ()
    assert published.correlations == ()
    assert published.deltas == ()
    assert published.hypotheses == ()
    assert published.state.requested_level == "L0"
    assert published.state.emitted_level == "L0"
    assert published.state.complete is True
    assert published.state.next_level == "L1"
    assert published.state.tokens_used >= published.state.token_budget - published.state.tokens_remaining
    assert [op.kind for op in published.state.operations] == [
        "patterns",
        "timeline",
        "stack_fingerprints",
        "correlations",
        "deltas",
        "hypotheses",
    ]


def test_compile_l1_reduces_sensitivity_and_limits_patterns_timeline():
    context = _build_context()
    published = JcodeContextCompiler().compile(
        context,
        level="L1",
        token_budget=900,
        directives=[
            ExpansionDirective(kind="patterns", limit=2),
            ExpansionDirective(kind="timeline", limit=1),
            ExpansionDirective(kind="deltas", limit=1),
            ExpansionDirective(kind="hypotheses", limit=0),
        ],
    )

    assert published.disclosure_level == "L1"
    assert published.state.complete is True
    assert len(json.dumps(published.to_dict(), sort_keys=True, ensure_ascii=False)) // 4 <= 900
    assert len(published.patterns) <= 2
    assert len(published.timeline) <= 1
    assert published.state.operations[0].kind == "patterns"
    assert published.state.operations[0].requested == 2
    first_pattern = published.patterns[0]
    assert "samples" not in first_pattern
    assert "retentionReason" in first_pattern
    assert "evidenceRefs" not in first_pattern


def test_compile_l2_exposes_samples_when_requested_and_tracks_hypotheses():
    context = _build_context()
    published = JcodeContextCompiler().compile(
        context,
        level="L2",
        token_budget=1800,
        directives=[
            ExpansionDirective(kind="patterns", limit=2, samples_per_pattern=1),
            ExpansionDirective(kind="timeline", limit=4),
            ExpansionDirective(kind="stack_fingerprints", limit=2),
            ExpansionDirective(kind="hypotheses", limit=5),
            ExpansionDirective(kind="deltas", limit=2),
            ExpansionDirective(kind="correlations", limit=1),
        ],
    )

    assert published.disclosure_level == "L2"
    assert published.state.complete is True
    assert len(json.dumps(published.to_dict(), sort_keys=True, ensure_ascii=False)) // 4 <= 1800
    assert len(published.patterns) >= 1
    sample_entry = published.patterns[0]
    assert isinstance(sample_entry.get("samples"), list)
    assert len(sample_entry["samples"]) <= 1
    assert published.stack_fingerprints == ()
    assert next(op for op in published.state.operations if op.kind == "stack_fingerprints").requested == 0
    assert published.hypotheses

    pattern_hypothesis = next(
        hypothesis for hypothesis in published.hypotheses if hypothesis["target"].startswith("LP-")
    )
    assert pattern_hypothesis["evidenceRefs"]
    assert any(item.kind == "correlations" for item in published.state.operations)

def test_compile_with_baseline_generates_deltas_and_strict_budget_exposes_incomplete():
    context = _build_context_with_baseline()
    strict_budget = 110

    with pytest.raises(RuntimeError, match="disclosure budget exhausted"):
        JcodeContextCompiler().compile(context, level="L2", token_budget=strict_budget, strict=True)

    published = JcodeContextCompiler().compile(context, level="L2", token_budget=strict_budget)
    assert published.state.complete is False
    assert published.state.requested_level == "L2"
    assert published.state.token_budget == strict_budget
    assert published.state.tokens_used > strict_budget
    assert any(op.applied < op.requested for op in published.state.operations)
    assert published.deltas == ()


def test_operation_summary_is_stable_under_tight_expansion_budget():
    context = _build_context(token_budget=1200)
    published = JcodeContextCompiler().compile(
        context,
        level="L2",
        token_budget=450,
        directives=[
            ExpansionDirective(kind="patterns", limit=50),
            ExpansionDirective(kind="timeline", limit=50),
            ExpansionDirective(kind="stack_fingerprints", limit=20),
            ExpansionDirective(kind="correlations", limit=20),
            ExpansionDirective(kind="deltas", limit=20),
            ExpansionDirective(kind="hypotheses", limit=20),
        ],
    )

    assert published.state.requested_level == "L2"
    assert [op.kind for op in published.state.operations] == [
        "patterns",
        "timeline",
        "stack_fingerprints",
        "correlations",
        "deltas",
        "hypotheses",
    ]
    state_payload = published.state.to_dict()
    assert state_payload["operations"][0]["kind"] == "patterns"
    assert state_payload["nextLevel"] is None
    assert state_payload["tokensRemaining"] == published.state.tokens_remaining
    assert json.dumps(state_payload)
