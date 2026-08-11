"""Gate 1 fixtures: bounded SourceGraphLookup protocol and fixture lookup."""

import pytest

from incident_context.runtime_code import (
    InMemoryFixtureLookup,
    LookupBatch,
    LookupBoundsError,
    LookupStatus,
    ObservabilityAnchorKind,
    RevisionQuality,
    SourceGraphLookup,
    fingerprint_template,
)
from runtime_code_helpers import REPOSITORY, REVISION, anchor, make_callsite, scope

TEMPLATE = "order placed"
FP = fingerprint_template(TEMPLATE)


def _lookup(revision: str = REVISION, **kwargs):
    return InMemoryFixtureLookup(REPOSITORY, revision, **kwargs)


def _seed_one(lookup, *, owner="reserve", line=10, logger="logger", source_file="src/app.ts"):
    callsite = make_callsite(
        source_file=source_file,
        start_line=line,
        end_line=line,
        owner_symbol=owner,
        anchor_kind=ObservabilityAnchorKind.LOG_TEMPLATE,
        fingerprint=FP,
        logger=logger,
    )
    record = anchor(canonical_template=TEMPLATE, logger=logger, callsite_override=callsite)
    lookup.seed(record, record.source_callsite)
    return record


def test_protocol_surface_is_exposed():
    assert isinstance(SourceGraphLookup, type)


def test_find_callsites_by_fingerprint_deterministic_order():
    lookup = _lookup()
    for line in (30, 10, 20):
        _seed_one(lookup, owner=f"sym{line}", line=line)
    batch = lookup.find_callsites_by_fingerprint(scope(), [FP])
    assert batch.status is LookupStatus.AVAILABLE
    lines = [record.start_line for record in batch.all_records]
    assert lines == [10, 20, 30]
    assert len(batch.entries) == 1
    assert batch.entries[0].key == FP


def test_find_by_logger_and_scope_mismatch():
    lookup = _lookup()
    _seed_one(lookup, logger="PaymentService")
    hit = lookup.find_symbols_by_logger(scope(), ["PaymentService"])
    assert len(hit.all_records) == 1
    miss = lookup.find_symbols_by_logger(
        scope(repository="other-org", requested_revision=REVISION), ["PaymentService"]
    )
    assert miss.status is LookupStatus.AVAILABLE
    assert miss.all_records == ()


def test_unavailable_lookup_is_data_not_empty_success():
    lookup = _lookup(unavailable_methods={"find_callsites_by_fingerprint"})
    batch = lookup.find_callsites_by_fingerprint(scope(), [FP])
    assert batch.status is LookupStatus.UNAVAILABLE
    assert batch.all_records == ()
    assert batch.to_dict()["status"] == "UNAVAILABLE"


def test_bounds_reject_oversized_keys_and_limits():
    lookup = _lookup()
    with pytest.raises(LookupBoundsError):
        lookup.find_callsites_by_fingerprint(scope(), [f"k{i}" for i in range(51)])
    with pytest.raises(LookupBoundsError):
        lookup.find_callsites_by_fingerprint(scope(), [FP], limit_per_key=21)
    with pytest.raises(LookupBoundsError):
        lookup.expand_symbol(scope(), ["n1"], ["calls"], limit=51)
    with pytest.raises(LookupBoundsError):
        lookup.find_callsites_by_source_location(scope(), [(f"f{i}.ts", 1) for i in range(51)])


def test_candidate_cap_and_truncation_accounting():
    lookup = _lookup(max_candidates_per_key=5)
    for index in range(7):
        _seed_one(lookup, owner=f"sym{index}", line=10 + index)
    batch = lookup.find_callsites_by_fingerprint(scope(), [FP])
    assert len(batch.all_records) == 5
    assert batch.truncated_keys == (FP,)


def test_expand_symbol_bounded_and_deterministic():
    from incident_context.runtime_code import ExpandedGraphRecord

    lookup = _lookup()
    for index in range(3):
        lookup.seed_relation(
            "nodeA",
            "calls",
            ExpandedGraphRecord(
                source_graph_node_id="nodeA",
                relation="calls",
                related_graph_node_id=f"nodeB{index}",
                related_symbol=f"callee{index}",
                source_file="src/callee.ts",
                start_line=1,
                end_line=1 + index,
            ),
        )
    batch = lookup.expand_symbol(scope(), ["nodeA"], ["calls"])
    assert len(batch.all_records) == 3
    assert [record.related_symbol for record in batch.all_records] == ["callee0", "callee1", "callee2"]


def test_source_location_lookup_resolves_frames():
    lookup = _lookup()
    _seed_one(lookup, line=42)
    batch = lookup.find_callsites_by_source_location(scope(), [("src/app.ts", 42)])
    assert len(batch.all_records) == 1
    assert batch.entries[0].key == "src/app.ts:42"
    assert lookup.find_callsites_by_source_location(scope(), [("src/app.ts", 99)]).all_records == ()


def test_revision_matching_uses_resolved_revision():
    lookup = _lookup(revision="abc123")
    _seed_one(lookup)
    hit = lookup.find_callsites_by_fingerprint(
        scope(
            requested_revision="def456",
            resolved_revision="abc123",
            revision_quality=RevisionQuality.NEAREST_KNOWN,
        ),
        [FP],
    )
    assert len(hit.all_records) == 1
    miss = lookup.find_callsites_by_fingerprint(
        scope(
            requested_revision="def456",
            resolved_revision="zzz999",
            revision_quality=RevisionQuality.NEAREST_KNOWN,
        ),
        [FP],
    )
    assert miss.all_records == ()


def test_batch_serialization_is_deterministic():
    lookup = _lookup()
    _seed_one(lookup, line=10)
    _seed_one(lookup, owner="other", line=20)
    batch = lookup.find_callsites_by_fingerprint(scope(), [FP])
    assert isinstance(batch, LookupBatch)
    first = batch.to_dict()
    second = lookup.find_callsites_by_fingerprint(scope(), [FP]).to_dict()
    assert first == second
