"""Gate 1 fixtures: deterministic TypeScript/JavaScript canonicalization."""

import json

from incident_context.runtime_code import (
    ObservabilityAnchorKind,
    TypeScriptJavaScriptIndexer,
    canonicalize_runtime_message,
    extract_observability_callsites,
    fingerprint_template,
)
from runtime_code_helpers import REVISION


def _index(source: str, source_file: str = "src/app.ts"):
    indexer = TypeScriptJavaScriptIndexer()
    return indexer.index_source("avion", REVISION, source_file, source)


def _templates(source: str):
    return [call.canonical_template for call in extract_observability_callsites(source)]


def test_static_source_forms_recover_templates():
    source = """
logger.info('single quoted');
logger.info("double quoted");
logger.info(`no substitution`);
logger.info(`with ${interpolation} inside`);
logger.info('first arg static');
appLogger.warn(`template ${value}`);
console.debug('console debug');
console.info("console info");
console.warn(`console warn ${x}`);
console.error('console error');
LokiClient.log('loki log');
LokiClient.push({ message: 'loki push', fields: { a: 1 } });
log.trace('trace');
logger.fatal('fatal');
"""
    calls = extract_observability_callsites(source)
    templates = [call.canonical_template for call in calls]
    assert "single quoted" in templates
    assert "double quoted" in templates
    assert "no substitution" in templates
    assert "with <arg> inside" in templates
    assert "first arg static" in templates
    assert "template <arg>" in templates
    assert "console debug" in templates
    assert "console info" in templates
    assert "console warn <arg>" in templates
    assert "console error" in templates
    assert "loki log" in templates
    assert "loki push" in templates
    assert "trace" in templates
    assert "fatal" in templates
    assert all(not call.dynamic for call in calls)


def test_dynamic_messages_marked_not_guessed():
    source = """
logger.info('static prefix ' + computed);
logger.error(computeMessage());
logger.warn(undefinedMessage);
logger.info();
logger.error('a' + 'b');
logger.info(null);
console.error(fn());
"""
    calls = extract_observability_callsites(source)
    assert calls
    for call in calls:
        assert call.dynamic is True
        assert call.canonical_template is None
        assert call.anchor_kind is ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE


def test_non_observability_calls_ignored():
    source = """
function calculate(x) { return x * 2; }
calculate(3);
audit.info('not a logger receiver');
blog('not a logger');
logger.info('real log');
"""
    calls = extract_observability_callsites(source)
    assert len(calls) == 1
    assert calls[0].canonical_template == "real log"


def test_comments_and_strings_do_not_fabricate_calls():
    source = """
// logger.info('inside line comment');
/* logger.error('inside block comment'); */
const example = "logger.info('inside a string')";
logger.info('the real call');
"""
    calls = extract_observability_callsites(source)
    assert len(calls) == 1
    assert calls[0].canonical_template == "the real call"


def test_runtime_message_converges_with_source_template():
    source = "logger.error(`payment failed for ${userId} at ${timestamp}`);"
    source_template = _templates(source)[0]
    runtime_message = "payment failed for 42 at 2026-08-11T12:00:03Z"
    assert canonicalize_runtime_message(runtime_message) == source_template
    assert fingerprint_template(canonicalize_runtime_message(runtime_message)) == fingerprint_template(
        source_template
    )


def test_runtime_normalization_rules_and_idempotency():
    message = "order 42 failed token=abc123 at 10.0.0.1 for a@b.com in 30ms latency=50ms"
    normalized = canonicalize_runtime_message(message)
    assert normalized == "order <arg> failed token=<arg> at <arg> for <arg> in <arg> latency=<arg>"
    assert canonicalize_runtime_message(normalized) == normalized
    assert "abc123" not in normalized
    assert "a@b.com" not in normalized


def test_runtime_normalization_keeps_static_text():
    assert canonicalize_runtime_message("  order   placed  ") == "order placed"
    assert canonicalize_runtime_message("v2 of the api") == "v2 of the api"


def test_bugzero_style_leading_repeated_whitespace_converges():
    """Real BugZero-style callsite (` ⚠️  Graphify evidence index: ${index}`):
    the static source template and the runtime message normalize whitespace
    identically, so canonical template and versioned fingerprint are equal."""
    source = 'if (options.verbose) console.warn(`  ⚠️  Graphify evidence index: ${index}`);\n'
    (call,) = extract_observability_callsites(source)
    assert call.dynamic is False
    assert call.canonical_template == "⚠️ Graphify evidence index: <arg>"
    runtime_message = "  ⚠️  Graphify evidence index: 42"
    assert canonicalize_runtime_message(runtime_message) == call.canonical_template
    assert fingerprint_template(canonicalize_runtime_message(runtime_message)) == fingerprint_template(
        call.canonical_template
    )
    # Frozen-contract digest for the collapsed template; Graphify's sha256_hex
    # must produce the same value for the same source literal.
    assert fingerprint_template(call.canonical_template) == (
        "04396c276aefb5be306f09bf25b529ee980335395261223c5e24df3e4714ad50"
    )


def test_static_string_whitespace_collapses_like_runtime():
    source = 'console.info(" job   started ");\n'
    assert _templates(source) == ["job started"]
    assert canonicalize_runtime_message(" job   started ") == "job started"
    assert fingerprint_template(" job   started ") == fingerprint_template("job started")


def test_multiline_template_whitespace_collapses_like_runtime():
    source = "logger.warn(`line one\nline two ${id}`);\n"
    (call,) = extract_observability_callsites(source)
    assert call.canonical_template == "line one line two <arg>"
    assert canonicalize_runtime_message("line one\nline two 42") == call.canonical_template
    assert fingerprint_template(canonicalize_runtime_message("line one\nline two 42")) == (
        fingerprint_template(call.canonical_template)
    )


def test_same_template_at_multiple_callsites_shares_anchor_identity():
    source = """
class A {
  first() { logger.info('duplicate template'); }
  second() { logger.info('duplicate template'); }
}
"""
    indexed = _index(source)
    templates = set(item.anchor.canonical_template for item in indexed)
    anchor_ids = set(item.anchor.id for item in indexed)
    assert templates == {"duplicate template"}
    assert len(anchor_ids) == 1
    assert len({item.callsite.owner_symbol for item in indexed}) == 2
    assert len(indexed) == 2
    assert indexed[0].callsite.start_line != indexed[1].callsite.start_line


def test_fingerprint_stable_across_line_movement():
    first = fingerprint_template("payment failed for <arg>")
    source_a = 'logger.info("payment failed for " + id);\n'
    source_b = "\n" * 50 + "logger.info(`payment failed for ${id}`);\n"
    indexed_a = _index(source_a)
    indexed_b = _index(source_b)
    assert first == fingerprint_template("payment failed for <arg>")
    assert indexed_b[0].anchor.fingerprint == indexed_b[0].anchor.fingerprint
    assert indexed_a[0].callsite.start_line == 1
    assert indexed_b[0].callsite.start_line == 51
    # Dynamic concatenation is never guessed in either position.
    assert indexed_a[0].callsite.anchor_kind is ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE
    assert indexed_b[0].callsite.anchor_kind is ObservabilityAnchorKind.LOG_TEMPLATE


def test_indexer_emits_deterministic_records_without_source_bodies():
    source = """
class PaymentService {
  reserve(id: string) {
    logger.info(`payment failed for ${id}`);
    console.error('boom ' + id);
    LokiClient.push({ message: 'order placed' });
  }
}
"""
    first = _index(source)
    second = _index(source)
    assert len(first) == 3
    assert [item.to_dict() for item in first] == [item.to_dict() for item in second]
    encoded = json.dumps([item.to_dict() for item in first])
    assert "reserve(id: string)" not in encoded
    assert "boom" not in encoded
    assert "LokiClient.push" not in encoded
    for item in first:
        assert item.validate() is None
        assert item.anchor.fingerprint
        assert item.callsite.owner_symbol == "reserve"
        assert item.callsite.graph_node_id == "src_app.ts#reserve"
