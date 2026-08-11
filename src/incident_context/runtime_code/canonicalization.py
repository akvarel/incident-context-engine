"""TypeScript/JavaScript v1 source and runtime canonicalization.

The canonicalization version is ``runtime-code-canonicalization/v1``.

Source forms that are statically recoverable:

- string literals (cooked);
- no-substitution template literals (cooked);
- template literals with substitutions, each substitution replaced by
  ``<arg>``;
- ``console.debug/info/warn/error`` first argument;
- structured BugZero ``LokiClient.log/push`` message literals, including an
  object-literal ``{ message: <literal> }`` form;
- common logger calls with a static first message argument (receivers named
  ``log``/``logger`` or ending in ``logger``, methods
  ``debug/info/warn/error/log/trace/fatal``).

Dynamic concatenation, unknown functions, computed message expressions, or
any first argument that is not exactly one recoverable literal is marked
``DYNAMIC_LOG_CALLSITE``; the system never guesses a template.

Runtime normalization replaces volatile values with ``<arg>`` through the
same deterministic rule family used by log-pattern normalization so that
source and runtime forms converge to the same canonical template.  The rules
are ordered and documented; the result is idempotent.

The scanner is a documented deterministic lexer, not a full ECMAScript
parser.  It deliberately treats any first argument that is not exactly one
recoverable literal as dynamic so it never fabricates a template from code it
cannot prove static.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .models import ObservabilityAnchorKind

# ---------------------------------------------------------------------------
# Runtime canonicalization
# ---------------------------------------------------------------------------
#
# Ordered deterministic rules.  Every rule replaces a volatile value with the
# placeholder ``<arg>`` so runtime messages converge with source templates
# that substitute ``<arg>`` for interpolated values.  Sensitive values are
# replaced wholesale (never preserved) so canonical templates never embed
# credentials.  ``key=value`` rules keep the static key and replace the value.

_RUNTIME_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?i)(\b(?:authorization|token|secret|password|api[_-]?key)[=:]\s*)\S+"),
        r"\1<arg>",
    ),
    (
        re.compile(
            r"(?i)(\b(?:trace_id|span_id|request_id|correlation_id|session_id|"
            r"order_id|user_id|shard|id)[=:]\s*)\S+"
        ),
        r"\1<arg>",
    ),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "<arg>"),
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
        ),
        "<arg>",
    ),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<arg>"),
    (
        re.compile(
            r"\b\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
        ),
        "<arg>",
    ),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "<arg>"),
    (
        re.compile(r"(?i)(\b(?:duration|timeout|latency)[=:]\s*)\d+(?:\.\d+)?(?:ms|s|m|h)?\b"),
        r"\1<arg>",
    ),
    (
        re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|m|h|%|bytes?|kb|mb|gb|tb|req|rps)?\b"),
        "<arg>",
    ),
    (
        re.compile(r"(?<![0-9a-fA-F])(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{7,40}(?![0-9a-fA-F])"),
        "<arg>",
    ),
)


def canonicalize_runtime_message(message: str) -> str:
    """Deterministically normalize a runtime message to its canonical template.

    Volatile values are replaced with ``<arg>`` so the result converges with
    the canonical template recovered from source.  Sensitive values are never
    preserved.  The transformation is idempotent.
    """
    result = str(message)
    for pattern, replacement in _RUNTIME_RULES:
        result = pattern.sub(replacement, result)
    return re.sub(r"\s+", " ", result).strip()


# ---------------------------------------------------------------------------
# Source lexer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceToken:
    """One deterministic source token.

    ``kind`` is one of ``STRING``, ``TEMPLATE``, ``IDENT``, ``NUMBER``,
    ``PUNCT``, or ``REGEX``.  For ``STRING`` and ``TEMPLATE`` the ``value`` is
    the cooked literal text; template substitutions are already replaced with
    ``<arg>``.  All other kinds carry the raw source text.
    """

    kind: str
    value: str
    start: int
    end: int


_TEMPLATE_SUBSTITUTION = "<arg>"

_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "`": "`",
}


def _cook_escape(source: str, index: int) -> tuple[str, int]:
    """Cook one escape sequence starting at ``source[index] == '\\\\'``."""
    if index + 1 >= len(source):
        return "\\", index + 1
    char = source[index + 1]
    if char in _ESCAPES:
        return _ESCAPES[char], index + 2
    if char == "\n":
        return "", index + 2
    if char == "\r" and index + 2 < len(source) and source[index + 2] == "\n":
        return "", index + 3
    if char in "xX":
        end = min(index + 4, len(source))
        hex_text = source[index + 2 : end]
        if re.fullmatch(r"[0-9a-fA-F]{2}", hex_text):
            return chr(int(hex_text, 16)), end
        return "x", index + 2
    if char in "uU":
        if index + 2 < len(source) and source[index + 2] == "{":
            close = source.find("}", index + 3)
            if close != -1 and 1 <= close - (index + 3) <= 6:
                hex_text = source[index + 3 : close]
                if re.fullmatch(r"[0-9a-fA-F]+", hex_text):
                    return chr(int(hex_text, 16)), close + 1
            return "u", index + 2
        hex_text = source[index + 2 : index + 6]
        if re.fullmatch(r"[0-9a-fA-F]{4}", hex_text):
            return chr(int(hex_text, 16)), index + 6
        return "u", index + 2
    # Unknown escapes preserve the escaped character (JavaScript semantics).
    return char, index + 2


def _scan_string(source: str, start: int, quote: str) -> tuple[str, int]:
    cooked: list[str] = []
    index = start + 1
    while index < len(source):
        char = source[index]
        if char == "\\":
            escaped, index = _cook_escape(source, index)
            cooked.append(escaped)
            continue
        if char == quote:
            return "".join(cooked), index + 1
        if char in "\n\r":
            # Unterminated string: deterministic recovery to end of input.
            return "".join(cooked), len(source)
        cooked.append(char)
        index += 1
    return "".join(cooked), len(source)


def _scan_template(source: str, start: int) -> tuple[str, int]:
    cooked: list[str] = []
    index = start + 1
    while index < len(source):
        char = source[index]
        if char == "\\":
            escaped, index = _cook_escape(source, index)
            cooked.append(escaped)
            continue
        if char == "`":
            return "".join(cooked), index + 1
        if source.startswith("${", index):
            end = _scan_substitution_end(source, index + 2)
            cooked.append(_TEMPLATE_SUBSTITUTION)
            index = end
            continue
        cooked.append(char)
        index += 1
    return "".join(cooked), len(source)


def _scan_substitution_end(source: str, start: int) -> int:
    """Return the index just past the ``}`` closing a ``${...}`` substitution."""
    depth = 1
    index = start
    while index < len(source):
        char = source[index]
        if char in ("'", '"'):
            _, index = _scan_string(source, index, char)
            continue
        if char == "`":
            _, index = _scan_template(source, index)
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index)
            index = len(source) if newline == -1 else newline + 1
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            index = len(source) if close == -1 else close + 2
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return len(source)


def _scan_regex(source: str, start: int) -> int:
    index = start + 1
    in_class = False
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            return index + 1
        elif char in "\n\r":
            return len(source)
        index += 1
    return len(source)


_EXPRESSION_POSITION = {
    "(",
    "[",
    "{",
    ",",
    ";",
    ":",
    "=",
    "=>",
    "?",
    "&&",
    "||",
    "!",
    "+",
    "-",
    "*",
    "%",
    "&",
    "|",
    "^",
    "~",
    "<",
    ">",
    "===",
    "==",
    "!=",
    "!==",
    "<=",
    ">=",
    "**",
    "...",
    "??",
    "?.",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "&=",
    "|=",
    "^=",
    "??=",
    "&&=",
    "||=",
    ">>>",
    ">>",
    "<<",
}
_EXPRESSION_KEYWORDS = {
    "return",
    "case",
    "throw",
    "delete",
    "typeof",
    "void",
    "new",
    "in",
    "instanceof",
    "yield",
    "await",
    "else",
    "do",
}


def _starts_regex(source: str, index: int, tokens: list[SourceToken]) -> bool:
    if index + 1 >= len(source) or source[index + 1] in ("/", "*"):
        return False
    if not tokens:
        return True
    previous = tokens[-1]
    if previous.kind == "REGEX":
        return False
    if previous.kind == "PUNCT":
        return previous.value in _EXPRESSION_POSITION
    if previous.kind == "IDENT":
        return previous.value in _EXPRESSION_KEYWORDS
    return False


def tokenize_source(source: str) -> list[SourceToken]:
    """Deterministically tokenize TypeScript/JavaScript source text."""
    tokens: list[SourceToken] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char in " \t\r\n\f\v":
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index)
            index = length if newline == -1 else newline + 1
            continue
        if source.startswith("/*", index):
            close = source.find("*/", index + 2)
            index = length if close == -1 else close + 2
            continue
        if char in ("'", '"'):
            cooked, end = _scan_string(source, index, char)
            tokens.append(SourceToken("STRING", cooked, index, end))
            index = end
            continue
        if char == "`":
            cooked, end = _scan_template(source, index)
            tokens.append(SourceToken("TEMPLATE", cooked, index, end))
            index = end
            continue
        if char == "/" and _starts_regex(source, index, tokens):
            end = _scan_regex(source, index)
            tokens.append(SourceToken("REGEX", source[index:end], index, end))
            index = end
            continue
        if char.isalpha() or char in "_$":
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] in "_$"):
                end += 1
            tokens.append(SourceToken("IDENT", source[index:end], index, end))
            index = end
            continue
        if char.isdigit() or (char == "." and index + 1 < length and source[index + 1].isdigit()):
            end = index + 1
            while end < length and (source[end].isalnum() or source[end] in "._"):
                end += 1
            tokens.append(SourceToken("NUMBER", source[index:end], index, end))
            index = end
            continue
        matched = False
        for operator in (
            "===",
            "!==",
            ">>>",
            "=>",
            "?.",
            "??",
            "**",
            "&&",
            "||",
            "++",
            "--",
            "==",
            "!=",
            "<=",
            ">=",
            "<<",
            ">>",
            "+=",
            "-=",
            "*=",
            "/=",
            "%=",
            "&=",
            "|=",
            "^=",
            "??=",
            "&&=",
            "||=",
            "...",
        ):
            if source.startswith(operator, index):
                tokens.append(SourceToken("PUNCT", operator, index, index + len(operator)))
                index += len(operator)
                matched = True
                break
        if matched:
            continue
        tokens.append(SourceToken("PUNCT", char, index, index + 1))
        index += 1
    return tokens


# ---------------------------------------------------------------------------
# Owner-symbol tracking (documented heuristic)
# ---------------------------------------------------------------------------


def _matching_paren(tokens: list[SourceToken], open_index: int) -> int | None:
    depth = 0
    for index in range(open_index, len(tokens)):
        token = tokens[index]
        if token.kind != "PUNCT":
            continue
        if token.value == "(":
            depth += 1
        elif token.value == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _method_lookahead(tokens: list[SourceToken], index: int) -> bool:
    """Return whether ``IDENT ( ... ) {`` starts a method-like declaration."""
    if index + 1 >= len(tokens) or tokens[index + 1].kind != "PUNCT" or tokens[index + 1].value != "(":
        return False
    close = _matching_paren(tokens, index + 1)
    if close is None or close + 1 >= len(tokens):
        return False
    following = tokens[close + 1]
    return following.kind == "PUNCT" and following.value == "{"


def _owner_symbols(tokens: list[SourceToken]) -> list[str]:
    """Deterministic enclosing-symbol heuristic for every token.

    Class names, named/anonymous functions, methods, and ``const/let/var``
    arrow assignments push a scope that closes with the matching ``}``.
    Unenclosed code belongs to ``<module>``.
    """
    depth = 0
    stack: list[tuple[str, int]] = []
    pending: str | None = None
    owners: list[str] = []
    for index, token in enumerate(tokens):
        if token.kind == "PUNCT":
            if token.value == "{":
                if pending is not None:
                    stack.append((pending, depth + 1))
                    pending = None
                depth += 1
            elif token.value == "}":
                depth -= 1
                while stack and stack[-1][1] > depth:
                    stack.pop()
        elif token.kind == "IDENT":
            if token.value == "class" and index + 1 < len(tokens) and tokens[index + 1].kind == "IDENT":
                pending = tokens[index + 1].value
            elif token.value == "function" and index + 1 < len(tokens) and tokens[index + 1].kind == "IDENT":
                pending = tokens[index + 1].value
            elif token.value == "function":
                pending = "<anonymous>"
            elif (
                token.value in {"const", "let", "var"}
                and index + 2 < len(tokens)
                and tokens[index + 1].kind == "IDENT"
                and tokens[index + 2].kind == "PUNCT"
                and tokens[index + 2].value == "="
            ):
                pending = tokens[index + 1].value
            elif _method_lookahead(tokens, index):
                pending = token.value
        owners.append(stack[-1][0] if stack else "<module>")
    return owners


# ---------------------------------------------------------------------------
# Callsite extraction
# ---------------------------------------------------------------------------

_CONSOLE_METHODS = {"debug", "info", "warn", "error"}
_LOKICLIENT_METHODS = {"log", "push"}
_LOGGER_METHODS = {"debug", "info", "warn", "error", "log", "trace", "fatal"}
_SEPARATORS = {".", "?."}


def _is_logger_receiver(name: str) -> bool:
    lower = name.lower()
    return lower in {"log", "logger"} or lower.endswith("logger")


@dataclass(frozen=True)
class ObservabilityCall:
    """One statically detected observability callsite."""

    logger: str
    method: str
    start_line: int
    end_line: int
    owner_symbol: str
    canonical_template: str | None
    dynamic: bool
    anchor_kind: ObservabilityAnchorKind


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _extract_first_argument(
    tokens: list[SourceToken], open_index: int, close_index: int
) -> tuple[list[SourceToken], int]:
    """Return the first-argument token slice and its end index (exclusive).

    The first argument ends at the first top-level comma or the closing
    parenthesis; nested braces, brackets, and parentheses are respected.
    """
    end = close_index if close_index is not None else len(tokens)
    depth = 0
    for index in range(open_index + 1, end):
        token = tokens[index]
        if token.kind != "PUNCT":
            continue
        if token.value in ("(", "[", "{"):
            depth += 1
        elif token.value in (")", "]", "}"):
            depth -= 1
        elif token.value == "," and depth == 0:
            return tokens[open_index + 1 : index], index
    return tokens[open_index + 1 : end], end


def _static_literal(arguments: list[SourceToken]) -> str | None:
    """Return the canonical template when the first argument is recoverable.

    Accepts exactly one string/template literal, or an object literal of the
    structured form ``{ message: <literal> }``.  Anything else is dynamic.
    """
    if len(arguments) == 1 and arguments[0].kind in ("STRING", "TEMPLATE"):
        return arguments[0].value
    if len(arguments) >= 5:
        first = arguments[0]
        last = arguments[-1]
        if first.kind == "PUNCT" and first.value == "{" and last.kind == "PUNCT" and last.value == "}":
            for index in range(len(arguments) - 2):
                key = arguments[index]
                colon = arguments[index + 1]
                literal = arguments[index + 2]
                if (
                    key.kind == "IDENT"
                    and key.value == "message"
                    and colon.kind == "PUNCT"
                    and colon.value == ":"
                    and literal.kind in ("STRING", "TEMPLATE")
                ):
                    return literal.value
    return None


def extract_observability_callsites(source: str) -> tuple[ObservabilityCall, ...]:
    """Return deterministically ordered observability callsites in ``source``.

    Malformed or exotic constructs never fabricate a template: any first
    argument that is not exactly one recoverable literal yields a
    ``DYNAMIC_LOG_CALLSITE`` record.
    """
    tokens = tokenize_source(source)
    owners = _owner_symbols(tokens)
    calls: list[ObservabilityCall] = []
    for index, token in enumerate(tokens):
        if token.kind != "IDENT":
            continue
        matched: tuple[str, str] | None = None
        if index + 3 < len(tokens):
            separator = tokens[index + 1]
            method_token = tokens[index + 2]
            open_token = tokens[index + 3]
            if (
                separator.kind == "PUNCT"
                and separator.value in _SEPARATORS
                and method_token.kind == "IDENT"
                and open_token.kind == "PUNCT"
                and open_token.value == "("
            ):
                if token.value == "console" and method_token.value in _CONSOLE_METHODS:
                    matched = ("console", method_token.value)
                elif token.value == "LokiClient" and method_token.value in _LOKICLIENT_METHODS:
                    matched = ("LokiClient", method_token.value)
                elif _is_logger_receiver(token.value) and method_token.value in _LOGGER_METHODS:
                    matched = (token.value, method_token.value)
        if matched is None:
            continue
        logger, method = matched
        open_index = index + 3
        close_index = _matching_paren(tokens, open_index)
        arguments, _ = _extract_first_argument(tokens, open_index, close_index)
        template = _static_literal(arguments)
        end_offset = tokens[close_index].end if close_index is not None else tokens[-1].end
        calls.append(
            ObservabilityCall(
                logger=logger,
                method=method,
                start_line=_line_of(source, token.start),
                end_line=_line_of(source, end_offset),
                owner_symbol=owners[index],
                canonical_template=template,
                dynamic=template is None,
                anchor_kind=(
                    ObservabilityAnchorKind.DYNAMIC_LOG_CALLSITE
                    if template is None
                    else ObservabilityAnchorKind.LOG_TEMPLATE
                ),
            )
        )
    return tuple(calls)


__all__ = [
    "ObservabilityCall",
    "SourceToken",
    "canonicalize_runtime_message",
    "extract_observability_callsites",
    "tokenize_source",
]
