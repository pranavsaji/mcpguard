"""Check tool-call arguments against the *approved* input schema.

Used by the runtime policy gate: a call is compared with the schema recorded in
the reviewed lockfile, not the one the server serves today. That turns the rug
pull into a hard failure at call time — a new ``telemetry`` or ``sidenote``
parameter the model was talked into filling is an *undeclared argument*.

It is a deliberately small subset of JSON Schema (type, enum, const, required,
properties, additionalProperties, patternProperties, items, length / count /
numeric bounds, pattern, anyOf / oneOf / allOf), with one intentional
difference: a property the approved schema does not declare is a problem
unless ``additionalProperties`` explicitly allows it. JSON Schema's
permissive default is exactly the gap an injected field travels through.
``$ref`` is not resolved (the subschema is skipped, not failed). Problems name the
argument and the rule it broke, never the value — they end up in audit logs.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Mapping

__all__ = ["check_arguments"]

_MAX_DEPTH = 32
_MAX_PROBLEMS = 20


def _type_ok(value: object, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    if isinstance(value, bool):
        return False
    if expected == "integer":
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if expected == "number":
        return isinstance(value, (int, float))
    return True  # unknown type keyword: don't fail on what we don't understand


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object" if isinstance(value, dict) else "value"


def check_arguments(arguments: object, schema: Mapping[str, object]) -> list[str]:
    """Problems with ``arguments`` against ``schema``; empty when they conform."""
    problems: list[str] = []
    _check(arguments, schema, "arguments", problems, 0)
    return problems[:_MAX_PROBLEMS]


def _check(value: object, schema: object, path: str, out: list[str], depth: int) -> None:
    if depth > _MAX_DEPTH:
        out.append(f"{path}: nested deeper than {_MAX_DEPTH} levels; not checked")
        return
    if len(out) >= _MAX_PROBLEMS or not isinstance(schema, Mapping):
        return
    if "$ref" in schema:
        return
    declared = schema.get("type")
    types = [declared] if isinstance(declared, str) else declared if isinstance(declared, list) else []
    if types and not any(_type_ok(value, str(t)) for t in types):
        out.append(f"{path}: expected {'/'.join(str(t) for t in types)}, got {_type_name(value)}")
        return
    if "const" in schema and value != schema["const"]:
        out.append(f"{path}: differs from the approved constant")
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        out.append(f"{path}: not one of the approved values")
    _combinators(value, schema, path, out, depth)
    if isinstance(value, str):
        _string(value, schema, path, out)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        _number(value, schema, path, out)
    elif isinstance(value, dict):
        _object(value, schema, path, out, depth)
    elif isinstance(value, list):
        _array(value, schema, path, out, depth)


def _combinators(value: object, schema: Mapping[str, object], path: str, out: list[str], depth: int) -> None:
    for key in ("anyOf", "oneOf"):
        branches = schema.get(key)
        if isinstance(branches, list) and branches and not any(
            _passes(value, b, path, depth) for b in branches
        ):
            out.append(f"{path}: matches none of the approved {key} alternatives")
    branches = schema.get("allOf")
    if isinstance(branches, list):
        for branch in branches:
            _check(value, branch, path, out, depth + 1)


def _passes(value: object, schema: object, path: str, depth: int) -> bool:
    trial: list[str] = []
    _check(value, schema, path, trial, depth + 1)
    return not trial


def _string(value: str, schema: Mapping[str, object], path: str, out: list[str]) -> None:
    max_len, min_len = schema.get("maxLength"), schema.get("minLength")
    if isinstance(max_len, int) and len(value) > max_len:
        out.append(f"{path}: longer than the approved maximum of {max_len}")
    if isinstance(min_len, int) and len(value) < min_len:
        out.append(f"{path}: shorter than the approved minimum of {min_len}")
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and not _pattern_ok(pattern, value):
        out.append(f"{path}: does not match the approved pattern")


def _number(value: float, schema: Mapping[str, object], path: str, out: list[str]) -> None:
    bounds = (
        ("maximum", operator.gt, "above the approved maximum"),
        ("minimum", operator.lt, "below the approved minimum"),
        ("exclusiveMaximum", operator.ge, "at or above the approved limit"),
        ("exclusiveMinimum", operator.le, "at or below the approved limit"),
    )
    for key, violates, message in bounds:
        bound = schema.get(key)
        if isinstance(bound, (int, float)) and not isinstance(bound, bool) and violates(value, bound):
            out.append(f"{path}: {message} ({bound})")


def _object(
    value: dict[str, object], schema: Mapping[str, object], path: str, out: list[str], depth: int
) -> None:
    props = schema.get("properties")
    props = props if isinstance(props, Mapping) else {}
    required = schema.get("required")
    if isinstance(required, list):
        for name in required:
            if isinstance(name, str) and name not in value:
                out.append(f"{path}.{name}: required by the approved schema but missing")
    patterns = schema.get("patternProperties")
    patterns = patterns if isinstance(patterns, Mapping) else {}
    additional = schema.get("additionalProperties")
    for name, item in value.items():
        child = f"{path}.{name}"
        if name in props:
            _check(item, props[name], child, out, depth + 1)
            continue
        matched = False
        for regex, sub in patterns.items():
            if _pattern_ok(str(regex), name, unparseable=False):
                matched = True
                _check(item, sub, child, out, depth + 1)
        if matched:
            continue
        if isinstance(additional, Mapping):
            _check(item, additional, child, out, depth + 1)
        elif additional is not True:
            out.append(f"{child}: undeclared argument (not in the approved schema)")


def _array(value: list[object], schema: Mapping[str, object], path: str, out: list[str], depth: int) -> None:
    max_items, min_items = schema.get("maxItems"), schema.get("minItems")
    if isinstance(max_items, int) and len(value) > max_items:
        out.append(f"{path}: more than the approved maximum of {max_items} items")
    if isinstance(min_items, int) and len(value) < min_items:
        out.append(f"{path}: fewer than the approved minimum of {min_items} items")
    items = schema.get("items")
    if isinstance(items, Mapping):
        for index, item in enumerate(value):
            _check(item, items, f"{path}[{index}]", out, depth + 1)


def _pattern_ok(pattern: str, value: str, *, unparseable: bool = True) -> bool:
    """JSON Schema (ECMA-262) ``pattern`` semantics on Python's engine: ASCII classes,
    and ``$`` must not accept a trailing newline the way Python's does.

    ``unparseable`` is the answer for a pattern Python can't compile — it can't be
    enforced, so a value isn't failed for it (and a property isn't matched by it).
    """
    try:
        match = re.search(pattern, value, re.ASCII)
    except (re.error, OverflowError, RecursionError):
        return unparseable
    if match is None:
        return False
    return not (value.endswith("\n") and "$" in pattern and match.end() == len(value) - 1)
