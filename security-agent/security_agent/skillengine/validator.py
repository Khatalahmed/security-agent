"""Minimal JSON-schema-subset validator (pure stdlib).

Supports exactly what the skill finding schemas use: object `type`, a
`required` list, per-property `type` (string/number/integer/boolean/array/object)
and string `enum`. This avoids a jsonschema dependency while still rejecting
model output that drifts from a skill's declared finding shape.
"""
from __future__ import annotations

_PYTYPES = {
    "string": str, "number": (int, float), "integer": int,
    "boolean": bool, "array": list, "object": dict,
}


def validate_item(item, schema: dict) -> list[str]:
    """Return a list of human-readable errors ([] means valid).

    An empty schema ({}) accepts anything except a non-object top level when the
    schema explicitly asks for type=object.
    """
    errors: list[str] = []
    if not schema:
        return errors

    if schema.get("type") == "object" and not isinstance(item, dict):
        return [f"expected object, got {type(item).__name__}"]

    if isinstance(item, dict):
        for req in schema.get("required", []):
            if req not in item or item[req] in (None, ""):
                errors.append(f"missing required field '{req}'")

        props = schema.get("properties", {})
        for key, spec in props.items():
            if key not in item:
                continue
            val = item[key]
            want = spec.get("type")
            pytype = _PYTYPES.get(want)
            if pytype and not isinstance(val, pytype):
                errors.append(f"field '{key}' should be {want}, got {type(val).__name__}")
                continue
            enum = spec.get("enum")
            if enum and val not in enum:
                errors.append(f"field '{key}'={val!r} not in {enum}")
    return errors


def is_valid(item, schema: dict) -> bool:
    return not validate_item(item, schema)
