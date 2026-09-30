"""A small, dependency-free validator for the JSON Schema subset used by the conformance files.

Supported keywords: ``type`` (a name or a list of names), ``properties``, ``required``,
``additionalProperties`` (``false`` or a schema), ``items``, ``minItems``, ``uniqueItems``,
``enum``, ``const``, ``pattern``, ``minLength``, ``minimum``. Anything else in a schema is
refused up front, so a keyword this validator silently ignores can never make a document look
valid. Errors are returned as ``"<json pointer>: <rule>"`` strings in document order.
"""

import json
import re


SUPPORTED = {
    "$schema", "$id", "title", "description", "type", "properties", "required",
    "additionalProperties", "items", "minItems", "uniqueItems", "enum", "const", "pattern",
    "minLength", "minimum",
}
TYPES = {
    "object": lambda value: isinstance(value, dict),
    "array": lambda value: isinstance(value, list),
    "string": lambda value: isinstance(value, str),
    "integer": lambda value: isinstance(value, int) and not isinstance(value, bool),
    "number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
    "boolean": lambda value: isinstance(value, bool),
    "null": lambda value: value is None,
}


class SchemaError(ValueError):
    """The schema itself uses a keyword this validator does not implement."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def check_schema(schema, pointer=""):
    """Refuse a schema that relies on keywords outside the supported subset."""
    if not isinstance(schema, dict):
        raise SchemaError(f"{pointer or '/'}: schema must be an object")
    unsupported = sorted(set(schema) - SUPPORTED)
    if unsupported:
        raise SchemaError(f"{pointer or '/'}: unsupported schema keyword(s) {', '.join(unsupported)}")
    for name, child in schema.get("properties", {}).items():
        check_schema(child, f"{pointer}/properties/{name}")
    if isinstance(schema.get("additionalProperties"), dict):
        check_schema(schema["additionalProperties"], f"{pointer}/additionalProperties")
    if "items" in schema:
        check_schema(schema["items"], f"{pointer}/items")


def validate(instance, schema, pointer=""):
    """Return the list of violations of ``instance`` against ``schema`` (empty when valid)."""
    errors = []
    where = pointer or "/"
    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        if not any(TYPES[name](instance) for name in names):
            errors.append(f"{where}: expected type {' or '.join(names)}")
            return errors
    if "const" in schema and _canonical(instance) != _canonical(schema["const"]):
        errors.append(f"{where}: must equal the constant value")
    if "enum" in schema and _canonical(instance) not in {_canonical(item) for item in schema["enum"]}:
        errors.append(f"{where}: must be one of the enumerated values")
    if isinstance(instance, str):
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            errors.append(f"{where}: does not match the required pattern")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{where}: shorter than the minimum length")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{where}: below the minimum")
    if isinstance(instance, dict):
        for name in schema.get("required", []):
            if name not in instance:
                errors.append(f"{where}: missing required property {name}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for name, value in instance.items():
            child = f"{pointer}/{name}"
            if name in properties:
                errors.extend(validate(value, properties[name], child))
            elif additional is False:
                errors.append(f"{child}: property is not allowed")
            elif isinstance(additional, dict):
                errors.extend(validate(value, additional, child))
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{where}: fewer items than the minimum")
        if schema.get("uniqueItems"):
            seen = set()
            for index, item in enumerate(instance):
                key = _canonical(item)
                if key in seen:
                    errors.append(f"{pointer}/{index}: duplicates an earlier item")
                seen.add(key)
        if "items" in schema:
            for index, item in enumerate(instance):
                errors.extend(validate(item, schema["items"], f"{pointer}/{index}"))
    return errors
