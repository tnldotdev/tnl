"""validate the generated defining authority schemas, not a parallel challenge model."""

from __future__ import annotations

import json
import re
from datetime import datetime
from importlib.resources import files
from typing import TypeGuard, cast

from ._identity_models import IdentitySourceChallenge, IdentitySourceReply, IdentitySourceSelection


def _object(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        return None
    return cast(dict[str, object], value)


_raw: object = json.loads(files("tnl").joinpath("_identity_schemas.json").read_text())
_schemas = _object(_raw)
if _schemas is None:
    raise RuntimeError("invalid generated identity schemas")


def _matches(value: object, raw: object) -> bool:
    if type(raw) is bool:
        return raw
    schema = _object(raw)
    if schema is None:
        return False
    reference = schema.get("$ref")
    if isinstance(reference, str):
        assert _schemas is not None
        return _matches(value, _schemas.get(reference.rsplit("/", 1)[-1]))
    enum = schema.get("enum")
    if isinstance(enum, list) and not any(type(item) is type(value) and item == value for item in enum):
        return False
    if "const" in schema and (type(value) is not type(schema["const"]) or value != schema["const"]):
        return False
    one = schema.get("oneOf")
    if isinstance(one, list) and sum(_matches(value, child) for child in one) != 1:
        return False
    if "not" in schema and _matches(value, schema["not"]):
        return False
    if "if" in schema:
        branch = "then" if _matches(value, schema["if"]) else "else"
        if branch in schema and not _matches(value, schema[branch]):
            return False
    kind = schema.get("type")
    if kind == "string":
        if not isinstance(value, str):
            return False
        minimum, maximum, pattern = (schema.get(key) for key in ("minLength", "maxLength", "pattern"))
        if isinstance(minimum, int) and len(value) < minimum or isinstance(maximum, int) and len(value) > maximum:
            return False
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            return False
        if schema.get("format") == "date-time":
            try:
                if datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
                    return False
            except ValueError:
                return False
    if kind == "integer" and type(value) is not int:
        return False
    if kind == "boolean" and type(value) is not bool:
        return False
    if kind == "object" or "properties" in schema or "required" in schema:
        item = _object(value)
        if item is None:
            return False
        minimum, maximum = schema.get("minProperties"), schema.get("maxProperties")
        if isinstance(minimum, int) and len(item) < minimum or isinstance(maximum, int) and len(item) > maximum:
            return False
        required = schema.get("required", [])
        if not isinstance(required, list) or any(key not in item for key in required):
            return False
        properties = _object(schema.get("properties", {}))
        if properties is None:
            return False
        for key, child in item.items():
            if key in properties:
                if not _matches(child, properties[key]):
                    return False
            elif "additionalProperties" in schema and not _matches(child, schema["additionalProperties"]):
                return False
    return True


def is_source(value: object) -> TypeGuard[IdentitySourceSelection]:
    assert _schemas is not None
    return _matches(value, _schemas["IdentitySourceSelection"])


def is_challenge(value: object) -> TypeGuard[IdentitySourceChallenge]:
    assert _schemas is not None
    return _matches(value, _schemas["IdentitySourceChallenge"])


def is_reply(value: object) -> TypeGuard[IdentitySourceReply]:
    assert _schemas is not None
    return _matches(value, _schemas["IdentitySourceReply"])
