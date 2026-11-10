"""validated explicit credentials and exact application-grant selection."""

from __future__ import annotations

import base64
import hmac
import ipaddress
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._protocol import TnlError, hostname


def visitor_token(value: object) -> str:
    if isinstance(value, str) and 0 < len(value) <= 2048:
        parts = value.split(".")
        if len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in parts):
            kind, identifier, secret = parts
            if kind in {"vsh1", "vsg1"}:
                prefix = "shr_" if kind == "vsh1" else "shg_"
                if re.fullmatch(prefix + r"[A-Za-z0-9]{22}", identifier) and len(secret) == 43:
                    decoded = base64.urlsafe_b64decode(secret + "=")
                    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") == secret:
                        return value
            elif kind.startswith("ey"):
                # signed permissions remain opaque; the publisher verifies them.
                return value
    raise TnlError("sdk.configuration_invalid", "supply a valid explicit visitor credential")


def https_origin(value: str) -> httpx.URL:
    try:
        url = httpx.URL(value)
        if (
            url.scheme == "https"
            and url.host
            and not url.userinfo
            and not url.query
            and not url.fragment
            and url.raw_path == b"/"
            and str(url) == value == "https://" + url.netloc.decode()
            and len(value) <= 4096
            and "\\" not in value
            and not any(character.isspace() or ord(character) < 32 for character in value)
            and (url.port is None or 1 <= url.port <= 65535)
        ):
            return url
    except (httpx.InvalidURL, ValueError, TypeError):
        pass
    raise TnlError("sdk.configuration_invalid", "select one canonical HTTPS origin without a path")


def opaque_id(value: object, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]{22}", value) is None
    ):
        raise ValueError("identifier")
    return value


def dns_hostname(value: object) -> str:
    name = hostname(value)
    try:
        ipaddress.ip_address(name)
    except ValueError:
        if name.encode("idna").decode() == name:
            return name
    raise ValueError("hostname")


def timestamp(value: object) -> float:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value
        )
        is None
    ):
        raise ValueError("timestamp")
    return datetime.fromisoformat(value).timestamp()


def json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate object field")
    return result


@dataclass(frozen=True, slots=True, repr=False)
class ApplicationGrant:
    id: str
    operation: str
    kind: str
    resource: str
    expires: float


@dataclass(frozen=True, slots=True, repr=False)
class ApplicationDocument:
    control_url: str
    client_id: str
    key_id: str
    team_id: str
    key: Ed25519PrivateKey
    grants: tuple[ApplicationGrant, ...]

    def __repr__(self) -> str:
        return "<tnl application credential (private)>"

    def visit(self, resource: str) -> ApplicationGrant:
        for grant in self.grants:
            if (
                grant.operation == "visit"
                and grant.resource == resource
                and grant.expires > time.time()
            ):
                return grant
        raise TnlError("sdk.credential_denied", "select an exact current application visit grant")


def application_document(value: object) -> ApplicationDocument:
    try:
        if isinstance(value, str):
            if len(value.encode()) > 128 * 1024:
                raise ValueError("document size")
            value = json.loads(value, object_pairs_hook=json_object)
        if not isinstance(value, Mapping) or set(value) != {
            "version",
            "control_url",
            "client_id",
            "key_id",
            "team_id",
            "private_key",
            "grants",
        }:
            raise ValueError("document fields")
        if type(value["version"]) is not int or value["version"] != 1:
            raise ValueError("version")
        control = value["control_url"]
        if not isinstance(control, str):
            raise ValueError("control URL")
        https_origin(control)
        client, key_id = opaque_id(value["client_id"], "pub_"), opaque_id(value["key_id"], "pkey_")
        team = value["team_id"]
        if not isinstance(team, str) or not 0 < len(team) <= 256:
            raise ValueError("team")
        encoded = value["private_key"]
        if not isinstance(encoded, str) or re.fullmatch(r"[A-Za-z0-9_-]{86}", encoded) is None:
            raise ValueError("key")
        raw = base64.urlsafe_b64decode(encoded + "==")
        if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded:
            raise ValueError("key encoding")
        key = Ed25519PrivateKey.from_private_bytes(raw[:32])
        if not hmac.compare_digest(key.public_key().public_bytes_raw(), raw[32:]):
            raise ValueError("key binding")
        records = value["grants"]
        if not isinstance(records, list) or not 0 < len(records) <= 64:
            raise ValueError("grant count")
        grants = []
        ids: set[str] = set()
        bindings: set[tuple[str, str]] = set()
        for record in records:
            if not isinstance(record, Mapping):
                raise ValueError("grant")
            identifier = opaque_id(record.get("id"), "pgrant_")
            kind, operation = record.get("kind"), record.get("operation")
            if kind == "saved_public_url" and operation in {"visit", "publish"}:
                fields = {"public_url_id"}
                resource = opaque_id(record.get("public_url_id"), "url_")
            elif kind == "service" and operation in {"visit", "publish"}:
                fields = {"service_id"}
                resource = opaque_id(record.get("service_id"), "svc_")
            elif kind == "namespace" and operation == "allocate":
                fields = {"domain_id", "namespace"}
                resource = opaque_id(record.get("domain_id"), "dom_")
                dns_hostname(record.get("namespace"))
            else:
                raise ValueError("operation and kind")
            if set(record) - {"expires_at"} != {"id", "operation", "kind"} | fields:
                raise ValueError("grant fields")
            expires = timestamp(record["expires_at"]) if "expires_at" in record else float("inf")
            assert isinstance(operation, str) and isinstance(kind, str)
            binding = (operation, resource)
            if identifier in ids or binding in bindings:
                raise ValueError("duplicate grant")
            ids.add(identifier)
            bindings.add(binding)
            grants.append(ApplicationGrant(identifier, operation, kind, resource, expires))
        return ApplicationDocument(control, client, key_id, team, key, tuple(grants))
    except Exception:
        pass
    # JSON and crypto errors may include private input; never retain their cause.
    raise TnlError("sdk.credential_invalid", "the application credential is invalid") from None
