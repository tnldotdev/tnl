"""bounded capability-authenticated local HTTP shapes."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import cast
from urllib.parse import urlsplit


class TnlError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RegistrationLost(TnlError):
    def __init__(self) -> None:
        super().__init__("sdk.registration_stale", "the local tnl registration was lost")


class NativeUnavailable(TnlError):
    def __init__(self) -> None:
        super().__init__("sdk.dev_unavailable", "the local tnl publisher is unavailable")


class InvalidResponse(TnlError):
    def __init__(self) -> None:
        super().__init__("sdk.response_invalid", "the local publisher returned an invalid response")


@dataclass(frozen=True, slots=True)
class Endpoint:
    url: str
    capability: str = field(repr=False)
    owner_id: str
    scope: str
    service: str | None = None
    invocation_id: str | None = None


def object_value(value: object, keys: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - keys:
        raise InvalidResponse()
    return cast(dict[str, object], value)


def text(value: object, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\0" in value:
        raise InvalidResponse()
    return value


def service_name(value: object) -> str:
    name = text(value, 32)
    if re.fullmatch(r"[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?", name) is None:
        raise InvalidResponse()
    return name


def hostname(value: object) -> str:
    name = text(value, 253)
    if any(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
        for label in name.split(".")
    ):
        raise InvalidResponse()
    return name


def parse_endpoint(
    value: object, *, service: str | None = None, invocation_id: str | None = None
) -> Endpoint:
    obj = object_value(
        value, {"version", "url", "capability", "owner_id", "scope", "service", "invocation_id"}
    )
    url = text(obj.get("url"), 128)
    try:
        parts = urlsplit(url)
        address = ipaddress.ip_address(parts.hostname or "")
        port = parts.port
        authority = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
        if (
            not address.is_loopback
            or port is None
            or not 1 <= port <= 65535
            or url != f"http://{authority}"
        ):
            raise InvalidResponse()
    except ValueError:
        raise InvalidResponse() from None
    capability = text(obj.get("capability"), 64)
    owner = text(obj.get("owner_id"), 32)
    if (
        type(obj.get("version")) is not int
        or obj["version"] != 1
        or re.fullmatch(r"[a-f0-9]{64}", capability) is None
        or re.fullmatch(r"[a-f0-9]{32}", owner) is None
    ):
        raise InvalidResponse()
    if obj.get("scope") == "app":
        name = service_name(obj.get("service"))
        if (
            "invocation_id" in obj
            or invocation_id is not None
            or service is not None
            and name != service
        ):
            raise InvalidResponse()
        return Endpoint(url, capability, owner, "app", service=name)
    ident = text(obj.get("invocation_id"), 128)
    if (
        obj.get("scope") != "invocation"
        or "service" in obj
        or service is not None
        or ident != invocation_id
        or re.fullmatch(r"ivk_[A-Za-z0-9]{22}", ident) is None
    ):
        raise InvalidResponse()
    return Endpoint(url, capability, owner, "invocation", invocation_id=ident)


def parse_registration(value: object, owner: str, target: str) -> dict[str, object]:
    obj = object_value(value, {"version", "registration_id", "owner", "target"})
    ident = text(obj.get("registration_id"), 128)
    if (
        type(obj.get("version")) is not int
        or obj["version"] != 1
        or re.fullmatch(r"reg_[a-f0-9]{32}", ident) is None
        or obj.get("owner") != owner
        or obj.get("target") != target
    ):
        raise InvalidResponse()
    return obj


@dataclass(frozen=True, slots=True)
class Status:
    registered: bool
    routable: bool
    ready: bool
    public_url: str | None
    publish_run_number: int | None
    failure: str | None


def parse_status(value: object, service: str, registration_id: str, target: str) -> Status | None:
    obj = object_value(
        value, {"schema_version", "project", "cursor", "observed_at", "services", "publications"}
    )
    if type(obj.get("schema_version")) is not int or obj["schema_version"] != 1:
        raise InvalidResponse()
    text(obj.get("project"))
    text(obj.get("cursor"), 128)
    try:
        datetime.fromisoformat(text(obj.get("observed_at")))
    except ValueError:
        raise InvalidResponse() from None
    services = obj.get("services")
    publications = obj.get("publications", [])
    if (
        not isinstance(services, list)
        or len(services) > 1
        or not isinstance(publications, list)
        or len(publications) > 64
    ):
        raise InvalidResponse()
    for raw in publications:
        publication = object_value(
            raw,
            {
                "tunnel_id",
                "command",
                "state",
                "process_id",
                "server",
                "project",
                "service",
                "service_protocol",
                "public_url_id",
                "publish_run_number",
                "public_port",
                "hostname",
                "public_url",
                "target",
                "framework",
                "started_at",
                "updated_at",
                "heartbeat_at",
                "lease_expires_at",
                "failure",
            },
        )
        if (
            publication.get("service") != service
            or type(publication.get("process_id")) is not int
            or publication.get("command") not in ("publish", "dev")
            or publication.get("state")
            not in ("starting", "provisioning", "ready", "draining", "stopped", "failed", "stale")
        ):
            raise InvalidResponse()
        for key in (
            "tunnel_id",
            "server",
            "project",
            "started_at",
            "updated_at",
            "heartbeat_at",
            "lease_expires_at",
        ):
            text(publication.get(key))
        for key, field_value in publication.items():
            if key in {"process_id", "publish_run_number", "public_port"}:
                if type(field_value) is not int or not 1 <= field_value <= 2**53 - 1:
                    raise InvalidResponse()
            else:
                text(field_value)
    if not services:
        return None
    item = object_value(
        services[0],
        {
            "project",
            "service",
            "service_protocol",
            "directory",
            "tunnel_id",
            "public_url",
            "registration_id",
            "target",
            "framework",
            "registered",
            "routable",
            "ready",
            "publish_run_number",
            "provisioning_stage",
            "readiness",
            "observation",
            "failure",
        },
    )
    if item.get("service") != service or item.get("service_protocol", "http") != "http":
        raise InvalidResponse()
    text(item.get("directory"))
    for key in (
        "project",
        "tunnel_id",
        "registration_id",
        "target",
        "framework",
        "provisioning_stage",
        "failure",
    ):
        if key in item:
            text(item[key])
    for key in ("registered", "routable", "ready"):
        if type(item.get(key)) is not bool:
            raise InvalidResponse()
    readiness = object_value(item.get("readiness"), {"path"})
    if not text(readiness.get("path")).startswith("/"):
        raise InvalidResponse()
    number = item.get("publish_run_number")
    if number is not None and (type(number) is not int or not 1 <= number <= 2**53 - 1):
        raise InvalidResponse()
    public_url = item.get("public_url")
    if public_url is not None:
        url = text(public_url)
        try:
            expected = f"https://{hostname(urlsplit(url).hostname)}"
        except ValueError:
            raise InvalidResponse() from None
        if url != expected:
            raise InvalidResponse()
    if "observation" in item:
        observation = object_value(
            item["observation"],
            {
                "registration_id",
                "publish_run_number",
                "checked_at",
                "status",
                "ready",
                "reason",
                "readiness",
            },
        )
        observed_path = object_value(observation.get("readiness"), {"path"})
        if not text(observed_path.get("path")).startswith("/"):
            raise InvalidResponse()
        text(observation.get("registration_id"), 128)
        try:
            datetime.fromisoformat(text(observation.get("checked_at")))
        except ValueError:
            raise InvalidResponse() from None
        if (
            type(observation.get("ready")) is not bool
            or type(observation.get("publish_run_number")) is not int
        ):
            raise InvalidResponse()
        observed_run = observation["publish_run_number"]
        if not isinstance(observed_run, int) or not 1 <= observed_run <= 2**53 - 1:
            raise InvalidResponse()
        if "status" in observation:
            status = observation["status"]
            if type(status) is not int or not 100 <= status <= 599:
                raise InvalidResponse()
        if "reason" in observation:
            text(observation["reason"])
        if item["ready"] and (
            observation["registration_id"] != registration_id
            or observation["publish_run_number"] != number
            or not observation["ready"]
        ):
            raise InvalidResponse()
    elif item["ready"]:
        raise InvalidResponse()
    if item.get("registration_id") != registration_id or item.get("target") != target:
        return None
    if item["routable"] and (not item["registered"] or number is None):
        raise InvalidResponse()
    return Status(
        cast(bool, item["registered"]),
        cast(bool, item["routable"]),
        cast(bool, item["ready"]),
        cast(str | None, public_url),
        cast(int | None, number),
        cast(str | None, item.get("failure")),
    )
