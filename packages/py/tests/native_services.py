"""normal environment constructor fixture with the generated checked typing hook."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import tnl
from tnl._connections import _EnvironmentClient, _object, _text
from tnl._environment import _NativeSelection
from tnl._identity_validation import is_source
from tnl._service_facts import _bind_services


class Client(_EnvironmentClient):
    async def connect(self, service: Literal["api"]) -> tnl.HTTPConnection:
        connection = await self._connect(service)
        assert isinstance(connection, tnl.HTTPConnection)
        return connection


services = _bind_services({"api": {"protocol": "http"}}, Client)


def new_client(token: str | None = None, *, acquisition: tnl.NativeAcquisition | None = None) -> Client:
    value: object = json.loads(Path("environment.json").read_text())
    request = _object(value, {"schema", "selection", "source"})
    assert request.get("schema") == 1 and type(request.get("schema")) is int
    selection = _object(request.get("selection"), {"environment", "permission_id", "services"})
    assert selection.get("services") == {"api": "http"}
    reference = _object(selection.get("environment"), {"server", "project_key", "environment_id"})
    environment = tnl.EnvironmentReference(_text(reference.get("server")), _text(reference.get("project_key")), _text(reference.get("environment_id")))
    source = request.get("source")
    assert is_source(source) and source["kind"] == "oidc"

    async def assertion() -> tnl.OIDCAssertion:
        assert token is not None
        encoded = token.split(".")[1]
        claims: object = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        assert isinstance(claims, dict) and type(claims.get("exp")) is int
        # declared expiry bounds acquisition only; authority verifies the proof.
        return tnl.OIDCAssertion(token, datetime.fromtimestamp(claims["exp"], UTC))

    identity = tnl.IdentitySource("oidc", source["machine_id"], assertion if acquisition is None else None, acquisition=acquisition, permission_id=_text(selection.get("permission_id")))
    return tnl.client(services=services, environment=environment, identity=identity)


def actual_owner(client: Client) -> Path:
    context = client._selection
    assert isinstance(context, _NativeSelection)
    owners = [owner for owner in context._owners if not owner.stopped]
    assert len(owners) == 1 and owners[0].ipc is not None
    return Path(owners[0].ipc._filename)


def context(client: Client) -> _NativeSelection:
    selection = client._selection
    assert isinstance(selection, _NativeSelection)
    return selection
