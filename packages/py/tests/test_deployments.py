"""deployment handles capture selection and join only their own native work."""

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tnl
from tnl import _connections, _deployments


def test_local_deployment_requires_no_credential_and_reuses_driver_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    stopped: list[_connections._Scope] = []
    monkeypatch.setattr(_connections._Scope, "binary", lambda _self: Path("/fixture/tnl"))
    monkeypatch.setattr(_connections._Scope, "stop", lambda scope: stopped.append(scope))

    def command(_binary: Path, *args: str, input_value: object = None) -> object:
        calls.append(args)
        return {
            "schema": 1,
            "protocol": "postgres",
            "host": "127.0.0.1",
            "port": 15432,
            "binding": "a" * 64,
        }

    monkeypatch.setattr(_deployments, "_command", command)

    async def run() -> None:
        local = tnl.create_client(
            project="acme/shop", services={"db": {"protocol": "postgres"}}
        ).deployment("local")
        connection = await local.connect("db")
        assert isinstance(connection, tnl.LocalPostgresConnection)
        assert connection.ssl is False
        created: list[object] = []
        closed: list[object] = []

        def create(value: _deployments.DeploymentConnection) -> object:
            client = object()
            created.append(client)
            return client

        database = local.client("db", create=create, close=closed.append)
        assert await database() is await database()
        assert len(created) == 1
        await local.aclose()
        assert closed == created
        assert all(args[0] == "local" for args in calls)

    asyncio.run(run())


@pytest.mark.parametrize(
    "deployment_id", ["dpl_0123456789ABCDEFGHIJKL", "dpl_abcdefghijklmnopqrstuv"]
)
def test_remote_selections_are_independent_and_do_not_read_provider_configuration(
    monkeypatch: pytest.MonkeyPatch,
    deployment_id: str,
) -> None:
    selected: list[dict[str, object] | None] = []
    stopped: list[_connections._Scope] = []
    monkeypatch.setattr(_connections._Scope, "stop", lambda scope: stopped.append(scope))

    def prepare(
        scope: _connections._Scope, service: str, selection: object = None
    ) -> tuple[_connections.Connection, _connections._Session]:
        selected.append(scope.deployment)
        assert selection is None
        assert service == "cache"
        return _connections.TCPConnection(
            "127.0.0.1",
            12345,
            datetime.now(UTC) + timedelta(minutes=1),
            _transport_id="ctg_" + "a" * 22,
        ), _connections._Session(scope, "/fixture/handle.json")

    monkeypatch.setattr(_connections._Scope, "prepare", prepare)

    async def run() -> None:
        client = tnl.create_client(
            project="acme/shop", services={"cache": {"protocol": "tcp"}}, token="private-credential"
        )
        first, sibling = client.deployment("production"), client.deployment(deployment_id)
        await first.connect("cache")
        await sibling.connect("cache")
        assert selected[0] is not selected[1]
        assert selected[0] is not None and selected[0]["name"] == "production"
        assert selected[1] is not None and selected[1]["name"] == deployment_id
        assert "private-credential" not in repr(first)
        await first.aclose()
        assert stopped == [first._scope]
        await sibling.connect("cache")
        await sibling.aclose()
        assert stopped == [first._scope, sibling._scope]
        with pytest.raises(tnl.TnlError) as failure:
            await first.connect("cache")
        assert failure.value.code == "sdk.connection_closed"

    asyncio.run(run())


@pytest.mark.parametrize(
    "name",
    [
        "",
        "dpl_short",
        "dpl_" + "a" * 23,
        "dpl_" + "a" * 21 + "-",
        "dpl_" + "a" * 21 + "é",
        "dpl_" + "a" * 22 + "\n",
        "svc_" + "a" * 22,
    ],
)
def test_invalid_deployment_selection_is_rejected_before_native_startup(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def prepare(*_args: object) -> None:
        pytest.fail("invalid selection started native work")

    monkeypatch.setattr(_connections._Scope, "prepare", prepare)
    client = tnl.create_client(
        project="acme/shop", services={"cache": {"protocol": "tcp"}}, token="private-credential"
    )
    with pytest.raises(tnl.TnlError):
        client.deployment(name)
