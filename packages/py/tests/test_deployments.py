"""deployment handles capture selection and join only their own native work."""

import asyncio
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tnl
from tnl import _connections, _deployments


def test_root_exposes_only_project_bound_connections() -> None:
    assert not hasattr(tnl, "connect")
    assert not hasattr(tnl, "client")
    assert not hasattr(tnl, "Project")
    assert not hasattr(tnl, "ConnectionHandle")


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


def test_remote_connection_rejects_unknown_names_and_protocol_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_connections._Scope, "stop", lambda _self: None)

    def prepare(
        scope: _connections._Scope, _service: str, _selection: object = None
    ) -> tuple[_connections.Connection, _connections._Session]:
        return (
            _connections.HTTPConnection(
                "127.0.0.1",
                15443,
                datetime.now(UTC) + timedelta(minutes=1),
                ssl.create_default_context(),
                "database.example.test",
                None,
                "https://database.example.test:15443",
                _transport_id="ctg_" + "a" * 22,
            ),
            _connections._Session(scope, "/fixture/handle.json"),
        )

    monkeypatch.setattr(_connections._Scope, "prepare", prepare)

    async def run() -> None:
        deployment = tnl.create_client(
            project="acme/shop",
            services={"database": {"protocol": "postgres"}},
            token="private-credential",
        ).deployment("production")
        with pytest.raises(tnl.TnlError) as unknown:
            await deployment.connect("missing")
        assert unknown.value.code == "sdk.configuration_invalid"
        with pytest.raises(tnl.TnlError) as mismatch:
            await deployment.connect("database")
        assert mismatch.value.code == "sdk.connection_invalid"
        await deployment.aclose()

    asyncio.run(run())


@pytest.mark.parametrize(
    ("protocol", "extra", "connection_type"),
    [
        ("postgres", {}, tnl.LocalPostgresConnection),
        (
            "mysql",
            {"ssl": {"servername": "db.example.test", "rejectUnauthorized": True}},
            tnl.LocalMySQLConnection,
        ),
        ("tcp", {}, tnl.LocalTCPConnection),
        ("http", {"url": "http://127.0.0.1:15432"}, tnl.LocalHTTPConnection),
        (
            "kubernetes",
            {
                "ssl": {"servername": "cluster.example.test", "rejectUnauthorized": True},
                "server": "https://127.0.0.1:15432",
                "kubeconfig": "apiVersion: v1",
                "context": "production",
            },
            tnl.LocalKubernetesConnection,
        ),
    ],
)
def test_local_protocols_use_account_free_native_settings(
    monkeypatch: pytest.MonkeyPatch,
    protocol: _deployments.Protocol,
    extra: dict[str, object],
    connection_type: type[object],
) -> None:
    monkeypatch.setattr(_connections._Scope, "binary", lambda _self: Path("/fixture/tnl"))
    monkeypatch.setattr(_connections._Scope, "stop", lambda _self: None)
    calls: list[tuple[str, ...]] = []

    def command(_binary: Path, *args: str, input_value: object = None) -> object:
        calls.append(args)
        return {
            "schema": 1,
            "protocol": protocol,
            "host": "127.0.0.1",
            "port": 15432,
            "binding": "a" * 64,
            **extra,
        }

    monkeypatch.setattr(_deployments, "_command", command)

    async def run() -> None:
        local = tnl.create_client(
            project="acme/shop", services={"service": {"protocol": protocol}}
        ).deployment("local")
        connection = await local.connect("service")
        assert isinstance(connection, connection_type)
        if protocol == "mysql":
            assert isinstance(connection, tnl.LocalMySQLConnection)
            assert isinstance(connection.ssl, ssl.SSLContext)
            assert connection.server_hostname == "db.example.test"
        if protocol == "http":
            assert isinstance(connection, tnl.LocalHTTPConnection)
            assert connection.url == "http://127.0.0.1:15432"
        if protocol == "kubernetes":
            assert isinstance(connection, tnl.LocalKubernetesConnection)
            assert connection.context == "production"
        await local.aclose()
        assert calls == [
            (
                "local",
                "--directory",
                str(local._scope.directory),
                "--service",
                "service",
                "--protocol",
                protocol,
            )
        ]

    asyncio.run(run())


@pytest.mark.parametrize(
    ("protocol", "extra"),
    [
        ("mysql", {"ssl": {"servername": "db.example.test", "rejectUnauthorized": False}}),
        ("tcp", {"url": "http://127.0.0.1:15432"}),
        ("http", {"url": "https://wrong.example.test:15432"}),
        (
            "kubernetes",
            {
                "ssl": {"servername": "cluster.example.test", "rejectUnauthorized": True},
                "server": "https://wrong.example.test:15432",
                "kubeconfig": "apiVersion: v1",
                "context": "production",
            },
        ),
    ],
)
def test_local_protocols_reject_untrusted_native_settings(
    monkeypatch: pytest.MonkeyPatch,
    protocol: _deployments.Protocol,
    extra: dict[str, object],
) -> None:
    monkeypatch.setattr(_connections._Scope, "binary", lambda _self: Path("/fixture/tnl"))
    monkeypatch.setattr(_connections._Scope, "stop", lambda _self: None)
    monkeypatch.setattr(
        _deployments,
        "_command",
        lambda *_args, **_kwargs: {
            "schema": 1,
            "protocol": protocol,
            "host": "127.0.0.1",
            "port": 15432,
            "binding": "a" * 64,
            **extra,
        },
    )

    async def run() -> None:
        local = tnl.create_client(
            project="acme/shop", services={"service": {"protocol": protocol}}
        ).deployment("local")
        with pytest.raises(tnl.TnlError) as failure:
            await local.connect("service")
        assert failure.value.code == "sdk.connection_invalid"
        await local.aclose()

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
