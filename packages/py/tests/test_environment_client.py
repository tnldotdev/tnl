"""operation fixtures prove SDK dispatch/lifetime, not deployed authorization."""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Literal, assert_type, overload

import pytest
from test_service_facts import wire

import tnl
from tnl._connections import _EnvironmentClient, _ResolvedService, _SelectionContext
from tnl._service_facts import _bind_services



class _Client(_EnvironmentClient):
    @overload
    async def connect(self, service: Literal["db"]) -> tnl.PostgresConnection: ...

    @overload
    async def connect(self, service: Literal["api"]) -> tnl.HTTPConnection: ...

    async def connect(self, service: str) -> tnl.Connection:
        return await self._connect(service)


services = _bind_services({"db": {"protocol": "postgres"}, "api": {"protocol": "http"}}, _Client)


class _Selection:
    def __init__(self, discovery: str = "postgres", prepared: str = "postgres") -> None:
        self.discovery = discovery
        self.protocol = prepared
        self.preparations = 0
        self.closed = 0
        self.failure: BaseException | None = None

    async def resolve(self, service: str) -> _ResolvedService:
        return _ResolvedService(service, self.discovery, self)

    async def prepare(self, resolution: _ResolvedService) -> object:
        assert resolution.binding is self
        self.preparations += 1
        return wire(self.protocol)

    async def aclose(self) -> None:
        self.closed += 1
        if self.failure is not None:
            raise self.failure


async def _assertion() -> tnl.OIDCAssertion:
    return tnl.OIDCAssertion("unused.private.assertion", datetime.now(UTC) + timedelta(minutes=1))


async def _normal_constructor_returns_checked_generated_subtype(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selection: _SelectionContext = _Selection()
    # inject only the package-private operation owner. neither the public source
    # nor generated facts acquires a fake authorization capability.
    monkeypatch.setattr("tnl._client._NativeSelection", lambda *_: selection)
    async with tnl.client(
        services=services,
        environment=tnl.EnvironmentReference(
            "https://control.example", "project", "env_" + "a" * 22
        ),
        identity=tnl.IdentitySource("oidc", "mci_" + "a" * 22, _assertion, permission_id="mwp_" + "a" * 22),
    ) as client:
        assert_type(client, _Client)
        assert_type(await client.connect("db"), tnl.PostgresConnection)
        assert isinstance(await client.connect("db"), tnl.PostgresConnection)


async def _generated_postgres_rejects_wrong_discovery_and_native_protocol(
    discovery: str, prepared: str, calls: int
) -> None:
    selection = _Selection(discovery, prepared)
    client = services._new(selection)
    with pytest.raises(tnl.TnlError):
        await client.connect("db")
    assert selection.preparations == calls
    await client.aclose()


async def _clients_keep_independent_selection_and_retry_only_failed_cleanup() -> None:
    a, b = _Selection(), _Selection()
    first, second = services._new(a), services._new(b)
    await first.connect("db")
    await second.connect("db")
    failure = RuntimeError("independent cleanup failure")
    a.failure = failure
    with pytest.raises(RuntimeError) as raised:
        await first.aclose()
    assert raised.value is failure
    assert b.closed == 0
    await second.connect("db")
    a.failure = None
    await first.aclose()
    await first.aclose()
    assert a.closed == 2
    await second.aclose()


async def _close_joins_pending_operation_and_preserves_independent_failure() -> None:
    entered = asyncio.Event()
    failure = RuntimeError("operation failed during cancellation")

    class Pending(_Selection):
        async def prepare(self, resolution: _ResolvedService) -> object:
            entered.set()
            try:
                await asyncio.Future[None]()
            except asyncio.CancelledError:
                raise failure from None
            raise AssertionError("pending operation completed without cancellation")

    context = Pending()
    client = services._new(context)
    pending = asyncio.create_task(client.connect("db"))
    await entered.wait()
    with pytest.raises(RuntimeError) as raised:
        await client.aclose()
    assert raised.value is failure
    assert context.closed == 1
    with pytest.raises(RuntimeError) as operation:
        await pending
    assert operation.value is failure


def test_normal_constructor_returns_checked_generated_subtype(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asyncio.run(_normal_constructor_returns_checked_generated_subtype(monkeypatch))


@pytest.mark.parametrize("discovery,prepared,calls", [("http", "http", 0), ("postgres", "http", 1)])
def test_generated_postgres_rejects_wrong_discovery_and_native_protocol(
    discovery: str, prepared: str, calls: int
) -> None:
    asyncio.run(
        _generated_postgres_rejects_wrong_discovery_and_native_protocol(discovery, prepared, calls)
    )


def test_clients_keep_independent_selection_and_retry_only_failed_cleanup() -> None:
    asyncio.run(_clients_keep_independent_selection_and_retry_only_failed_cleanup())


def test_close_joins_pending_operation_and_preserves_independent_failure() -> None:
    asyncio.run(_close_joins_pending_operation_and_preserves_independent_failure())
