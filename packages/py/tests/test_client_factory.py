"""ordinary clients belong to factories; native cleanup belongs to deployments."""

import asyncio
import contextvars
import os
from collections.abc import Hashable
from dataclasses import dataclass
from pathlib import Path

import pytest
from test_workload_connections import NativeFixture

import tnl
from tnl._client import _Factory


@dataclass
class Client:
    binding: str


@pytest.mark.parametrize("failed", [False, True])
def test_factory_close_keeps_native_capabilities_until_deployment_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed: bool
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    tnl.configure_workload("job", token=lambda: "first")
    deployment = tnl.create_client(
        project="team/project", services={"db": {"protocol": "postgres"}}
    ).deployment("production")
    if failed:
        native.fail_start.add("first")
    closed: list[Client] = []
    get = deployment.client("db", create=lambda _: Client("a"), close=closed.append)

    async def scenario() -> None:
        if failed:
            with pytest.raises(tnl.TnlError):
                await get()
            assert deployment._scope.failure_handles
        else:
            value = await get()
            assert await get() is value
        await get.aclose()
        assert "sdk-close" not in native.calls and "sdk-stop" not in native.calls
        if failed:
            assert not closed and native.retained
        else:
            assert closed == [value]
            assert not deployment._acquisitions["db"]._session.closed
        await deployment.aclose()
        assert not native.retained

    asyncio.run(scenario())


def test_lazy_factory_coalesces_creation_but_selects_each_getter() -> None:
    async def scenario() -> None:
        acquisitions = 0
        creations = 0
        closed: list[Client] = []

        async def acquire() -> tuple[Hashable, str]:
            nonlocal acquisitions
            acquisitions += 1
            return "a", "a"

        async def create(binding: str) -> Client:
            nonlocal creations
            creations += 1
            await asyncio.sleep(0)
            return Client(binding)

        get = _Factory(acquire, create=create, close=closed.append)
        assert acquisitions == 0
        values = await asyncio.gather(*(get() for _ in range(10)))
        assert acquisitions == 10 and creations == 1
        assert all(value is values[0] for value in values) and closed == []
        await get.aclose()
        assert closed == [values[0]]

    asyncio.run(scenario())


def test_request_context_a_b_a_and_denial_never_borrow_another_client() -> None:
    async def scenario() -> None:
        identity = contextvars.ContextVar("identity", default="a")
        denied = RuntimeError("original authority denial")
        closed: list[Client] = []

        async def acquire() -> tuple[Hashable, str]:
            current = identity.get()
            await asyncio.sleep(0)
            if current == "denied":
                raise denied
            return current, current

        get = _Factory(acquire, create=Client, close=closed.append)
        a = await get()
        identity.set("b")
        b = await get()
        assert b is not a and b.binding == "b" and closed == []
        identity.set("a")
        assert await get() is a
        identity.set("denied")
        with pytest.raises(RuntimeError) as caught:
            await get()
        assert caught.value is denied
        identity.set("a")
        assert await get() is a
        await get.aclose()
        assert closed == [a, b]

    asyncio.run(scenario())


def test_close_joins_acquisition_without_creating_a_late_client() -> None:
    async def scenario() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        created: list[Client] = []

        async def acquire() -> tuple[Hashable, str]:
            entered.set()
            await release.wait()
            return "a", "a"

        def create(binding: str) -> Client:
            value = Client(binding)
            created.append(value)
            return value

        closed: list[Client] = []
        get = _Factory(acquire, create=create, close=closed.append)
        pending = asyncio.create_task(get())
        await entered.wait()
        cleanup = asyncio.create_task(get.aclose())
        await asyncio.sleep(0)
        assert not cleanup.done()
        release.set()
        with pytest.raises(tnl.TnlError) as caught:
            await pending
        assert caught.value.code == "sdk.client_closed"
        await cleanup
        assert created == [] and closed == []

    asyncio.run(scenario())


def test_close_joins_pending_create_and_closes_its_exact_client_once() -> None:
    async def scenario() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        value = Client("a")
        closed: list[Client] = []

        async def acquire() -> tuple[Hashable, str]:
            return "a", "a"

        async def create(binding: str) -> Client:
            assert binding == value.binding
            entered.set()
            await release.wait()
            return value

        get = _Factory(acquire, create=create, close=closed.append)
        pending = asyncio.create_task(get())
        await entered.wait()
        cleanups = [asyncio.create_task(get.aclose()) for _ in range(3)]
        await asyncio.sleep(0)
        assert not any(cleanup.done() for cleanup in cleanups)
        release.set()
        with pytest.raises(tnl.TnlError) as caught:
            await pending
        assert caught.value.code == "sdk.client_closed"
        await asyncio.gather(*cleanups)
        assert closed == [value]
        await get.aclose()
        assert closed == [value]

    asyncio.run(scenario())


def test_canceled_getter_does_not_abandon_shared_creation() -> None:
    async def scenario() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        closed: list[Client] = []

        async def acquire() -> tuple[Hashable, str]:
            return "a", "a"

        async def create(binding: str) -> Client:
            entered.set()
            await release.wait()
            return Client(binding)

        get = _Factory(acquire, create=create, close=closed.append)
        canceled, retained = asyncio.create_task(get()), asyncio.create_task(get())
        await entered.wait()
        canceled.cancel("only this caller")
        with pytest.raises(asyncio.CancelledError) as caught:
            await canceled
        assert caught.value.args == ("only this caller",)
        release.set()
        value = await retained
        assert await get() is value
        await get.aclose()
        assert closed == [value]

    asyncio.run(scenario())


def test_canceled_close_waiter_does_not_cancel_joined_cleanup() -> None:
    async def scenario() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        closes = 0

        async def acquire() -> tuple[Hashable, str]:
            return "a", "a"

        async def close(_client: Client) -> None:
            nonlocal closes
            closes += 1
            entered.set()
            await release.wait()

        get = _Factory(acquire, create=Client, close=close)
        await get()
        first = asyncio.create_task(get.aclose())
        await entered.wait()
        first.cancel("stop waiting, not cleanup")
        with pytest.raises(asyncio.CancelledError) as caught:
            await first
        assert caught.value.args == ("stop waiting, not cleanup",)
        second = asyncio.create_task(get.aclose())
        await asyncio.sleep(0)
        assert not second.done()
        release.set()
        await second
        assert closes == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["create", "close"])
def test_callback_cancellation_keeps_its_original_exception(operation: str) -> None:
    async def scenario() -> None:
        failure = asyncio.CancelledError("application callback canceled")
        fail = True

        async def acquire() -> tuple[Hashable, str]:
            return "a", "a"

        def create(binding: str) -> Client:
            if operation == "create" and fail:
                raise failure
            return Client(binding)

        def close(_client: Client) -> None:
            if operation == "close" and fail:
                raise failure

        get = _Factory(acquire, create=create, close=close)
        with pytest.raises(asyncio.CancelledError) as caught:
            if operation == "create":
                await get()
            else:
                await get()
                await get.aclose()
        assert caught.value is failure
        fail = False
        await get.aclose()

    asyncio.run(scenario())


def test_cleanup_retry_retains_only_the_exact_failed_clients() -> None:
    async def scenario() -> None:
        key = "a"
        failure = RuntimeError("driver cleanup failed")
        fail = True
        closed: list[Client] = []

        async def acquire() -> tuple[Hashable, str]:
            return key, key

        def close(client: Client) -> None:
            closed.append(client)
            if client.binding == "b" and fail:
                raise failure

        get = _Factory(acquire, create=Client, close=close)
        a = await get()
        key = "b"
        b = await get()
        results = await asyncio.gather(get.aclose(), get.aclose(), return_exceptions=True)
        assert all(result is failure for result in results) and closed == [a, b]
        fail = False
        await get.aclose()
        assert closed == [a, b, b]
        with pytest.raises(tnl.TnlError) as caught:
            await get()
        assert caught.value.code == "sdk.client_closed"

    asyncio.run(scenario())


def test_factory_does_not_reuse_clients_across_event_loops() -> None:
    async def acquire() -> tuple[Hashable, str]:
        return "a", "a"

    closed: list[Client] = []
    get = _Factory(acquire, create=Client, close=closed.append)
    with asyncio.Runner() as first, asyncio.Runner() as second:
        value = first.run(get())
        with pytest.raises(tnl.TnlError) as caught:
            second.run(get())
        assert caught.value.code == "sdk.client_context_invalid" and closed == []
        assert first.run(get()) is value
        first.run(get.aclose())
    asyncio.run(get.aclose())
    assert closed == [value]


def test_failed_creation_keeps_one_original_error_and_permits_retry() -> None:
    async def scenario() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        failure = RuntimeError("driver setup failed")
        attempts = 0
        closed: list[Client] = []

        async def acquire() -> tuple[Hashable, str]:
            return "a", "a"

        async def create(binding: str) -> Client:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                entered.set()
                await release.wait()
                raise failure
            return Client(binding)

        get = _Factory(acquire, create=create, close=closed.append)
        first, second = asyncio.create_task(get()), asyncio.create_task(get())
        await entered.wait()
        release.set()
        failures = await asyncio.gather(first, second, return_exceptions=True)
        assert all(error is failure for error in failures) and attempts == 1
        value = await get()
        assert attempts == 2
        await get.aclose()
        assert closed == [value]

    asyncio.run(scenario())


def test_multiple_cleanup_failures_keep_all_original_exceptions() -> None:
    async def scenario() -> None:
        key = "a"
        failures = {"a": RuntimeError("a"), "b": RuntimeError("b")}

        async def acquire() -> tuple[Hashable, str]:
            return key, key

        def close(client: Client) -> None:
            raise failures[client.binding]

        get = _Factory(acquire, create=Client, close=close)
        await get()
        key = "b"
        await get()
        with pytest.raises(ExceptionGroup) as caught:
            await get.aclose()
        assert caught.value.exceptions == (failures["a"], failures["b"])

    asyncio.run(scenario())


def test_binding_limit_does_not_evict_a_client_still_in_use() -> None:
    async def scenario() -> None:
        key = "0"
        closed: list[Client] = []

        async def acquire() -> tuple[Hashable, str]:
            return key, key

        get = _Factory(acquire, create=Client, close=closed.append)
        first = await get()
        for index in range(1, 64):
            key = str(index)
            await get()
        key = "overflow"
        with pytest.raises(tnl.TnlError) as caught:
            await get()
        assert caught.value.code == "sdk.client_capacity"
        key = "0"
        assert await get() is first and closed == []
        await get.aclose()
        assert len(closed) == 64

    asyncio.run(scenario())


def test_fork_fence_never_touches_parent_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        async def acquire() -> tuple[Hashable, str]:
            return "a", "a"

        closed: list[Client] = []
        get = _Factory(acquire, create=Client, close=closed.append)
        value = await get()
        pid = os.getpid()
        with monkeypatch.context() as child:
            child.setattr(os, "getpid", lambda: pid + 1)
            with pytest.raises(tnl.TnlError) as caught:
                await get()
            assert caught.value.code == "sdk.client_closed"
            await get.aclose()
            assert closed == []
        assert await get() is value
        await get.aclose()
        assert closed == [value]

    asyncio.run(scenario())
