"""ordinary client caching, caller cancellation, and joined retryable cleanup."""

import asyncio
import contextvars
import os
import threading
from collections.abc import Hashable
from dataclasses import dataclass
from pathlib import Path

import pytest
from test_workload_connections import NativeFixture

import tnl
from tnl import _connections
from tnl._client import _Factory, connection_client


@dataclass
class Client:
    binding: str


class NativeClientFactory:
    """observe real connection handles without replacing factory acquisition."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.handles: list[_connections.ConnectionHandle[_connections.Connection]] = []
        self.created: list[Client] = []
        self.closed: list[Client] = []
        self.get = connection_client(self.select, create=self.create, close=self.closed.append)

    def select(self) -> _connections.ConnectionHandle[_connections.Connection]:
        handle = tnl.connect("db", directory=self.directory)
        self.handles.append(handle)
        return handle

    def create(self, connection: _connections.Connection) -> Client:
        value = Client(connection.protocol)
        self.created.append(value)
        return value


@pytest.mark.parametrize("retry_close", [False, True])
def test_connection_client_failed_acquisition_releases_failure_for_a_fresh_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry_close: bool
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "other"
    tnl.configure_workload("job", token=lambda: current)
    failed, fresh = NativeClientFactory(tmp_path), NativeClientFactory(tmp_path)
    attempts: list[tuple[str, ...]] = []
    close_errors: list[tnl.TnlError] = []

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-close":
            attempts.append(args)
        try:
            return native.command(binary, *args, input_value=input_value)
        except tnl.TnlError as error:
            close_errors.append(error)
            raise

    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        nonlocal current
        peer = tnl.connect("db", directory=tmp_path)
        await peer
        scope = peer._session.scope
        current = "first"
        native.fail_start.add("first")
        try:
            with pytest.raises(tnl.TnlError) as first:
                await failed.get()
            error = first.value
            assert isinstance(error, _connections._RetainedStartFailure)
            observation = scope.failure_handles[error.handle].session
            assert not observation.joined
            with pytest.raises(tnl.TnlError) as repeated:
                await failed.get()
            assert repeated.value is error
            assert failed.created == [] and failed.closed == []
            native.fail_start.clear()
            if retry_close:
                native.fail_close = True
                with pytest.raises(tnl.TnlError) as cleanup:
                    await failed.get.aclose()
                assert cleanup.value is close_errors[0]
                assert observation.closed and not observation.joined
                assert scope.failure_handles[error.handle].session is observation
                assert not observation.joined and native.retained == {"first": error.handle}
                current = "other"
                await peer
                native.fail_close = False
            await failed.get.aclose()
            current = "first"
            value = await fresh.get()
            assert fresh.created == [value]
            expected = (
                "sdk-close",
                "--registry",
                scope.registry,
                "--parent-pid",
                str(os.getpid()),
                "--failure-handle",
                error.handle,
            )
            assert attempts == [expected] * (2 if retry_close else 1)
            assert observation.joined
            assert not native.retained and not scope.failure_handles
            assert native.closed == [] and "sdk-stop" not in native.calls
            before = list(attempts)
            await failed.get.aclose()
            assert attempts == before
            await fresh.get.aclose()
            assert fresh.closed == [value] and native.closed == []
            assert not fresh.handles[0]._session.closed
            current = "other"
            await peer
        finally:
            native.fail_close = False
            await failed.get.aclose()
            await fresh.get.aclose()
            for handle in [*failed.handles, *fresh.handles, peer]:
                await handle.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("fail_start", [False, True])
def test_connection_client_canceled_getter_joins_pending_native_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fail_start: bool
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    tnl.configure_workload("job", token=lambda: "first")
    if fail_start:
        native.fail_start.add("first")
    native.pause = True
    factory = NativeClientFactory(tmp_path)

    async def scenario() -> None:
        pending = asyncio.create_task(factory.get())
        closing: asyncio.Task[None] | None = None
        try:
            assert await asyncio.to_thread(native.identifying.wait, 5)
            pending.cancel("only this getter")
            with pytest.raises(asyncio.CancelledError) as caught:
                await pending
            assert caught.value.args == ("only this getter",)
            closing = asyncio.create_task(factory.get.aclose())
            await asyncio.sleep(0)
            assert not closing.done()
            native.release.set()
            await closing
            scope = factory.handles[0]._session.scope
            assert scope.pending == 0 and not scope.requests
            assert factory.created == [] and factory.closed == []
            assert not native.retained and not scope.failure_handles
            assert native.closed == [] and "sdk-stop" not in native.calls
            if fail_start:
                assert native.calls.count("sdk-close") == 1
            else:
                assert native.calls.count("sdk-close") == 0
                assert not factory.handles[0]._session.closed
        finally:
            native.release.set()
            await asyncio.gather(pending, return_exceptions=True)
            if closing is not None:
                await asyncio.gather(closing, return_exceptions=True)
            await factory.get.aclose()
            for handle in factory.handles:
                await handle.aclose()

    asyncio.run(scenario())


def test_connection_client_success_closes_only_drivers_not_shared_native_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    tnl.configure_workload("job", token=lambda: "first")
    first, sibling = NativeClientFactory(tmp_path), NativeClientFactory(tmp_path)

    async def scenario() -> None:
        try:
            a, b = await first.get(), await sibling.get()
            owner = first.handles[0]._session
            assert owner is sibling.handles[0]._session
            await first.get.aclose()
            assert first.closed == [a] and sibling.closed == []
            assert not owner.closed and native.closed == []
            assert await sibling.get() is b
            await sibling.get.aclose()
            assert sibling.closed == [b]
            assert not owner.closed and native.closed == []
            assert "sdk-close" not in native.calls and "sdk-stop" not in native.calls
            assert len(native.owners) == 1
            assert (await sibling.handles[0]).protocol == "postgres"
        finally:
            await first.get.aclose()
            await sibling.get.aclose()
            for handle in [*first.handles, *sibling.handles]:
                await handle.aclose()

    asyncio.run(scenario())


def test_connection_client_failed_human_acquisition_does_not_close_its_current_owner_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    monkeypatch.delenv("TNL_WORKLOAD")
    factory = NativeClientFactory(tmp_path)
    native.fail_start.add("first")

    class IPC:
        def __init__(self, file: str) -> None:
            self.file = file

        def prepare(
            self,
            name: str,
            assertion: str | None = None,
            *,
            sdk: bool = False,
            requested_at: str | None = None,
            selection: dict[str, object] | None = None,
            preview: bool = False,
            request_handle: str | None = None,
        ) -> object:
            assert sdk and not preview and selection is None and assertion is None
            assert requested_at is not None
            return native.select(name, "first")

        def close(self) -> None:
            pass

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-prepare":
            assert isinstance(input_value, dict) and "assertion" not in input_value
            input_value = {**input_value, "assertion": "other"}
        return native.command(binary, *args, input_value=input_value)

    monkeypatch.setattr(_connections, "OwnerIPC", IPC)
    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        peer = tnl.connect("db", directory=tmp_path)
        await peer
        owner = peer._session
        try:
            with pytest.raises(tnl.TnlError) as caught:
                await factory.get()
            assert isinstance(caught.value, _connections._RetainedStartFailure)
            assert factory.handles[0]._session is owner
            await factory.get.aclose()
            assert not native.retained and not owner.scope.failure_handles
            assert factory.created == [] and factory.closed == []
            assert not owner.closed and native.closed == []
            assert native.calls.count("sdk-close") == 1 and "sdk-stop" not in native.calls
            assert peer.snapshot().protocol == "postgres"
        finally:
            await factory.get.aclose()
            for handle in [*factory.handles, peer]:
                await handle.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("distinct", [False, True])
def test_connection_client_failure_cleanup_bookkeeping_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, distinct: bool
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "0"
    tnl.configure_workload("job", token=lambda: current)
    factory, fresh = NativeClientFactory(tmp_path), NativeClientFactory(tmp_path)
    select = native.select

    def failed(name: str, assertion: str | None) -> object:
        assert assertion is not None
        native.retained.setdefault(assertion, f"{len(native.retained):064x}.{'1' * 16}")
        return select(name, assertion)

    monkeypatch.setattr(native, "select", failed)

    async def scenario() -> None:
        nonlocal current
        try:
            for index in range(64 if distinct else 80):
                current = str(index) if distinct else "0"
                with pytest.raises(_connections._RetainedStartFailure):
                    await factory.get()
            if distinct:
                current = "overflow"
                with pytest.raises(tnl.TnlError) as caught:
                    await factory.get()
                assert caught.value.code == "sdk.client_capacity"
                assert len(factory.handles) == 64 and "overflow" not in native.retained
            await factory.get.aclose()
            assert native.calls.count("sdk-close") == (64 if distinct else 1)
            assert not native.retained
            assert not factory.handles[0]._session.scope.failure_handles
            assert native.closed == [] and "sdk-stop" not in native.calls
            before = list(native.calls)
            await factory.get.aclose()
            assert native.calls == before
            monkeypatch.setattr(native, "select", select)
            await fresh.get()
        finally:
            await factory.get.aclose()
            await fresh.get.aclose()
            for handle in [*factory.handles, *fresh.handles]:
                await handle.aclose()

    asyncio.run(scenario())


def test_connection_client_canceled_close_waiter_does_not_cancel_native_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    tnl.configure_workload("job", token=lambda: "first")
    native.fail_start.add("first")
    factory = NativeClientFactory(tmp_path)
    entered, release = threading.Event(), threading.Event()

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-close":
            entered.set()
            assert release.wait(5)
        return native.command(binary, *args, input_value=input_value)

    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        with pytest.raises(_connections._RetainedStartFailure):
            await factory.get()
        first = asyncio.create_task(factory.get.aclose())
        second: asyncio.Task[None] | None = None
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            first.cancel("stop waiting, not cleanup")
            with pytest.raises(asyncio.CancelledError) as caught:
                await first
            assert caught.value.args == ("stop waiting, not cleanup",)
            second = asyncio.create_task(factory.get.aclose())
            await asyncio.sleep(0)
            assert not second.done()
            release.set()
            await second
            assert not native.retained and native.calls.count("sdk-close") == 1
        finally:
            release.set()
            await asyncio.gather(first, return_exceptions=True)
            if second is not None:
                await asyncio.gather(second, return_exceptions=True)
            await factory.get.aclose()
            for handle in factory.handles:
                await handle.aclose()

    asyncio.run(scenario())


def test_connection_client_driver_creation_failure_does_not_own_the_native_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    tnl.configure_workload("job", token=lambda: "first")
    fixture = NativeClientFactory(tmp_path)
    failure = RuntimeError("ordinary driver setup failed")

    def create(connection: _connections.Connection) -> Client:
        raise failure

    get = connection_client(fixture.select, create=create, close=fixture.closed.append)

    async def scenario() -> None:
        try:
            with pytest.raises(RuntimeError) as caught:
                await get()
            assert caught.value is failure
            owner = fixture.handles[0]._session
            await get.aclose()
            assert not owner.closed and native.closed == []
            assert "sdk-close" not in native.calls and "sdk-stop" not in native.calls
            assert fixture.closed == []
            assert (await fixture.handles[0]).protocol == "postgres"
        finally:
            await get.aclose()
            for handle in fixture.handles:
                await handle.aclose()

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
        assert all(value is values[0] for value in values)
        assert closed == []
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
        assert b is not a and b.binding == "b"
        assert closed == []
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
        assert all(result is failure for result in results)
        assert closed == [a, b]
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
        assert caught.value.code == "sdk.client_context_invalid"
        assert closed == []
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
