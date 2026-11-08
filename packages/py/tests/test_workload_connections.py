"""provider acquisition and native-selected owners without SDK identity decoding."""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tnl
from tnl import _connections, _workload


def prepared(name: str, deadline: str) -> dict[str, object]:
    protocol = "postgres" if name == "db" else "mysql"
    return {
        "schema": 1,
        "project_runtime": {
            "dev": False,
            "namespace": "example.test",
            "services": {
                name: {
                    "protocol": protocol,
                    "hostname": f"{name}.example.test",
                    "namespace": "example.test",
                    "public": False,
                    "port": 15443,
                }
            },
        },
        "connection": {
            "schema": 1,
            "protocol": protocol,
            "host": "127.0.0.1",
            "port": 34567,
            "expires_at": deadline,
            "transport_id": "ctg_" + ("a" if protocol == "postgres" else "b") * 22,
            "ssl": {"servername": f"{name}.example.test", "rejectUnauthorized": True},
        },
    }


class NativeFixture:
    """model replies from native, not an SDK-side identity or lifecycle engine."""

    def __init__(self, directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.directory = directory
        self.calls: list[str] = []
        self.requests: list[tuple[str, str | None]] = []
        self.owners: dict[str, str] = {}
        self.owner_lock = threading.Lock()
        self.owner_index = 0
        self.closed: list[str] = []
        self.denied: set[str] = set()
        self.deadline = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        self.identifying, self.release = threading.Event(), threading.Event()
        self.pause = False
        self.failure: str | None = None
        self.fail_start: set[str] = set()
        self.fail_prepare: set[str] = set()
        self.retained: dict[str, str] = {}
        self.fail_close = False
        self.human = False
        monkeypatch.setattr(_connections, "_sessions", {})
        monkeypatch.setattr(_workload, "_configuration", None)
        monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
        monkeypatch.delenv("TNL_CONNECTION_HANDLE", raising=False)
        monkeypatch.setenv("TNL_WORKLOAD", "job")
        manifest = directory / ".tnl/generated/workloads.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "workloads": {
                        "job": {
                            "provider": "oidc",
                            "services": ["db", "mysql"],
                            "acquisition": {"method": "callback"},
                        }
                    },
                }
            )
        )
        monkeypatch.setattr(_connections, "_command", self.command)
        fixture = self

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
            ) -> object:
                if preview:
                    return fixture.preview(name, selection)
                if sdk and not fixture.human:
                    assert (
                        selection is not None
                        and "sdk_workload" in selection
                        and requested_at is not None
                    )
                return fixture.select(name, assertion) if sdk else prepared(name, fixture.deadline)

            def close(self) -> None:
                pass

        monkeypatch.setattr(_connections, "OwnerIPC", IPC)

    def command(self, binary: Path, *args: str, input_value: object = None) -> object:
        self.calls.append(args[0])
        assert not any(token in args for token in ("first", "rotated", "forged", "other"))
        if args[0] == "sdk-workload":
            return self.preview(args[args.index("--service") + 1], input_value)
        if args[0] == "sdk-prepare":
            assert "--retain-start-failure" in args
            assertion = input_value.get("assertion") if isinstance(input_value, dict) else None
            assert isinstance(assertion, str) or self.human and assertion is None
            return self.select(args[args.index("--selected-service") + 1], assertion)
        if args[0] == "sdk-close-failure":
            if self.fail_close:
                raise tnl.TnlError("sdk.connection_unavailable", "native close did not join")
            handle = args[args.index("--failure-handle") + 1]
            self.retained = {key: value for key, value in self.retained.items() if value != handle}
            return {"schema": 1, "state": "stopped"}
        if args[0] == "stop":
            if self.fail_close:
                raise tnl.TnlError("sdk.connection_unavailable", "native close did not join")
            self.closed.append(args[args.index("--handle") + 1])
            return {"schema": 1, "state": "stopped"}
        if args[0] == "sdk-stop":
            self.closed.extend(self.owners.values())
            self.retained.clear()
            return {"schema": 1, "state": "stopped"}
        assert args[0] == "read"
        return prepared(args[-1], self.deadline)

    def preview(self, service: str, request: object) -> object:
        return {
            "schema": 1,
            "name": "job",
            "source": "callback",
            "policy": "a" * 64,
            "directory": str(self.directory),
            "manifest": str(self.directory / ".tnl/generated/workloads.json"),
        }

    def select(self, name: str, assertion: str | None) -> object:
        if self.human and assertion is None:
            assertion = "human"
        self.requests.append((name, assertion))
        if self.pause:
            self.identifying.set()
            assert self.release.wait(5)
        if self.failure == "denied" or assertion == "forged" or name in self.denied:
            raise tnl.TnlError("sdk.workload_denied", "assertion or service rejected")
        if self.failure == "expired":
            return {"schema": 1, "reason": "TNL_CLIENT_CONNECTION_EXPIRED"}
        if self.failure == "schema":
            return {"schema": True}
        assert assertion is not None
        if assertion in self.fail_start or assertion in self.retained:
            handle = self.retained.setdefault(assertion, f"{'a' * 64}.{'1' * 16}")
            return {
                "schema": 1,
                "reason": "TNL_CLIENT_AUTHENTICATION_REQUIRED",
                "sdk_retained_start_failure": True,
                "sdk_failure_handle": handle,
            }
        binding = "same" if assertion in {"first", "rotated"} else assertion
        with self.owner_lock:
            file = self.owners.get(binding)
            if file is None or file in self.closed:
                self.owner_index += 1
                file = str(self.directory / f"owner-{self.owner_index}")
                self.owners[binding] = file
        if assertion in self.fail_prepare:
            return {
                "schema": 1,
                "reason": "TNL_CLIENT_CONNECTION_UNAVAILABLE",
                "sdk_owner_handle": file,
            }
        return {
            "schema": 1,
            "owner": {
                "expires_at": self.deadline,
                "connection_handle": file,
                "executable": str(Path(sys.executable).resolve()),
            },
            "prepared": prepared(name, self.deadline),
        }


@pytest.mark.parametrize("peer_owner", [False, True])
@pytest.mark.parametrize("retry_close", [False, True])
@pytest.mark.parametrize("cancel_getter", [False, True])
def test_human_alias_close_retains_the_late_owner_until_exact_cleanup_joins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    peer_owner: bool,
    retry_close: bool,
    cancel_getter: bool,
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    close_attempts: list[str] = []
    close_errors: list[tnl.TnlError] = []

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] in {"stop", "sdk-close"} and "--handle" in args:
            close_attempts.append(args[args.index("--handle") + 1])
        try:
            return native.command(binary, *args, input_value=input_value)
        except tnl.TnlError as error:
            close_errors.append(error)
            raise

    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        peer: _connections.ConnectionHandle[_connections.Connection] | None = None
        if peer_owner:
            tnl.configure_workload("job", token=lambda: "other")
            peer = tnl.connect("db", directory=tmp_path)
            await peer
        configuration = _workload._configuration
        monkeypatch.setattr(_workload, "_configuration", None)
        monkeypatch.delenv("TNL_WORKLOAD")
        native.human = True
        handle, alias = tnl.connect("db", directory=tmp_path), tnl.connect("db", directory=tmp_path)
        original = handle._session
        scope = original.scope
        assert alias._session is original and original.handle is None
        native.pause = True

        async def prepare() -> _connections.Connection:
            return await handle

        pending = asyncio.create_task(prepare())
        fresh: _connections.ConnectionHandle[_connections.Connection] | None = None
        try:
            assert await asyncio.to_thread(native.identifying.wait, 5)
            registry = scope.registry
            assert registry is not None
            await alias.aclose()
            assert original.closed and original.joined and original.handle is None
            assert not pending.done() and scope.pending == 1
            if cancel_getter:
                pending.cancel("only this await")
                with pytest.raises(asyncio.CancelledError) as canceled:
                    await pending
                assert canceled.value.args == ("only this await",)
            native.release.set()
            if not cancel_getter:
                with pytest.raises(tnl.TnlError) as caught:
                    await pending
                assert caught.value.code == "sdk.connection_closed"
            if retry_close:
                native.fail_close = True
                with pytest.raises(tnl.TnlError) as failed:
                    await handle.aclose()
                assert failed.value is close_errors[-1]
                owner = native.owners["human"]
                assert scope.registry == registry and scope.handles[owner].handle == owner
                assert not scope.handles[owner].joined and not handle._lifetime.joined
                assert not native.closed
                native.fail_close = False
            await handle.aclose()
            owner = native.owners["human"]
            assert close_attempts == [owner] * (2 if retry_close else 1)
            assert native.closed == [owner] and "sdk-stop" not in native.calls
            assert original.closed and original.joined and original.handle is None
            assert handle._lifetime.joined and alias._lifetime.joined
            assert not scope.pending and not scope.requests and not scope.failure_handles
            assert set(scope.handles) == ({native.owners["other"]} if peer_owner else set())
            assert (scope.registry == registry) if peer_owner else scope.registry is None
            with pytest.raises(tnl.TnlError) as closed:
                await alias
            assert closed.value.code == "sdk.connection_closed"
            native.pause = False
            fresh = tnl.connect("db", directory=tmp_path)
            await fresh
            replacement = native.owners["human"]
            assert replacement != owner and fresh._session is not original
            before = list(close_attempts)
            await alias.aclose()
            await handle.aclose()
            assert close_attempts == before and not fresh._session.closed
            await fresh.aclose()
            assert native.closed == [owner, replacement]
            if peer is not None:
                native.human = False
                monkeypatch.setattr(_workload, "_configuration", configuration)
                monkeypatch.setenv("TNL_WORKLOAD", "job")
                assert peer.snapshot().protocol == "postgres"
                await peer
                await peer.aclose()
            assert not scope.handles and not scope.failure_handles and scope.registry is None
        finally:
            native.release.set()
            native.fail_close = False
            await asyncio.gather(pending, return_exceptions=True)
            await handle.aclose()
            await alias.aclose()
            if fresh is not None:
                await fresh.aclose()
            if peer is not None:
                await peer.aclose()

    asyncio.run(scenario())


def test_human_alias_close_does_not_replace_the_original_acquisition_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    monkeypatch.delenv("TNL_WORKLOAD")
    native.human = True
    native.pause = True
    native.failure = "denied"
    errors: list[tnl.TnlError] = []

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        try:
            return native.command(binary, *args, input_value=input_value)
        except tnl.TnlError as error:
            errors.append(error)
            raise

    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        handle, alias = tnl.connect("db", directory=tmp_path), tnl.connect("db", directory=tmp_path)

        async def prepare() -> _connections.Connection:
            return await handle

        pending = asyncio.create_task(prepare())
        try:
            assert await asyncio.to_thread(native.identifying.wait, 5)
            await alias.aclose()
            native.release.set()
            with pytest.raises(tnl.TnlError) as caught:
                await pending
            assert caught.value is errors[0] and caught.value.code == "sdk.workload_denied"
            await handle.aclose()
            assert not native.closed and "sdk-stop" not in native.calls
            assert not handle._session.scope.handles
        finally:
            native.release.set()
            await asyncio.gather(pending, return_exceptions=True)
            await handle.aclose()
            await alias.aclose()

    asyncio.run(scenario())


def test_policy_reclamation_pins_identity_waiters_and_preserves_active_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # native capacity assertions: TestConnectionSDKRegistryCapacityAndReclamation.
    native = NativeFixture(tmp_path, monkeypatch)
    tnl.configure_workload("job", token=lambda: "first")

    async def scenario() -> None:
        original = tnl.connect("db", directory=tmp_path)
        await original
        scope = original._session.scope
        native.pause = True
        first, second = tnl.connect("db", directory=tmp_path), tnl.connect("db", directory=tmp_path)

        async def one(
            handle: _connections.ConnectionHandle[_connections.Connection],
        ) -> _connections.Connection:
            return await handle

        waiters = [asyncio.create_task(one(handle)) for handle in (first, second)]
        assert await asyncio.to_thread(native.identifying.wait, 5)
        await original.aclose()
        assert first._session.scope is second._session.scope is scope
        native.release.set()
        await asyncio.gather(*waiters)
        assert first._session is second._session
        assert len(native.requests) == 2  # cold selection plus one identical pending operation.
        await first.aclose()
        assert not scope.handles and not scope.failure_handles

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", [None, "denied", "expired", "schema"])
def test_inactive_manifest_policies_do_not_exhaust_the_process_lifetime_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    # native rejects invalid selector proofs before reserving owner capacity.
    native = NativeFixture(tmp_path, monkeypatch)
    native.failure = failure
    current = ""
    tnl.configure_workload("job", token=lambda: current)

    async def scenario() -> None:
        nonlocal current
        for index in range(40):
            current = str(index)
            handle = tnl.connect("db", directory=tmp_path)
            if failure is not None:
                with pytest.raises(tnl.TnlError) as caught:
                    await handle
                assert (
                    caught.value.code
                    == {
                        "denied": "sdk.workload_denied",
                        "expired": "sdk.connection_expired",
                        "schema": "sdk.connection_invalid",
                    }[failure]
                )
            else:
                await handle
                before = handle._session
                await handle
                assert handle._session is before
            await handle.aclose()
        assert len(_connections._sessions) == 1
        scope = next(iter(_connections._sessions.values()))
        assert not scope.handles and not scope.failures and not scope.requests

    asyncio.run(scenario())


def test_rotating_assertions_and_services_share_only_control_verified_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current, callbacks = "first", 0

    async def token() -> str:
        nonlocal callbacks
        callbacks += 1
        return current

    tnl.configure_workload("job", token=token)

    async def scenario() -> None:
        nonlocal current
        first = tnl.connect("db", directory=tmp_path)
        with pytest.raises(tnl.TnlError):
            first.snapshot()
        await first
        assert native.calls == ["sdk-workload", "sdk-prepare"]
        for _ in range(10):
            await first
        assert native.calls == ["sdk-workload", "sdk-prepare"] and callbacks == 11
        await tnl.connect("mysql", directory=tmp_path)
        current = "rotated"
        rotated = tnl.connect("db", directory=tmp_path)
        await rotated
        assert rotated._session is first._session and len(native.owners) == 1
        native.denied.add("mysql")
        with pytest.raises(tnl.TnlError):
            await tnl.connect("mysql", directory=tmp_path)
        await first
        current = "forged"
        with pytest.raises(tnl.TnlError):
            await tnl.connect("db", directory=tmp_path)
        assert native.requests[-1] == ("db", "forged")
        current = "other"
        other = tnl.connect("db", directory=tmp_path)
        await other
        assert len(native.owners) == 2 and other._session is not first._session
        await first.aclose()
        with pytest.raises(tnl.TnlError, match="closed"):
            await first
        await other  # closing the first native capability leaves its peer usable.
        await other.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("retry_close", [False, True])
def test_closing_failed_identity_releases_only_its_native_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry_close: bool
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "first"
    tnl.configure_workload("job", token=lambda: current)
    native.fail_start.add("first")

    async def scenario() -> None:
        nonlocal current
        failed, alias = tnl.connect("db", directory=tmp_path), tnl.connect("db", directory=tmp_path)
        with pytest.raises(tnl.TnlError) as first:
            await failed
        with pytest.raises(tnl.TnlError) as second:
            await alias
        assert first.value is second.value
        current = "other"
        peer = tnl.connect("db", directory=tmp_path)
        await peer
        native.fail_start.clear()
        if retry_close:
            native.fail_close = True
            with pytest.raises(tnl.TnlError):
                await failed.aclose()
            assert peer._session.scope.failures and not native.closed
            await peer
            native.fail_close = False
        await failed.aclose()
        assert "sdk-stop" not in native.calls and not native.closed
        assert not peer._session.scope.failures
        current = "first"
        retry = tnl.connect("db", directory=tmp_path)
        await retry
        calls = len(native.calls)
        await alias.aclose()
        assert len(native.calls) == calls  # old shared failure cannot close a replacement.
        current = "other"
        await peer
        await retry.aclose()
        await peer.aclose()

    asyncio.run(scenario())


def test_reselecting_one_handle_cannot_transfer_a_siblings_close_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    NativeFixture(tmp_path, monkeypatch)
    current = "first"
    tnl.configure_workload("job", token=lambda: current)

    async def scenario() -> None:
        nonlocal current
        first, alias = tnl.connect("db", directory=tmp_path), tnl.connect("db", directory=tmp_path)
        await first
        await alias
        current = "other"
        await first
        assert first._session is not alias._session
        await alias.aclose()
        await first
        await first.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("retry_close", [False, True])
def test_initial_service_failure_keeps_cleanup_without_stopping_a_peer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry_close: bool
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "other"
    tnl.configure_workload("job", token=lambda: current)

    async def scenario() -> None:
        nonlocal current
        peer = tnl.connect("db", directory=tmp_path)
        await peer
        current = "first"
        native.fail_prepare.add("first")
        failed = tnl.connect("db", directory=tmp_path)
        with pytest.raises(tnl.TnlError) as caught:
            await failed
        assert caught.value.code == "sdk.connection_unavailable"
        owner = native.owners["same"]
        assert owner not in native.closed
        if retry_close:
            native.fail_close = True
            with pytest.raises(tnl.TnlError):
                await failed.aclose()
            assert owner not in native.closed
            native.fail_close = False
        await failed.aclose()
        assert native.closed == [owner] and "sdk-stop" not in native.calls
        current = "other"
        await peer
        await peer.aclose()
        assert not peer._session.scope.handles

    asyncio.run(scenario())


@pytest.mark.parametrize("retry_close", [False, True])
def test_close_joins_an_inflight_identity_reselection_without_leaking_its_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry_close: bool
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "first"
    tnl.configure_workload("job", token=lambda: current)

    async def scenario() -> None:
        nonlocal current
        handle = tnl.connect("db", directory=tmp_path)
        await handle
        first = handle._session.handle
        current = "peer"
        peer = tnl.connect("db", directory=tmp_path)
        await peer
        current = "other"
        native.pause = True

        async def prepare() -> _connections.Connection:
            return await handle

        pending = asyncio.create_task(prepare())
        closing: asyncio.Task[None] | None = None
        try:
            assert await asyncio.to_thread(native.identifying.wait, 5)
            native.fail_close = retry_close
            closing = asyncio.create_task(handle.aclose())
            # observe the public close fence while native selection is held.
            async with asyncio.timeout(5):
                while True:
                    try:
                        handle.snapshot()
                    except tnl.TnlError as error:
                        assert error.code == "sdk.connection_closed"
                        break
                    await asyncio.sleep(0)
            assert not closing.done()
            native.release.set()
            with pytest.raises(tnl.TnlError) as caught:
                await pending
            assert caught.value.code == "sdk.connection_closed"
            if retry_close:
                with pytest.raises(tnl.TnlError):
                    await closing
                assert native.owners["other"] not in native.closed
                native.fail_close = False
                await handle.aclose()
            else:
                await closing
            assert first in native.closed and native.owners["other"] in native.closed
            assert native.owners["peer"] not in native.closed and "sdk-stop" not in native.calls
            current = "peer"
            await peer
            await peer.aclose()
            assert not peer._session.scope.handles
        finally:
            native.release.set()
            await asyncio.gather(pending, return_exceptions=True)
            if closing is not None:
                await asyncio.gather(closing, return_exceptions=True)

    asyncio.run(scenario())


def test_closing_an_old_owner_alias_does_not_close_a_pending_new_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "first"
    tnl.configure_workload("job", token=lambda: current)

    async def scenario() -> None:
        nonlocal current
        handle = tnl.connect("db", directory=tmp_path)
        alias = tnl.connect("db", directory=tmp_path)
        await handle
        await alias
        current = "other"
        native.pause = True

        async def prepare() -> _connections.Connection:
            return await handle

        pending = asyncio.create_task(prepare())
        try:
            assert await asyncio.to_thread(native.identifying.wait, 5)
            await alias.aclose()
            native.release.set()
            await pending
            assert native.owners["other"] not in native.closed
            await handle
            await handle.aclose()
            assert not handle._session.scope.handles
        finally:
            native.release.set()
            await asyncio.gather(pending, return_exceptions=True)

    asyncio.run(scenario())


def test_cancelled_reselection_retains_its_worker_for_joined_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "first"
    tnl.configure_workload("job", token=lambda: current)

    async def scenario() -> None:
        nonlocal current
        handle = tnl.connect("db", directory=tmp_path)
        await handle
        current = "other"
        native.pause = True

        async def prepare() -> _connections.Connection:
            return await handle

        pending = asyncio.create_task(prepare())
        try:
            assert await asyncio.to_thread(native.identifying.wait, 5)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            closing = asyncio.create_task(handle.aclose())
            native.release.set()
            await closing
            assert native.owners["same"] in native.closed
            assert native.owners["other"] in native.closed
            assert not handle._session.scope.handles
        finally:
            native.release.set()
            await asyncio.gather(pending, return_exceptions=True)

    asyncio.run(scenario())


def test_close_retains_all_concurrent_identity_selections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "first"
    tnl.configure_workload("job", token=lambda: current)
    entered = {name: threading.Event() for name in ("other", "third")}
    select = native.select

    def observe(name: str, assertion: str | None) -> object:
        if assertion in entered:
            entered[assertion].set()
        return select(name, assertion)

    monkeypatch.setattr(native, "select", observe)

    async def scenario() -> None:
        nonlocal current
        handle = tnl.connect("db", directory=tmp_path)
        await handle
        native.pause = True

        async def prepare() -> _connections.Connection:
            return await handle

        pending: list[asyncio.Task[_connections.Connection]] = []
        closing: asyncio.Task[None] | None = None
        try:
            for name, event in entered.items():
                current = name
                pending.append(asyncio.create_task(prepare()))
                assert await asyncio.to_thread(event.wait, 5)
            closing = asyncio.create_task(handle.aclose())
            async with asyncio.timeout(5):
                while True:
                    try:
                        handle.snapshot()
                    except tnl.TnlError as error:
                        assert error.code == "sdk.connection_closed"
                        break
                    await asyncio.sleep(0)
            assert not closing.done()
            native.release.set()
            for result in await asyncio.gather(*pending, return_exceptions=True):
                assert isinstance(result, tnl.TnlError) and result.code == "sdk.connection_closed"
            await closing
            assert len(set(native.owners.values())) == 3
            assert set(native.closed) == set(native.owners.values())
            assert not handle._session.scope.handles
        finally:
            native.release.set()
            await asyncio.gather(*pending, return_exceptions=True)
            if closing is not None:
                await asyncio.gather(closing, return_exceptions=True)

    asyncio.run(scenario())


def test_unretained_preparation_errors_do_not_accumulate_cleanup_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    NativeFixture(tmp_path, monkeypatch)
    current = "first"
    tnl.configure_workload("job", token=lambda: current)

    async def scenario() -> None:
        nonlocal current
        handle = tnl.connect("db", directory=tmp_path)
        await handle
        current = "forged"
        for _ in range(40):
            with pytest.raises(tnl.TnlError):
                await handle
            assert not handle._lifetime.preparations
        await handle.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["owner", "start"])
@pytest.mark.parametrize("retry_close", [False, True])
def test_recovery_failure_keeps_exact_replacement_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, retry_close: bool
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    current = "other"
    tnl.configure_workload("job", token=lambda: current)
    original = tnl.TnlError("sdk.connection_unavailable", "the old owner is unavailable")
    replacement = str(tmp_path / "replacement") if failure == "owner" else "b" * 64 + "." + "2" * 16
    diagnostic: dict[str, object] = {"reason": "TNL_CLIENT_CONNECTION_EXPIRED"}
    if failure == "owner":
        diagnostic["sdk_owner_handle"] = replacement
    else:
        diagnostic.update(sdk_retained_start_failure=True, sdk_failure_handle=replacement)
    recoveries: list[str] = []
    cleanup: list[tuple[str, str]] = []
    select = native.select

    def unavailable(name: str, assertion: str | None) -> object:
        if assertion == "first":
            raise original
        return select(name, assertion)

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if "--recover-handle" in args:
            assert args[0] == "sdk-prepare" and "--retain-start-failure" in args
            recoveries.append(args[args.index("--recover-handle") + 1])
            raise _connections._native_error(
                diagnostic["reason"],
                diagnostic.get("sdk_retained_start_failure") is True,
                diagnostic.get("sdk_failure_handle"),
                diagnostic.get("sdk_owner_handle"),
            )
        if args[0] in {"stop", "sdk-close-failure"}:
            flag = "--handle" if args[0] == "stop" else "--failure-handle"
            cleanup.append((args[0], args[args.index(flag) + 1]))
        return native.command(binary, *args, input_value=input_value)

    monkeypatch.setattr(native, "select", unavailable)
    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        nonlocal current
        peer = tnl.connect("db", directory=tmp_path)
        await peer
        scope = peer._session.scope
        peer_owner = peer._session.handle
        current = "first"
        failed = tnl.connect("db", directory=tmp_path)
        with pytest.raises(tnl.TnlError) as caught:
            await failed
        assert recoveries == [peer_owner] and not cleanup
        if retry_close:
            native.fail_close = True
            with pytest.raises(tnl.TnlError):
                await failed.aclose()
            assert failed._lifetime.closed and not failed._lifetime.joined
            assert not native.closed
            native.fail_close = False
        await failed.aclose()
        expected = "stop" if failure == "owner" else "sdk-close-failure"
        assert cleanup == [(expected, replacement)] * (2 if retry_close else 1)
        assert native.closed == ([replacement] if failure == "owner" else [])
        assert "sdk-stop" not in native.calls
        assert set(scope.handles) == {peer_owner}
        assert not scope.failures and not scope.failure_handles
        assert failed._lifetime.joined
        error = caught.value
        assert isinstance(
            error, (_connections._OwnerPreparationFailure, _connections._RetainedStartFailure)
        )
        assert error.handle == replacement and error.code == "sdk.connection_expired"
        before = list(cleanup)
        await failed.aclose()
        assert cleanup == before
        current = "other"
        await peer
        await peer.aclose()
        assert not scope.handles

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "reference",
    [
        {},
        {"sdk_owner_handle": "relative-owner"},
        {"sdk_retained_start_failure": True, "sdk_failure_handle": "invalid"},
    ],
)
def test_recovery_failure_without_cleanup_reference_preserves_original_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reference: dict[str, object]
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)
    tnl.configure_workload("job", token=lambda: "first")
    original = tnl.TnlError("sdk.connection_unavailable", "the old owner is unavailable")

    def unavailable(name: str, assertion: str | None) -> object:
        raise original

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if "--recover-handle" in args:
            raise _connections._native_error(
                "TNL_SERVER_RESPONSE_INVALID",
                reference.get("sdk_retained_start_failure") is True,
                reference.get("sdk_failure_handle"),
                reference.get("sdk_owner_handle"),
            )
        return native.command(binary, *args, input_value=input_value)

    async def scenario() -> None:
        handle = tnl.connect("db", directory=tmp_path)
        await handle
        monkeypatch.setattr(native, "select", unavailable)
        monkeypatch.setattr(_connections, "_command", command)
        with pytest.raises(tnl.TnlError) as caught:
            await handle
        assert caught.value is original and caught.value.__cause__ is None
        assert not handle._lifetime.preparations
        await handle.aclose()

    asyncio.run(scenario())


def test_callback_failures_do_not_expose_private_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = NativeFixture(tmp_path, monkeypatch)

    def token() -> str:
        raise RuntimeError("private-assertion")

    tnl.configure_workload("job", token=token)
    with pytest.raises(tnl.TnlError) as caught:
        asyncio.run(_workload.select_workload("db", native.preview))
    assert "private-assertion" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
