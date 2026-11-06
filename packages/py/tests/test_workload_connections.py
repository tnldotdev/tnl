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
                workload: str | None = None,
                manifest: str | None = None,
                requested_at: str | None = None,
            ) -> object:
                if sdk:
                    assert workload == "job" and manifest is not None and requested_at is not None
                return fixture.select(name, assertion) if sdk else prepared(name, fixture.deadline)

            def close(self) -> None:
                pass

        monkeypatch.setattr(_connections, "OwnerIPC", IPC)

    def command(self, binary: Path, *args: str, input_value: object = None) -> object:
        self.calls.append(args[0])
        assert not any(token in args for token in ("first", "rotated", "forged", "other"))
        if args[0] == "sdk-prepare":
            assert "--retain-start-failure" in args
            assertion = input_value.get("assertion") if isinstance(input_value, dict) else None
            assert isinstance(assertion, str)
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

    def select(self, name: str, assertion: str | None) -> object:
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
        assert native.calls == ["sdk-prepare"]
        for _ in range(10):
            await first
        assert native.calls == ["sdk-prepare"] and callbacks == 11
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


def test_callback_failures_do_not_expose_private_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    NativeFixture(tmp_path, monkeypatch)

    def token() -> str:
        raise RuntimeError("private-assertion")

    tnl.configure_workload("job", token=token)
    with pytest.raises(tnl.TnlError) as caught:
        asyncio.run(_workload.select_workload(str(tmp_path), "db"))
    assert "private-assertion" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
