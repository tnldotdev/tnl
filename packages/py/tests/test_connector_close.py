"""closing joins preparations before releasing their exact native references."""

from __future__ import annotations

import asyncio
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tnl
from tnl import _connections


def test_close_before_first_handle_joins_native_and_retains_failed_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "_sessions", {})
    monkeypatch.delenv("TNL_CONNECTION_HANDLE", raising=False)
    for name in ("TNL_WORKLOAD", "VERCEL", "GITHUB_ACTIONS", "FLY_APP_NAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    starting, stopping, release = threading.Event(), threading.Event(), threading.Event()
    failure = tnl.TnlError("sdk.connection_unavailable", "cleanup did not join")
    stop_attempts = 0
    stopped_registries: list[str] = []
    owner = str(tmp_path / "owner" / "handle.json")

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        nonlocal stop_attempts
        if args[0] == "sdk-prepare":
            starting.set()
            assert release.wait(5)
            raise _connections._OwnerPreparationFailure(
                tnl.TnlError("sdk.connection_unavailable", "initial service failed"), owner
            )
        assert args[0] == "sdk-close" and args[-2:] == ("--handle", owner)
        stopped_registries.append(args[args.index("--registry") + 1])
        stopping.set()
        stop_attempts += 1
        if stop_attempts == 1:
            raise failure
        return {"schema": 1, "state": "stopped"}

    monkeypatch.setattr(_connections, "_command", command)
    handle = tnl.connect("database", directory=tmp_path)

    async def prepare() -> tnl.Connection:
        return await handle

    async def scenario() -> None:
        pending = asyncio.create_task(prepare())
        assert await asyncio.to_thread(starting.wait, 5)
        (preparation,) = handle._lifetime.preparations
        try:
            closing = asyncio.create_task(handle.aclose())
            while not handle._lifetime.closed:
                await asyncio.sleep(0)
            assert not closing.done() and not stopping.is_set()
            release.set()
            with pytest.raises(tnl.TnlError) as error:
                await closing
            assert error.value is failure
            assert stopping.is_set() and preparation.pending == 0
            registry = handle._session.scope.registry
            assert registry is not None
            await handle.aclose()
            assert stopped_registries == [registry, registry]
            assert handle._session.joined
            with pytest.raises(tnl.TnlError):
                await pending
            with pytest.raises(tnl.TnlError, match="closed"):
                await handle
            assert stop_attempts == 2
        finally:
            release.set()
            await asyncio.gather(pending, return_exceptions=True)

    asyncio.run(scenario())


def test_known_owner_is_retained_if_opening_its_ipc_client_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "_sessions", {})
    binary = Path(sys.executable).resolve(strict=True)
    monkeypatch.setattr(_connections, "native_binary", lambda: binary)
    owner = str(tmp_path / "owner" / "handle.json")
    failure = tnl.TnlError("sdk.connection_unavailable", "owner IPC client failed")
    closed: list[str] = []

    class IPC:
        def __init__(self, path: str) -> None:
            raise failure

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-prepare":
            return {
                "schema": 1,
                "owner": {
                    "connection_handle": owner,
                    "executable": str(binary),
                    "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                },
                "prepared": {},
            }
        assert args[0] == "sdk-close" and args[-2:] == ("--handle", owner)
        closed.append(owner)
        return {"schema": 1, "state": "stopped"}

    monkeypatch.setattr(_connections, "OwnerIPC", IPC)
    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        handle = tnl.connect("database", directory=tmp_path)
        with pytest.raises(tnl.TnlError) as caught:
            await handle
        assert caught.value is failure
        await handle.aclose()
        assert closed == [owner]
        assert not handle._session.scope.handles and handle._session.scope.registry is None

    asyncio.run(scenario())
