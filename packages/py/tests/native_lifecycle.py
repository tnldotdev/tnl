"""actual SDK close and failure routing through the production native registry."""

import asyncio
import os
import socket
from pathlib import Path

import tnl
from tnl import _connections


def released(port: int) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))


async def run(handle: tnl.ConnectionHandle[tnl.Connection], first: tnl.Connection) -> None:
    assert await asyncio.to_thread(input) == "lifecycle"
    owner = handle._session.handle
    assert owner is not None
    os.environ["TNL_CONNECTION_HANDLE"] = owner
    try:
        borrowed = tnl.connect("api")
        assert (await borrowed).port == first.port
        await borrowed.aclose()
    finally:
        del os.environ["TNL_CONNECTION_HANDLE"]
    assert Path(owner).exists() and (await handle).port == first.port
    alias = tnl.connect("api")
    await alias
    await asyncio.gather(handle.aclose(), alias.aclose(), handle.aclose())
    assert not Path(owner).exists()
    released(first.port)

    replacement = tnl.connect("api")
    current = await replacement
    new_owner = replacement._session.handle
    assert new_owner is not None and new_owner != owner
    await alias.aclose()
    assert (await replacement).port == current.port and Path(new_owner).exists()
    # force an actual native cleanup error, retaining its exact reference for retry.
    Path(new_owner).chmod(0o644)
    try:
        try:
            await replacement.aclose()
        except tnl.TnlError as error:
            assert error.code == "sdk.connection_unavailable"
        else:
            raise AssertionError("native accepted an unprotected owner handle")
        assert not replacement._session.joined and Path(new_owner).exists()
    finally:
        Path(new_owner).chmod(0o600)
    await replacement.aclose()
    assert replacement._session.joined and not Path(new_owner).exists()
    released(current.port)
    print("joined", flush=True)

    assert await asyncio.to_thread(input) == "startup"
    starting = tnl.connect("api")

    async def prepare(selected: tnl.ConnectionHandle[tnl.Connection]) -> tnl.Connection:
        return await selected

    pending = asyncio.create_task(prepare(starting))
    print("starting", flush=True)
    assert await asyncio.to_thread(input) == "close"
    (preparation,) = starting._lifetime.preparations
    closing = asyncio.create_task(starting.aclose())
    while not starting._lifetime.closed:
        await asyncio.sleep(0)
    assert not closing.done() and not pending.done()
    print("closing", flush=True)
    await closing
    try:
        await pending
    except tnl.TnlError as error:
        assert error.code == "sdk.connection_closed"
    else:
        raise AssertionError("closed startup returned a live connection")
    assert starting._session.joined and preparation.pending == 0
    assert not starting._session.scope.handles
    print("startup-joined", flush=True)

    assert await asyncio.to_thread(input) == "failure"
    failed = tnl.connect("api")
    errors = await asyncio.gather(*(prepare(failed) for _ in range(8)), return_exceptions=True)
    original = errors[0]
    assert isinstance(original, tnl.TnlError)
    assert all(error is original for error in errors)
    assert original.__cause__ is None
    assert failed._session.scope.failure_handles
    print("denied", flush=True)
    assert await asyncio.to_thread(input) == "retained"
    try:
        await failed
    except tnl.TnlError as error:
        assert error is original and error.__cause__ is None
    else:
        raise AssertionError("retained startup failure retried authentication")
    print("retained", flush=True)
    assert await asyncio.to_thread(input) == "retry"
    await failed.aclose()
    healthy = tnl.connect("api")
    snapshot = await healthy
    await failed.aclose()
    assert (await healthy).port == snapshot.port
    await healthy.aclose()
    released(snapshot.port)
    assert all(scope.pending == 0 for scope in _connections._sessions.values())
    print("recovered", flush=True)
