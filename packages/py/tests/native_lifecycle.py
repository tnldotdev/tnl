"""actual explicit SDK owner lifetime, borrowed handles and exact close retry."""

import asyncio
import os
import socket
from collections.abc import Callable
from pathlib import Path

import tnl
from native_services import Client, actual_owner, context


def released(port: int) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))


def unavailable(error: BaseException) -> None:
    if isinstance(error, BaseExceptionGroup):
        assert len(error.exceptions) == 1
        unavailable(error.exceptions[0])
    else:
        assert isinstance(error, tnl.TnlError) and error.code == "sdk.connection_unavailable"


async def run(selected: Client, first: tnl.HTTPConnection, new_client: Callable[[], Client]) -> None:
    assert await asyncio.to_thread(input) == "lifecycle"
    owner = actual_owner(selected)
    os.environ["TNL_CONNECTION_HANDLE"] = str(owner)
    try:
        borrowed = tnl.connect("api")
        assert (await borrowed).port == first.port
        await borrowed.aclose()
    finally:
        del os.environ["TNL_CONNECTION_HANDLE"]
    assert owner.exists() and (await selected.connect("api")).port == first.port
    alias = selected
    await asyncio.gather(selected.aclose(), alias.aclose(), selected.aclose())
    assert not owner.exists()
    released(first.port)

    replacement = new_client()
    current = await replacement.connect("api")
    new_owner = actual_owner(replacement)
    assert new_owner != owner
    await alias.aclose()
    assert (await replacement.connect("api")).port == current.port and new_owner.exists()
    new_owner.chmod(0o644)
    try:
        try:
            await replacement.aclose()
        except BaseException as error:
            unavailable(error)
        else:
            raise AssertionError("native accepted an unprotected owner handle")
        assert not context(replacement)._owners[0].stopped and new_owner.exists()
    finally:
        new_owner.chmod(0o600)
    await replacement.aclose()
    assert context(replacement)._owners[0].stopped and not new_owner.exists()
    released(current.port)
    print("joined", flush=True)

    assert await asyncio.to_thread(input) == "startup"
    starting = new_client()
    pending = asyncio.create_task(starting.connect("api"))
    print("starting", flush=True)
    assert await asyncio.to_thread(input) == "close"
    closing = asyncio.create_task(starting.aclose())
    while not starting._closed:
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
    source = context(starting)
    assert not source._workers and not source._sources
    assert all(owner.stopped and owner.process.returncode is not None for owner in source._owners)
    print("startup-joined", flush=True)

    assert await asyncio.to_thread(input) == "failure"
    failed = new_client()
    errors = await asyncio.gather(*(failed.connect("api") for _ in range(8)), return_exceptions=True)
    original = errors[0]
    assert isinstance(original, tnl.TnlError)
    assert all(error is original for error in errors) and original.__cause__ is None
    retained = context(failed)._starts["api"]
    assert retained.done() and retained.exception() is original
    print("denied", flush=True)
    assert await asyncio.to_thread(input) == "retained"
    try:
        await failed.connect("api")
    except tnl.TnlError as error:
        assert error is original and error.__cause__ is None
    else:
        raise AssertionError("retained startup failure retried authentication")
    assert context(failed)._starts["api"] is retained
    print("retained", flush=True)
    assert await asyncio.to_thread(input) == "retry"
    await failed.aclose()
    healthy = new_client()
    snapshot = await healthy.connect("api")
    await failed.aclose()
    assert (await healthy.connect("api")).port == snapshot.port
    await healthy.aclose()
    released(snapshot.port)
    assert all(not context(client)._workers and not context(client)._sources for client in (failed, healthy))
    print("recovered", flush=True)
