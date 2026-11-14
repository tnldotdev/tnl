"""public deployment cleanup against the production native registry."""

import asyncio
import os
import socket
from pathlib import Path

import tnl


def released(port: int) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))


async def run(client: tnl.Client, deployment: tnl.Deployment, first: tnl.HTTPConnection) -> None:
    assert await asyncio.to_thread(input) == "lifecycle"
    owner = deployment._acquisitions["api"]._session.handle
    assert owner is not None
    os.environ["TNL_CONNECTION_HANDLE"] = owner
    try:
        borrowed = client.deployment("production")
        connection = await borrowed.connect("api")
        assert isinstance(connection, tnl.HTTPConnection) and connection.port == first.port
        await borrowed.aclose()
    finally:
        del os.environ["TNL_CONNECTION_HANDLE"]
    assert Path(owner).exists()
    await asyncio.gather(deployment.aclose(), deployment.aclose())
    assert not Path(owner).exists()
    released(first.port)

    replacement = client.deployment("production")
    current = await replacement.connect("api")
    assert isinstance(current, tnl.HTTPConnection)
    new_owner = replacement._acquisitions["api"]._session.handle
    assert new_owner is not None and new_owner != owner
    await deployment.aclose()
    assert Path(new_owner).exists()
    Path(new_owner).chmod(0o644)
    try:
        try:
            await replacement.aclose()
        except BaseExceptionGroup as error:
            assert error.exceptions
        else:
            raise AssertionError("native accepted an unprotected owner handle")
        assert Path(new_owner).exists()
    finally:
        Path(new_owner).chmod(0o600)
    await replacement.aclose()
    assert not Path(new_owner).exists()
    released(current.port)
    print("joined", flush=True)

    assert await asyncio.to_thread(input) == "startup"
    starting = client.deployment("production")
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
    assert not starting._scope.pending
    print("startup-joined", flush=True)

    assert await asyncio.to_thread(input) == "failure"
    failed = client.deployment("production")
    errors = await asyncio.gather(
        *(failed.connect("api") for _ in range(8)), return_exceptions=True
    )
    original = errors[0]
    assert isinstance(original, tnl.TnlError)
    assert all(error is original for error in errors) and original.__cause__ is None
    assert failed._scope.failure_handles
    print("denied", flush=True)
    assert await asyncio.to_thread(input) == "retained"
    try:
        await failed.connect("api")
    except tnl.TnlError as error:
        assert error is original and error.__cause__ is None
    else:
        raise AssertionError("retained startup failure retried authentication")
    print("retained", flush=True)
    assert await asyncio.to_thread(input) == "retry"
    await failed.aclose()
    healthy = client.deployment("production")
    snapshot = await healthy.connect("api")
    assert isinstance(snapshot, tnl.HTTPConnection)
    await failed.aclose()
    current = await healthy.connect("api")
    assert isinstance(current, tnl.HTTPConnection) and current.host == snapshot.host
    await healthy.aclose()
    released(snapshot.port)
    print("recovered", flush=True)
