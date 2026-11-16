"""inherited deployments fail before taking a vanished parent thread's scope lock."""

import asyncio
import multiprocessing
import os
import threading
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Literal

import pytest

import tnl
from tnl import _connections, _deployments


def inherited_deployment(
    deployment: _deployments.Deployment,
    action: Literal["acquire", "close"],
    result: Connection,
) -> None:
    try:
        if action == "acquire":
            try:
                asyncio.run(deployment.connect("db"))
            except tnl.TnlError as error:
                assert error.code == "sdk.connection_closed"
            else:
                raise AssertionError("child acquired its parent's deployment")
            try:
                deployment.client("db", create=lambda _: object(), close=lambda _: None)
            except tnl.TnlError as error:
                assert error.code == "sdk.connection_closed"
            else:
                raise AssertionError("child created a factory on its parent's deployment")
            try:
                asyncio.run(deployment.__aenter__())
            except tnl.TnlError as error:
                assert error.code == "sdk.connection_closed"
            else:
                raise AssertionError("child entered its parent's deployment")
        else:
            asyncio.run(deployment.aclose())
            assert not deployment._closed
        result.send("fenced")
    except BaseException as error:
        result.send(f"{type(error).__name__}: {error}")
    finally:
        result.close()


@pytest.mark.parametrize("selection", ["local", "production"])
@pytest.mark.parametrize("action", ["acquire", "close"])
def test_inherited_deployment_never_waits_on_parent_scope_lock(
    monkeypatch: pytest.MonkeyPatch, selection: str, action: Literal["acquire", "close"]
) -> None:
    deployment = tnl.create_client(
        project="acme/shop",
        services={"db": {"protocol": "postgres"}},
        token="private-credential",
    ).deployment(selection)
    deployment._scope.registry = "/fixture/parent-registry"
    deployment._scope._binary = Path("/fixture/tnl")
    calls: list[int] = []

    def command(*_args: object, **_kwargs: object) -> object:
        calls.append(os.getpid())
        return {"schema": 1, "state": "stopped"}

    monkeypatch.setattr(_connections, "_command", command)
    held, release = threading.Event(), threading.Event()

    def hold_scope() -> None:
        with deployment._scope.lock:
            held.set()
            release.wait()

    worker = threading.Thread(target=hold_scope)
    worker.start()
    context = multiprocessing.get_context("fork")
    result, child_result = context.Pipe(duplex=False)
    child = context.Process(target=inherited_deployment, args=(deployment, action, child_result))
    try:
        assert held.wait(5), "parent did not hold the deployment scope lock"
        child.start()
        child_result.close()
        child.join(5)
        assert not child.is_alive(), "child waited on the inherited deployment scope lock"
        assert child.exitcode == 0
        assert result.poll(1), "child did not report its PID fence"
        assert result.recv() == "fenced"
        assert not deployment._closed and not calls
    finally:
        if child.pid is not None:
            if child.is_alive():
                child.kill()
            child.join(5)
            child.close()
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        result.close()
        child_result.close()
    asyncio.run(deployment.aclose())
    assert calls == [os.getpid()]
