"""lost registration replies retain real native commit and joined-worker boundaries."""

from __future__ import annotations

import asyncio
import json
import selectors
import subprocess
from collections.abc import Mapping
from pathlib import Path

import httpx
import pytest
from starlette.types import Receive, Scope, Send

from tnl import _asgi
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, NativeUnavailable, PublicationCleanupFailed, parse_endpoint


@pytest.mark.parametrize("cancel", [False, True])
def test_initial_registration_reply_loss_reconciles_and_joins_before_asgi_shutdown(
    tmp_path: Path, native_app_owner: Path, monkeypatch: pytest.MonkeyPatch, cancel: bool
) -> None:
    with subprocess.Popen(
        [str(native_app_owner), "-tnl-invocations", str(tmp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as owner:
        assert owner.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(owner.stdout, selectors.EVENT_READ)
            assert selector.select(10), "native invocation fixture did not start"
        line = owner.stdout.readline()
        if not line:
            _, errors = owner.communicate(timeout=5)
            pytest.fail(errors.decode())
        descriptor = json.loads(line)

        class MountedNative(NativeRuntime):
            async def start(
                self,
                directory: str,
                *,
                service: str | None = None,
                invocation_id: str | None = None,
                state_dir: str | None = None,
                publications: bool = False,
                environment: Mapping[str, str] | None = None,
            ) -> Endpoint:
                # only discovery is supplied by the fixture; registration uses
                # the actual scoped native HTTP handler and SQLite manager.
                async with httpx.AsyncClient(trust_env=False) as client:
                    reply = await client.post(
                        descriptor["url"] + "/v1/capabilities",
                        headers={"Authorization": "Bearer " + descriptor["capability"]},
                        json={"scope": "invocation", "invocation_id": invocation_id},
                    )
                    reply.raise_for_status()
                    return parse_endpoint(reply.json(), invocation_id=invocation_id)

        monkeypatch.setattr(_asgi, "_native", MountedNative())

        async def scenario() -> None:
            shutdown = asyncio.Event()

            async def app(scope: Scope, receive: Receive, send: Send) -> None:
                if scope["type"] == "lifespan":
                    while True:
                        message = await receive()
                        if message["type"] == "lifespan.startup":
                            await send({"type": "lifespan.startup.complete"})
                        elif message["type"] == "lifespan.shutdown":
                            shutdown.set()
                            await send({"type": "lifespan.shutdown.complete"})
                            return
                elif scope["type"] == "http":
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": b"still serving"})

            async def publish() -> None:
                async with await _asgi.start_publication(app, directory=tmp_path):
                    pytest.fail("lost initial reply was accepted")

            async def marker(name: str) -> None:
                async with asyncio.timeout(4):
                    while not (tmp_path / name).exists():
                        await asyncio.sleep(0.01)

            task = asyncio.create_task(publish())
            try:
                await marker("committed.json")
                registration = json.loads((tmp_path / "committed.json").read_text())
                if cancel:
                    task.cancel()
                (tmp_path / "release-register").touch()
                await marker("drain-started")
                assert not task.done() and not shutdown.is_set()
                async with httpx.AsyncClient(trust_env=False) as client:
                    reply = await client.get(registration["target"])
                    assert reply.text == "still serving"
                if cancel:
                    # repeated cancellation must still join native cleanup.
                    task.cancel()
                    await asyncio.sleep(0.05)
                    assert not task.done() and not shutdown.is_set()
                (tmp_path / "release-drain").touch()
                with pytest.raises(asyncio.CancelledError if cancel else NativeUnavailable):
                    await asyncio.wait_for(task, 4)
                assert shutdown.is_set()
                assert len(list(tmp_path.glob("worker-*"))) == 1
            finally:
                (tmp_path / "release-register").touch()
                (tmp_path / "release-drain").touch()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        try:
            asyncio.run(scenario())
        finally:
            owner.terminate()
            _, errors = owner.communicate(timeout=10)
            assert owner.returncode == 0, errors.decode()


@pytest.mark.parametrize("outcome", ["terminal", "transient", "success"])
def test_lost_unregister_reply_recovers_the_exact_native_outcome_and_closes_asgi(
    tmp_path: Path, native_app_owner: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    with subprocess.Popen(
        [
            str(native_app_owner),
            "-tnl-invocations",
            "-tnl-cleanup-reply-loss",
            outcome,
            str(tmp_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as owner:
        assert owner.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(owner.stdout, selectors.EVENT_READ)
            assert selector.select(10), "native invocation fixture did not start"
        descriptor = json.loads(owner.stdout.readline())

        class MountedNative(NativeRuntime):
            async def start(
                self,
                directory: str,
                *,
                service: str | None = None,
                invocation_id: str | None = None,
                state_dir: str | None = None,
                publications: bool = False,
                environment: Mapping[str, str] | None = None,
            ) -> Endpoint:
                async with httpx.AsyncClient(trust_env=False) as client:
                    reply = await client.post(
                        descriptor["url"] + "/v1/capabilities",
                        headers={"Authorization": "Bearer " + descriptor["capability"]},
                        json={"scope": "invocation", "invocation_id": invocation_id},
                    )
                    reply.raise_for_status()
                    return parse_endpoint(reply.json(), invocation_id=invocation_id)

        monkeypatch.setattr(_asgi, "_native", MountedNative())

        async def scenario() -> None:
            shutdown = asyncio.Event()

            async def app(scope: Scope, receive: Receive, send: Send) -> None:
                if scope["type"] == "lifespan":
                    while True:
                        message = await receive()
                        if message["type"] == "lifespan.startup":
                            await send({"type": "lifespan.startup.complete"})
                        elif message["type"] == "lifespan.shutdown":
                            shutdown.set()
                            await send({"type": "lifespan.shutdown.complete"})
                            return
                elif scope["type"] == "http":
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": b"still serving"})

            publication = await _asgi.start_publication(app, directory=tmp_path)
            target = publication._target
            (tmp_path / "release-drain").touch()
            if outcome == "terminal":
                with pytest.raises(PublicationCleanupFailed) as closing:
                    await publication.aclose()
                with pytest.raises(PublicationCleanupFailed) as finished:
                    await publication.wait()
                assert finished.value is closing.value
                reply = json.loads((tmp_path / "cleanup-reply.json").read_text())
                assert reply["code"] == "runtime.publication_cleanup_failed"
            else:
                await publication.aclose()
                await publication.wait()
            assert publication._close_complete and publication._serve_task.done()
            assert shutdown.is_set()
            assert (tmp_path / "cleanup-attempts").read_text() == (
                "2" if outcome == "transient" else "1"
            )
            assert len(list(tmp_path.glob("worker-*"))) == 1
            async with httpx.AsyncClient(trust_env=False) as client:
                with pytest.raises(httpx.ConnectError):
                    await client.get(target)

        try:
            asyncio.run(scenario())
        finally:
            (tmp_path / "release-drain").touch()
            owner.terminate()
            _, errors = owner.communicate(timeout=10)
            assert owner.returncode == 0, errors.decode()
