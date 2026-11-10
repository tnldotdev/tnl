"""source Python SDK through the real native registration and publisher owner."""

from __future__ import annotations

import asyncio
import socket
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

import tnl
from tnl import _native


async def main() -> None:
    credential, resource, binary, mode = sys.argv[1:]
    assert mode in {"python-prepare", "python-publish"}
    _native.native_binary = lambda: Path(binary)
    app = tnl.create_tnl(
        credential=Path(credential).read_text(),
        directory=Path.cwd(),
        state_dir=Path.cwd() / "state",
    )
    servers: list[tuple[uvicorn.Server, asyncio.Task[None], socket.socket]] = []
    release = asyncio.Event()
    lifespan: list[str] = []
    contexts = AsyncExitStack()

    async def command(expected: str) -> None:
        assert await asyncio.to_thread(input) == expected

    def handler(body: bytes) -> ASGIApp:
        async def asgi(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "lifespan":
                while True:
                    message = await receive()
                    if message["type"] == "lifespan.startup":
                        lifespan.append("startup")
                        await send({"type": "lifespan.startup.complete"})
                    elif message["type"] == "lifespan.shutdown":
                        lifespan.append("shutdown")
                        await send({"type": "lifespan.shutdown.complete"})
                        return
            assert scope["type"] == "http"
            assert b"tnl-visitor-token" not in dict(scope["headers"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            if scope["path"] == "/held":
                await send(
                    {"type": "http.response.body", "body": b"held prefix", "more_body": True}
                )
                await release.wait()
                body_value = b" held suffix"
            else:
                body_value = body
            await send({"type": "http.response.body", "body": body_value})

        return asgi

    async def listen(body: bytes) -> str:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        server = uvicorn.Server(
            uvicorn.Config(handler(body), lifespan="off", log_level="critical", access_log=False)
        )
        task = asyncio.create_task(server.serve(sockets=[listener]))
        servers.append((server, task, listener))
        while not server.started:
            if task.done():
                await task
                raise AssertionError("listener did not start")
            await asyncio.sleep(0.01)
        return f"http://127.0.0.1:{listener.getsockname()[1]}"

    try:
        prepared = None
        if mode == "python-prepare":
            prepared = await app.prepare(resource=resource)
            print("prepared", prepared.public_url, flush=True)
            await command("bind")
            target = await listen(b"first SDK listener")
            print("starting", flush=True)
            publication = await prepared.register(target)
            status = await publication.status()
            assert status.registered and not status.routable
            print("bound", flush=True)
            await command("ready")
        else:
            print("starting", flush=True)
            publication = await contexts.enter_async_context(
                app.publish(handler(b"first SDK listener"), resource=resource)
            )
            assert lifespan == ["startup"]
        await asyncio.wait_for(publication.wait(), 15)
        status = await publication.status()
        events = publication.watch(after=status.cursor)
        try:
            next_event = asyncio.create_task(anext(events))
            await asyncio.wait_for(publication.wait(), 15)
            event = await asyncio.wait_for(next_event, 15)
            assert event.cursor != status.cursor and event.snapshot is None
        finally:
            await events.aclose()
        print("ready", publication.url, flush=True)
        await command("visit")
        if prepared is not None:
            replacement = await prepared.register(await listen(b"replacement SDK listener"))
            try:
                await publication.status()
            except tnl.RegistrationLost:
                pass
            else:
                raise AssertionError("old handle observed its replacement")
            await publication.close()
            await asyncio.wait_for(replacement.wait(), 15)
            print("replaced", flush=True)
            await command("visit")
        await command("close")
        closing = asyncio.create_task(app.aclose())
        print("closing", flush=True)
        await command("release")
        assert not closing.done()
        release.set()
        await closing
        assert all(not task.done() and not server.should_exit for server, task, _ in servers)
        if mode == "python-publish":
            assert lifespan == ["startup", "shutdown"]
        await contexts.aclose()
        print("closed", flush=True)
    finally:
        release.set()
        await app.aclose()
        await contexts.aclose()
        for server, _, _ in servers:
            server.should_exit = True
        await asyncio.gather(*(task for _, task, _ in servers))
        for _, _, listener in servers:
            listener.close()


asyncio.run(main())
