"""check the installed wheel against a real local ASGI listener."""

from __future__ import annotations

import asyncio

import httpx
import websockets
from starlette.types import Receive, Scope, Send

import tnl
from tnl import _asgi
from tnl._native import NativeRuntime


class NativeStub(NativeRuntime):
    def __init__(self) -> None:
        self.events: list[str] = []
        self.target = ""

    async def start(self, directory: str) -> str:
        return "/unused/native.sock"

    async def request(self, socket: str, operation: str, payload: dict[str, object]) -> object:
        if operation == "register":
            self.events.append("register")
            self.target = str(payload["target"])
        if operation == "unregister":
            self.events.append("unregister")
            return None
        if operation == "renew":
            return None
        return {
            "version": 1,
            "registration_id": payload["registration_id"],
            "state": "routable",
            "public_url_id": "url_wheel_smoke",
            "public_url": "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test",
            "publish_run_number": 1,
        }


async def main() -> None:
    native = NativeStub()
    _asgi._native = native

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    native.events.append("startup")
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    native.events.append("shutdown")
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        elif scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"one", "more_body": True})
            await send({"type": "http.response.body", "body": b" two"})
        elif scope["type"] == "websocket":
            await receive()
            await send({"type": "websocket.accept"})
            message = await receive()
            await send({"type": "websocket.send", "text": str(message["text"])})
            await send({"type": "websocket.close", "code": 1000})

    async with tnl.open(
        app,
        credential="tnl_eph_" + "A" * 22 + "." + "B" * 43,
        limits=tnl.Limits(requests=2),
    ) as tunnel:
        assert tunnel.url == "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test"
        async with httpx.AsyncClient() as client:
            response = await client.get(native.target + "/")
            assert response.status_code == 200 and response.text == "one two"
        async with websockets.connect(native.target.replace("http://", "ws://") + "/") as ws:
            await ws.send("wheel websocket")
            assert await ws.recv() == "wheel websocket"
    await tunnel.wait()
    assert native.events == ["startup", "register", "unregister", "shutdown"]


if __name__ == "__main__":
    asyncio.run(main())
