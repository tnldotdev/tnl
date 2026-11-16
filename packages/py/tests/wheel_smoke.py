"""check the installed wheel against a real local ASGI listener."""

from __future__ import annotations

import asyncio
import importlib.metadata
import pathlib
import subprocess
import sys
from collections.abc import Mapping

import httpx
import websockets
from starlette.types import Receive, Scope, Send

import tnl
from tnl import _asgi, models
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint


class NativeStub(NativeRuntime):
    def __init__(self) -> None:
        self.events: list[str] = []
        self.target = ""
        self.registration: dict[str, object] = {}
        self.invocation_id = ""

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
        self.invocation_id = invocation_id or ""
        return Endpoint(
            "http://127.0.0.1:1234", "b" * 64, "a" * 32, "invocation", invocation_id=invocation_id
        )

    async def request(
        self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
    ) -> object:
        if operation == "publications/register":
            assert payload is not None
            self.events.append("register")
            self.target = str(payload["target"])
            self.registration = {
                "version": 1,
                "registration_id": "reg_" + "a" * 32,
                "owner": payload["owner"],
                "target": self.target,
            }
            return self.registration
        if operation == "unregister":
            self.events.append("unregister")
            return None
        if operation == "renew":
            return None
        return {
            "schema_version": 1,
            "project": "/project",
            "cursor": "cursor",
            "observed_at": "2026-10-14T12:00:00Z",
            "services": [
                {
                    "service": self.invocation_id,
                    "directory": ".",
                    "registration_id": self.registration["registration_id"],
                    "target": self.target,
                    "registered": True,
                    "routable": True,
                    "ready": False,
                    "readiness": {"path": "/"},
                    "public_url": "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test",
                    "run_number": 1,
                }
            ],
        }


async def main() -> None:
    # importing generated models and constructing a client starts no native work.
    tnl.create_client(project="acme/shop", token="private")
    body = models.CreateDeploymentRequest.model_validate(
        {"name": "customer", "targets": {"db": {"address": "db:5432"}}}
    )
    assert body.model_dump(mode="json")["targets"]["db"]["address"] == "db:5432"
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

    assert not hasattr(tnl, "open") and not hasattr(tnl, "Tunnel")
    deployment = tnl.create_client(project="acme/shop").deployment("local")
    async with await deployment.publish(app) as tunnel:
        assert tunnel.url == "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test"
        async with httpx.AsyncClient() as client:
            response = await client.get(native.target + "/")
            assert response.status_code == 200 and response.text == "one two"
        async with websockets.connect(native.target.replace("http://", "ws://") + "/") as ws:
            await ws.send("wheel websocket")
            assert await ws.recv() == "wheel websocket"
    await tunnel.wait()
    await deployment.aclose()
    assert native.events == ["startup", "register", "unregister", "shutdown"]


if __name__ == "__main__":
    version, release, commit = sys.argv[1:]
    package = pathlib.Path(tnl.__file__).parent
    assert importlib.metadata.version("tnldotdev-tnl") == version
    assert (package / "py.typed").is_file()
    assert subprocess.check_output([str(package / "bin/tnl"), "version"], text=True).strip() == (
        f"tnl {release} ({commit})"
    )
    asyncio.run(main())
