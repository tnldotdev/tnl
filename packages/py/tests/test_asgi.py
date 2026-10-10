"""exercise ASGI startup, native registration, streaming, and close boundaries."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
import websockets
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import Receive, Scope, Send

import tnl
from tnl import _asgi
from tnl._native import NativeRuntime
from tnl._protocol import InvalidResponse, NativeUnavailable, RegistrationLost, parse_status

_token = "tnl_eph_" + "A" * 22 + "." + "B" * 43
_public_url = "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test"


class FakeNative(NativeRuntime):
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.target = ""
        self.fail_status = False

    async def start(self, directory: str) -> str:
        self.events.append("socket")
        return "/tmp/tnl-test.sock"

    async def request(self, socket: str, operation: str, payload: dict[str, object]) -> object:
        if operation == "register":
            self.events.append("register")
            self.target = str(payload["target"])
            assert payload["credential"] == _token
            return {
                "version": 1,
                "registration_id": payload["registration_id"],
                "state": "routable",
                "public_url_id": "url_allocated",
                "public_url": _public_url,
                "publish_run_number": 1,
            }
        if operation == "status":
            if self.fail_status:
                raise NativeUnavailable()
            return {
                "version": 1,
                "registration_id": payload["registration_id"],
                "state": "routable",
                "public_url_id": "url_allocated",
                "public_url": _public_url,
                "publish_run_number": 1,
            }
        if operation == "unregister":
            self.events.append("unregister")
        return None


def test_python_uses_the_same_go_and_typescript_socket_fixture() -> None:
    path = Path(__file__).resolve().parents[3] / "internal/privateprotocol/testdata/adhoc.json"
    fixture: object = json.loads(path.read_text())
    assert isinstance(fixture, dict)
    ready = fixture["ready"]
    assert isinstance(ready, dict)
    registration_id = ready["registration_id"]
    assert isinstance(registration_id, str)
    assert parse_status(ready, registration_id).public_url == _public_url
    failed = fixture["failed"]
    assert parse_status(failed, registration_id).failure_code == "runtime.publication_failed"
    with pytest.raises(InvalidResponse):
        parse_status({**ready, "credential": "not allowed in status"}, registration_id)


def test_single_request_handler_requires_an_explicit_asgi_adapter() -> None:
    async def scenario() -> None:
        async def endpoint(request: Request) -> PlainTextResponse:
            return PlainTextResponse("received " + (await request.body()).decode())

        app = tnl.handler(endpoint)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://local",
        ) as client:
            response = await client.post("/nested/path", content=b"body")
            assert response.status_code == 200 and response.text == "received body"

    asyncio.run(scenario())


def test_lifespan_precedes_registration_and_close_joins_websockets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        events: list[str] = []
        native = FakeNative(events)
        monkeypatch.setattr(_asgi, "_native", native)

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "lifespan":
                while True:
                    message = await receive()
                    if message["type"] == "lifespan.startup":
                        events.append("startup")
                        await send({"type": "lifespan.startup.complete"})
                    elif message["type"] == "lifespan.shutdown":
                        events.append("shutdown")
                        await send({"type": "lifespan.shutdown.complete"})
                        return
            elif scope["type"] == "http":
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"hel", "more_body": True})
                await send({"type": "http.response.body", "body": b"lo", "more_body": False})
            elif scope["type"] == "websocket":
                await receive()
                await send({"type": "websocket.accept"})
                await send({"type": "websocket.send", "text": "hello websocket"})
                await receive()

        async with tnl.open(
            app, credential=_token, allow_all_ips=True, limits=tnl.Limits(requests=2)
        ) as tunnel:
            assert tunnel.url == _public_url
            assert events.index("startup") < events.index("register")
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    native.target + "/", headers={"Host": "app.example.test"}
                )
                assert response.status_code == 200 and response.text == "hello"
            async with websockets.connect(native.target.replace("http://", "ws://") + "/ws") as ws:
                assert await ws.recv() == "hello websocket"
        await tunnel.wait()
        assert events.index("register") < events.index("unregister") < events.index("shutdown")

    asyncio.run(scenario())


def test_strict_budget_fails_closed_if_native_manager_disappears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = FakeNative([])
        monkeypatch.setattr(_asgi, "_native", native)

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "lifespan":
                while True:
                    message = await receive()
                    if message["type"] == "lifespan.startup":
                        await send({"type": "lifespan.startup.complete"})
                    elif message["type"] == "lifespan.shutdown":
                        await send({"type": "lifespan.shutdown.complete"})
                        return

        async with tnl.open(app, credential=_token, limits=tnl.Limits(requests=1)) as tunnel:
            native.fail_status = True
            with pytest.raises(RegistrationLost):
                await asyncio.wait_for(tunnel.wait(), 2)

    asyncio.run(scenario())


def test_asgi_setup_preserves_publication_and_cleanup_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingNative(FakeNative):
        async def request(self, socket: str, operation: str, payload: dict[str, object]) -> object:
            if operation == "register":
                return {
                    "version": 1,
                    "registration_id": payload["registration_id"],
                    "state": "failed",
                    "failure_code": "runtime.publication_failed",
                }
            if operation == "unregister":
                raise tnl.TnlError("sdk.request_rejected", "cleanup failed")
            return None

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return

    monkeypatch.setattr(_asgi, "_native", FailingNative([]))

    async def scenario() -> None:
        async with tnl.open(app, credential=_token):
            pytest.fail("publication failure was accepted")

    with pytest.raises(ExceptionGroup) as caught:
        asyncio.run(scenario())
    codes = [error.code for error in caught.value.exceptions if isinstance(error, tnl.TnlError)]
    assert codes == ["sdk.publication_failed", "sdk.request_rejected"]
