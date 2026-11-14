"""exercise ASGI startup, native registration, streaming, and close boundaries."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Mapping

import httpx
import pytest
import websockets
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import Receive, Scope, Send

import tnl
from tnl import _asgi
from tnl._asgi import start_publication
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, InvalidResponse, NativeUnavailable, parse_status

_publisher = "pub_" + "A" * 22
_public_url = "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test"


class FakeNative(NativeRuntime):
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.target = ""
        self.fail_status = False
        self.registration: dict[str, object] = {}
        self.invocation_id = ""
        self.starts = 0

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
        self.events.append("endpoint")
        self.starts += 1
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
            assert payload.get("publisher_identity_id", _publisher) == _publisher
            assert "enrollment_key" not in payload
            self.registration = {
                "version": 1,
                "registration_id": "reg_" + str(self.starts) * 32,
                "owner": payload["owner"],
                "target": self.target,
            }
            return self.registration
        if operation == "status":
            if self.fail_status:
                self.fail_status = False
                raise NativeUnavailable()
            return self.snapshot()
        if operation == "unregister":
            assert payload == self.registration
            self.events.append("unregister")
        return None

    def snapshot(self) -> dict[str, object]:
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
                    "public_url": _public_url,
                    "run_number": self.starts,
                }
            ],
        }


def test_status_is_filtered_and_fenced_by_registration_and_bound_target() -> None:
    native = FakeNative([])
    native.invocation_id = "ivk_" + "A" * 22
    native.registration = {"registration_id": "reg_" + "a" * 32}
    native.target = "http://127.0.0.1:1234"
    native.starts = 1
    ready = native.snapshot()
    status = parse_status(
        ready, native.invocation_id, str(native.registration["registration_id"]), native.target
    )
    assert status is not None and status.public_url == _public_url
    assert parse_status(ready, native.invocation_id, "reg_" + "b" * 32, native.target) is None
    assert (
        parse_status(
            ready,
            native.invocation_id,
            str(native.registration["registration_id"]),
            "http://127.0.0.1:4321",
        )
        is None
    )
    with pytest.raises(InvalidResponse):
        parse_status(
            {**ready, "capability": "secret"},
            native.invocation_id,
            str(native.registration["registration_id"]),
            native.target,
        )
    with pytest.raises(InvalidResponse):
        parse_status(ready, "another", str(native.registration["registration_id"]), native.target)


@pytest.mark.parametrize(
    ("url", "valid"),
    [
        ("https://web.example", True),
        ("https://web.example:1024", True),
        ("https://web.example:25443", True),
        ("https://web.example:65535", True),
        ("https://127.1.example:25443", True),
        ("https://2130706433.example:25443", True),
        ("https://0x7f000001.example:25443", True),
        ("https://0177.0.0.1.example:25443", True),
        ("https://api-123.7.example:25443", True),
        ("https://api.123-test:25443", True),
        ("https://api.0x7f-test:25443", True),
        ("http://web.example:25443", False),
        ("https://user:secret@web.example:25443", False),
        ("https://web.example:25443/", False),
        ("https://web.example:25443?query", False),
        ("https://web.example:25443#fragment", False),
        ("https://web.example:025443", False),
        ("https://web.example:443", False),
        ("https://web.example:0", False),
        ("https://web.example:80", False),
        ("https://web.example:1023", False),
        ("https://web.example:65536", False),
        ("https://127.0.0.1:25443", False),
        ("https://127.1:25443", False),
        ("https://2130706433:25443", False),
        ("https://0x7f000001:25443", False),
        ("https://0177.0.0.1:25443", False),
        ("https://api.123:25443", False),
        ("https://api.0xff:25443", False),
        ("https://0x:25443", False),
    ],
)
def test_status_preserves_only_canonical_public_http_origins(url: str, valid: bool) -> None:
    native = FakeNative([])
    native.invocation_id = "ivk_" + "A" * 22
    native.registration = {"registration_id": "reg_" + "a" * 32}
    native.target, native.starts = "http://127.0.0.1:1234", 1
    snapshot = native.snapshot()
    services = snapshot["services"]
    assert isinstance(services, list) and isinstance(services[0], dict)
    services[0]["public_url"] = url
    if valid:
        status = parse_status(
            snapshot,
            native.invocation_id,
            str(native.registration["registration_id"]),
            native.target,
        )
        assert status is not None and status.public_url == url
    else:
        with pytest.raises(InvalidResponse):
            parse_status(
                snapshot,
                native.invocation_id,
                str(native.registration["registration_id"]),
                native.target,
            )


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


def test_invocation_status_matches_the_exact_native_tunnel() -> None:
    native = FakeNative([])
    native.invocation_id = "ivk_" + "A" * 22
    native.registration = {"registration_id": "reg_" + "a" * 32}
    native.target, native.starts = "http://127.0.0.1:1234", 1
    value = native.snapshot()
    services = value["services"]
    assert isinstance(services, list) and isinstance(services[0], dict)
    services[0]["tunnel_id"] = "exact-tunnel"
    publication = {
        "tunnel_id": "exact-tunnel",
        "command": "publish",
        "state": "ready",
        "process_id": 1,
        "server": "https://control.example",
        "project": "/project",
        "publish_run_number": 1,
        "started_at": value["observed_at"],
        "updated_at": value["observed_at"],
        "heartbeat_at": value["observed_at"],
        "lease_expires_at": value["observed_at"],
    }
    value["publications"] = [publication]
    assert (
        parse_status(
            value, native.invocation_id, str(native.registration["registration_id"]), native.target
        )
        is not None
    )
    for changed in (
        {**publication, "tunnel_id": "another-tunnel"},
        {**publication, "service": "another-service"},
    ):
        with pytest.raises(InvalidResponse):
            parse_status(
                {**value, "publications": [changed]},
                native.invocation_id,
                str(native.registration["registration_id"]),
                native.target,
            )
    services[0]["publish_run_number"] = services[0].pop("run_number")
    with pytest.raises(InvalidResponse):
        parse_status(
            value, native.invocation_id, str(native.registration["registration_id"]), native.target
        )


def test_default_selection_omits_credentials_and_explicit_file_is_sent_only_to_native(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = FakeNative([])
        monkeypatch.setattr(_asgi, "_native", native)

        async def endpoint(request: Request) -> PlainTextResponse:
            return PlainTextResponse("published")

        async with await start_publication(tnl.handler(endpoint)) as tunnel:
            assert tunnel.url == _public_url
            assert "require_post_quantum" not in tunnel._payload
            assert "publisher_credential_file" not in tunnel._payload
            assert "publisher_identity_id" not in tunnel._payload
        async with await start_publication(
            tnl.handler(endpoint),
            publisher_credential_file="/private/publisher.json",
            require_post_quantum=True,
            telemetry=False,
        ) as tunnel:
            assert tunnel._payload["require_post_quantum"] is True
            assert tunnel._payload["telemetry_disabled"] is True
            assert tunnel._payload["publisher_credential_file"] == "/private/publisher.json"
            assert "publisher_identity_id" not in tunnel._payload
            assert "/private/publisher.json" not in repr(tunnel)
            assert "/private/publisher.json" not in repr(native.snapshot())
        monkeypatch.setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/private/deployed.json")
        async with await start_publication(tnl.handler(endpoint)) as tunnel:
            assert tunnel._payload["publisher_credential_file"] == "/private/deployed.json"
            assert "publisher_credential_file" not in repr(native.snapshot())
        async with await start_publication(
            tnl.handler(endpoint), publisher_identity_id=_publisher
        ) as tunnel:
            assert tunnel._payload["publisher_identity_id"] == _publisher
            assert "publisher_credential_file" not in tunnel._payload

    asyncio.run(scenario())


def test_invalid_explicit_selection_never_starts_native(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        native = FakeNative([])
        monkeypatch.setattr(_asgi, "_native", native)

        async def endpoint(request: Request) -> PlainTextResponse:
            return PlainTextResponse("app")

        app = tnl.handler(endpoint)
        with pytest.raises(
            tnl.TnlError, match="publisher_credential_file must be an absolute path"
        ):
            async with await start_publication(app, publisher_credential_file="relative/file"):
                pytest.fail("invalid file was accepted")
        with pytest.raises(tnl.TnlError, match="select a publisher file or publisher ID"):
            async with await start_publication(
                app, publisher_credential_file="/private/file", publisher_identity_id=_publisher
            ):
                pytest.fail("conflicting selectors were accepted")
        assert native.starts == 0

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

        async with await start_publication(
            app, publisher_identity_id=_publisher, access="anonymous", limits=tnl.Limits(requests=2)
        ) as tunnel:
            assert tunnel.url == _public_url
            assert tunnel._payload["publisher_identity_id"] == _publisher
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


def test_invocation_reconnects_if_native_owner_is_replaced(
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

        async with await start_publication(app, publisher_identity_id=_publisher) as tunnel:
            native.fail_status = True
            async with asyncio.timeout(2):
                while native.starts < 2:
                    await asyncio.sleep(0.01)
            assert tunnel.url == _public_url
            assert native.events.count("register") == 2

    asyncio.run(scenario())


def test_close_joins_an_inflight_replacement_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        registering = asyncio.Event()
        acknowledge = asyncio.Event()
        events: list[str] = []

        class DelayedNative(FakeNative):
            async def request(
                self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
            ) -> object:
                if operation == "publications/register" and self.starts == 2:
                    registering.set()
                    await acknowledge.wait()
                return await super().request(endpoint, operation, payload)

        native = DelayedNative(events)
        monkeypatch.setattr(_asgi, "_native", native)

        async def endpoint(request: Request) -> PlainTextResponse:
            return PlainTextResponse("app")

        async with await start_publication(
            tnl.handler(endpoint), publisher_identity_id=_publisher
        ) as tunnel:
            native.fail_status = True
            await asyncio.wait_for(registering.wait(), 2)
            closing = asyncio.create_task(tunnel.aclose())
            await asyncio.sleep(0)
            assert not closing.done()
            acknowledge.set()
            await asyncio.wait_for(closing, 2)
            assert native.registration["registration_id"] == "reg_" + "2" * 32
            assert events[-1] == "unregister"

    asyncio.run(scenario())


def test_listener_exit_stops_reporting_a_routable_app(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        events: list[str] = []
        monkeypatch.setattr(_asgi, "_native", FakeNative(events))

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "lifespan":
                while True:
                    message = await receive()
                    if message["type"] == "lifespan.startup":
                        await send({"type": "lifespan.startup.complete"})
                    elif message["type"] == "lifespan.shutdown":
                        await send({"type": "lifespan.shutdown.complete"})
                        return

        async with await start_publication(app, publisher_identity_id=_publisher) as tunnel:
            tunnel._server.should_exit = True
            await asyncio.wait_for(tunnel._serve_task, 2)
            with pytest.raises(tnl.TnlError, match="ASGI listener stopped") as caught:
                await asyncio.wait_for(tunnel.wait(), 2)
            assert caught.value.code == "sdk.listener_failed"
            assert "unregister" in events

    asyncio.run(scenario())


def test_asgi_setup_preserves_publication_and_cleanup_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingNative(FakeNative):
        fail_cleanup = True

        async def request(
            self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
        ) -> object:
            if operation == "status":
                snapshot = self.snapshot()
                services = snapshot["services"]
                assert isinstance(services, list)
                services[0]["routable"] = False
                services[0]["failure"] = "runtime.publication_failed"
                return snapshot
            if operation == "unregister" and self.fail_cleanup:
                raise tnl.TnlError("sdk.request_rejected", "cleanup failed")
            return await super().request(endpoint, operation, payload)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return

    native = FailingNative([])
    monkeypatch.setattr(_asgi, "_native", native)
    servers: list[_asgi._OwnedServer] = []
    start_asgi = _asgi._start_asgi

    async def capture(
        app: _asgi.ASGIApp,
    ) -> tuple[_asgi._OwnedServer, asyncio.Task[None], socket.socket]:
        server, task, listener = await start_asgi(app)
        servers.append(server)
        return server, task, listener

    monkeypatch.setattr(_asgi, "_start_asgi", capture)

    async def scenario() -> None:
        with pytest.raises(ExceptionGroup) as caught:
            async with await start_publication(app, publisher_identity_id=_publisher):
                pytest.fail("publication failure was accepted")
        codes = [error.code for error in caught.value.exceptions if isinstance(error, tnl.TnlError)]
        assert codes == ["sdk.publication_failed", "sdk.request_rejected"]
        tunnel = servers[0].tunnel
        assert tunnel is not None and not tunnel._serve_task.done()
        assert not tunnel._server.should_exit
        native.fail_cleanup = False
        await tunnel.aclose()
        assert tunnel._serve_task.done()

    asyncio.run(scenario())
