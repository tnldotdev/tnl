"""application grants compose the existing ASGI listener and native invocation owners."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Mapping
from datetime import UTC, datetime

import httpx
import pytest
from starlette.types import ASGIApp, Receive, Scope, Send
from test_application_http import PUBLISH, SERVICE, URL, Authority, document, grants
from test_application_preparation import publisher_document
from test_asgi import FakeNative
from test_token_http import TOKEN

import tnl
from tnl import _asgi, _credential, _runtime
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, InvalidResponse, NativeUnavailable


class ApplicationNative(FakeNative):
    def __init__(self) -> None:
        super().__init__([])
        NativeRuntime.__init__(self)
        self.payloads: list[dict[str, object]] = []
        self.environments: list[dict[str, str | None]] = []
        self.public = True
        self.routable = True
        self.wait_register = False
        self.registered = asyncio.Event()
        self.release = asyncio.Event()
        self.cleanup_started = asyncio.Event()
        self.fail_cleanup = False
        self.lose_reply = False
        self.fail_status_denied = False

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def select(environment: Mapping[str, str | None]) -> ApplicationNative:
            self.environments.append(dict(environment))
            self._environment = dict(environment)
            return self

        monkeypatch.setattr(_runtime, "NativeRuntime", select)
        monkeypatch.setattr(_asgi, "_POLL_INTERVAL", 0.001)

    async def request(
        self,
        endpoint: Endpoint,
        operation: str,
        payload: dict[str, object] | None = None,
    ) -> object:
        if operation == "ad-hoc/register":
            assert payload is not None
            assert set(payload) == {
                "version",
                "invocation_id",
                "owner",
                "pid",
                "target",
                "server_url",
                "application_credential",
                "resource_id",
            }
            parsed = _credential.application_document(payload["application_credential"])
            assert len(parsed.grants) == 1 and parsed.grants[0].operation == "publish"
            assert parsed.grants[0].resource == payload["resource_id"]
            assert parsed.control_url == payload["server_url"] == "https://control.example"
            self.payloads.append(dict(payload))
            reply = await super().request(endpoint, operation, payload)
            self.registered.set()
            if self.wait_register:
                await self.release.wait()
            if self.lose_reply:
                self.lose_reply = False
                raise NativeUnavailable()
            return reply
        if operation == "unregister":
            self.cleanup_started.set()
            if self.fail_cleanup:
                raise tnl.TnlError("sdk.request_rejected", "native cleanup is unconfirmed")
        if operation == "status" and self.fail_status_denied:
            raise tnl.TnlError("sdk.credential_denied", "the application grant was revoked")
        return await super().request(endpoint, operation, payload)

    def snapshot(self) -> dict[str, object]:
        snapshot = super().snapshot()
        services = snapshot["services"]
        assert isinstance(services, list)
        item = services[0]
        resource = self.payloads[-1]["resource_id"]
        if resource == PUBLISH:
            item["public_url"] = "https://preview.example"
        elif self.public:
            item["public_url"] = "https://api.example:20001"
        else:
            item.pop("public_url")
        item["routable"] = self.routable
        return snapshot


def asgi(events: list[str]) -> ASGIApp:
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
            await send({"type": "http.response.body", "body": b"application ASGI bytes"})

    return app


@pytest.mark.parametrize("serialized", [False, True])
@pytest.mark.parametrize("resource,public", [(PUBLISH, True), (SERVICE, True), (SERVICE, False)])
def test_application_asgi_uses_only_the_exact_grant_and_the_existing_owned_listener(
    monkeypatch: pytest.MonkeyPatch,
    serialized: bool,
    resource: str,
    public: bool,
) -> None:
    native = ApplicationNative()
    native.install(monkeypatch)
    native.public = public
    monkeypatch.setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/private/must-not-read.json")
    monkeypatch.setenv("TNL_SERVER", "https://personal.example")
    value = publisher_document()

    async def scenario() -> None:
        app = tnl.create_tnl(credential=json.dumps(value) if serialized else value)
        async with app.publish(asgi(native.events), resource=resource) as publication:
            expected = (
                "https://preview.example"
                if resource == PUBLISH
                else ("https://api.example:20001" if public else None)
            )
            assert publication.url == expected
            assert native.events.index("startup") < native.events.index("register")
            assert (await publication.status()).routable
            async with httpx.AsyncClient(trust_env=False) as ordinary:
                response = await ordinary.get(native.target)
            assert response.status_code == 200 and response.content == b"application ASGI bytes"
            assert str(value["private_key"]) not in repr(publication)
        assert native.events.index("unregister") < native.events.index("shutdown")
        await publication.finished()
        assert not app._publications
        await app.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["token", "missing", "ambiguous", "expired"])
def test_denied_application_asgi_never_starts_lifespan_or_native(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    native = ApplicationNative()
    native.install(monkeypatch)
    value = publisher_document() if kind == "ambiguous" else document()
    if kind == "expired":
        grants(value)[2]["expires_at"] = "2020-01-01T00:00:00Z"

    async def scenario() -> None:
        async with tnl.create_tnl(credential=TOKEN if kind == "token" else value) as app:
            with pytest.raises(tnl.TnlError) as denied:
                async with app.publish(
                    asgi(native.events), resource=SERVICE if kind == "missing" else None
                ):
                    pytest.fail("an unauthorized listener was published")
            assert denied.value.code == "sdk.credential_denied"
            assert not native.events and not native.starts

    asyncio.run(scenario())


def test_application_asgi_recovers_with_the_same_resource_owner_target_and_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = ApplicationNative()
    native.install(monkeypatch)

    async def scenario() -> None:
        async with tnl.create_tnl(credential=document()) as app:
            async with app.publish(asgi(native.events)) as publication:
                native.fail_status = True
                async with asyncio.timeout(1):
                    while native.starts < 2:
                        await asyncio.sleep(0)
                assert native.payloads[0] == native.payloads[1]
                assert publication.url == "https://preview.example"
                assert native.events.count("startup") == 1
            assert native.events.count("unregister") == native.events.count("shutdown") == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("revoked", [False, True])
def test_expiry_or_revocation_finishes_the_same_publication_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    revoked: bool,
) -> None:
    native = ApplicationNative()
    native.install(monkeypatch)
    value = document()
    now = time.time()
    grants(value)[2]["expires_at"] = datetime.fromtimestamp(now + 60, UTC).isoformat()

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            async with app.publish(asgi(native.events)) as publication:
                if revoked:
                    native.fail_status_denied = True
                else:
                    monkeypatch.setattr(_credential.time, "time", lambda: now + 61)
                with pytest.raises(tnl.TnlError) as denied:
                    await asyncio.wait_for(publication.finished(), 1)
                assert denied.value.code == "sdk.credential_denied"
                assert len(native.payloads) == 1
        assert native.events[-2:] == ["unregister", "shutdown"]

    asyncio.run(scenario())


def test_expiry_during_lifespan_startup_closes_the_listener_without_registering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = ApplicationNative()
    native.install(monkeypatch)
    value = document()
    now = time.time()
    grants(value)[2]["expires_at"] = datetime.fromtimestamp(now + 60, UTC).isoformat()
    handler = asgi(native.events)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            monkeypatch.setattr(_credential.time, "time", lambda: now + 61)
        await handler(scope, receive, send)

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as runtime:
            with pytest.raises(tnl.TnlError) as denied:
                async with runtime.publish(app):
                    pytest.fail("expired grant was registered")
            assert denied.value.code == "sdk.credential_denied"
            assert native.events == ["startup", "shutdown"] and not native.starts

    asyncio.run(scenario())


def test_application_asgi_cleanup_retains_listener_and_clients_until_native_confirms_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)
    native = ApplicationNative()
    native.install(monkeypatch)
    closed: list[object] = []

    async def scenario() -> None:
        app = tnl.create_tnl(credential=value)
        get = app.client(URL, create=lambda _: object(), close=closed.append)
        ordinary = await get()
        context = app.publish(asgi(native.events))
        publication = await context.__aenter__()
        native.fail_cleanup = True
        with pytest.raises(ExceptionGroup):
            await app.aclose()
        assert not closed and authority.closed == 0 and "shutdown" not in native.events
        with pytest.raises(tnl.RegistrationLost):
            await publication.status()
        native.fail_cleanup = False
        await app.aclose()
        assert closed == [ordinary] and authority.closed == 1
        assert native.events[-2:] == ["unregister", "shutdown"]
        await context.__aexit__(None, None, None)

    asyncio.run(scenario())


@pytest.mark.parametrize("lost_reply", [False, True])
def test_canceled_application_asgi_waiter_retains_late_registration_for_joined_shutdown(
    monkeypatch: pytest.MonkeyPatch,
    lost_reply: bool,
) -> None:
    native = ApplicationNative()
    native.install(monkeypatch)
    native.wait_register = True
    native.lose_reply = lost_reply

    async def scenario() -> None:
        app = tnl.create_tnl(credential=document())
        context = app.publish(asgi(native.events))
        opening = asyncio.create_task(context.__aenter__())
        await asyncio.wait_for(native.registered.wait(), 1)
        opening.cancel("only this waiter")
        with pytest.raises(asyncio.CancelledError):
            await opening
        closing = asyncio.create_task(app.aclose())
        try:
            await asyncio.sleep(0)
            assert not closing.done() and "shutdown" not in native.events
        finally:
            native.release.set()
            await asyncio.wait_for(asyncio.shield(closing), 2)
        assert native.events[-2:] == ["unregister", "shutdown"]
        assert len(native.payloads) == (2 if lost_reply else 1)
        assert all(payload == native.payloads[0] for payload in native.payloads)

    asyncio.run(scenario())


@pytest.mark.parametrize("changed_public", [False, True])
def test_application_asgi_cannot_switch_service_reachability_after_reporting_routability(
    monkeypatch: pytest.MonkeyPatch,
    changed_public: bool,
) -> None:
    native = ApplicationNative()
    native.install(monkeypatch)
    native.public = not changed_public

    async def scenario() -> None:
        async with tnl.create_tnl(credential=publisher_document()) as app:
            async with app.publish(asgi(native.events), resource=SERVICE) as publication:
                native.public = changed_public
                with pytest.raises(InvalidResponse):
                    await asyncio.wait_for(publication.finished(), 1)
                assert len(native.payloads) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("override", ["access", "limits", "publisher_credential_file", "server"])
def test_application_asgi_internal_boundary_rejects_policy_and_identity_overrides_before_startup(
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    native = ApplicationNative()
    native.install(monkeypatch)

    async def scenario() -> None:
        with pytest.raises(tnl.TnlError) as denied:
            async with _asgi.publish_runtime(
                native,
                asgi(native.events),
                application=_credential.application_document(document()),
                access="anonymous" if override == "access" else None,
                limits=tnl.Limits(requests=1) if override == "limits" else None,
                publisher_credential_file="/private/publisher.json"
                if override == "publisher_credential_file"
                else None,
                server="https://personal.example" if override == "server" else None,
            ):
                pytest.fail("application policy was overridden")
        assert denied.value.code == "sdk.credential_denied" and not native.events

    asyncio.run(scenario())


def test_application_asgi_cleanup_failure_does_not_stop_a_sibling_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = ApplicationNative()
    first.install(monkeypatch)
    app = tnl.create_tnl(credential=document())
    second = ApplicationNative()
    second.install(monkeypatch)
    sibling = tnl.create_tnl(credential=document())

    async def scenario() -> None:
        async with app.publish(asgi(first.events)):
            async with sibling.publish(asgi(second.events)) as peer:
                first.fail_cleanup = True
                with pytest.raises(ExceptionGroup):
                    await app.aclose()
                assert "shutdown" not in second.events and (await peer.status()).routable
                first.fail_cleanup = False
                await app.aclose()
                assert "shutdown" not in second.events and (await peer.status()).routable
        await sibling.aclose()
        assert first.events.count("shutdown") == second.events.count("shutdown") == 1

    asyncio.run(scenario())
