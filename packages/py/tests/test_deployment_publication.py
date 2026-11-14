"""deployment publication composes the native monitor and a real ASGI listener."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import PlainTextResponse

import tnl
from tnl import _asgi, _connections
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, NativeUnavailable


@dataclass
class Session:
    endpoint: Endpoint
    environment: Mapping[str, str] | None
    publications: bool
    registration: dict[str, object] = field(default_factory=dict)
    payloads: list[dict[str, object]] = field(default_factory=list)
    stopped: bool = False

    @property
    def url(self) -> str:
        return f"https://app-{self.endpoint.owner_id}.example.test"


class Native(NativeRuntime):
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}
        self.operations: list[str] = []
        self.status_entered, self.routable = asyncio.Event(), asyncio.Event()
        self.routable.set()
        self.registered, self.reply = asyncio.Event(), asyncio.Event()
        self.reply.set()
        self.draining, self.drained = asyncio.Event(), asyncio.Event()
        self.drained.set()
        self.lose_reply = False
        self.failed_cleanup = False

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
        ident = str(len(self.sessions) + 1).zfill(32)
        endpoint = Endpoint(
            "http://127.0.0.1:1234",
            ident * 2,
            ident,
            "invocation" if service is None else "app",
            service=service,
            invocation_id=invocation_id,
        )
        self.sessions[endpoint.capability] = Session(endpoint, environment, publications)
        return endpoint

    async def request(
        self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
    ) -> object:
        self.operations.append(operation)
        session = self.sessions[endpoint.capability]
        if operation == "prepare":
            host = session.url.removeprefix("https://")
            return {
                "version": 1,
                "registration_id": "reg_" + endpoint.owner_id,
                "service": endpoint.service,
                "hostname": host,
                "public_url": session.url,
                "project": {
                    "dev": True,
                    "namespace": "example.test",
                    "services": {
                        "web": {
                            "protocol": "http",
                            "namespace": "example.test",
                            "hostname": host,
                            "port": 443,
                            "public": True,
                            "url": session.url,
                        }
                    },
                },
            }
        if operation in {"publications/register", "register"}:
            assert payload is not None
            session.payloads.append(dict(payload))
            session.registration = {
                "version": 1,
                "registration_id": "reg_" + endpoint.owner_id,
                "owner": payload["owner"],
                "target": payload["target"],
            }
            self.registered.set()
            await self.reply.wait()
            if self.lose_reply:
                self.lose_reply = False
                raise NativeUnavailable()
            return session.registration
        if operation == "status":
            self.status_entered.set()
            await self.routable.wait()
            return {
                "schema_version": 1,
                "project": "/project",
                "cursor": "cursor",
                "observed_at": "2026-11-13T12:00:00Z",
                "services": [
                    {
                        "service": endpoint.service or endpoint.invocation_id,
                        "directory": ".",
                        "registration_id": session.registration["registration_id"],
                        "target": session.registration["target"],
                        "registered": True,
                        "routable": True,
                        "ready": False,
                        "readiness": {"path": "/"},
                        "public_url": session.url,
                        "run_number": 1,
                    }
                ],
            }
        if operation == "unregister":
            self.draining.set()
            await self.drained.wait()
            if self.failed_cleanup:
                raise tnl.TnlError("sdk.request_rejected", "cleanup failed")
            assert payload == session.registration
            session.stopped = True
        return None


async def endpoint(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ASGI application")


def setup(monkeypatch: pytest.MonkeyPatch) -> Native:
    native = Native()
    monkeypatch.setattr(_asgi, "_native", native)
    monkeypatch.setattr(_connections._Scope, "stop", lambda _scope: None)
    return native


def test_hard_cutover_captured_authority_and_independent_publications(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not hasattr(tnl, "open") and not hasattr(tnl, "Tunnel")

    async def scenario() -> None:
        native = setup(monkeypatch)
        monkeypatch.setenv("TNL_TOKEN", "captured-private")
        monkeypatch.setenv("TNL_STATE_DIR", "/private/original")
        client = tnl.create_client(project="acme/shop")
        a, b = client.deployment("production"), client.deployment("customer")
        monkeypatch.setenv("TNL_TOKEN", "other-tenant")
        monkeypatch.setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/wrong/file")
        named = await a.publish("web", tnl.handler(endpoint))
        temporary = await b.publish(tnl.handler(endpoint))
        first, second = native.sessions.values()
        assert first.payloads[0]["deployment"] == {
            "project": "acme/shop",
            "name": "production",
            "service": "web",
            "credential": "captured-private",
        }
        assert second.payloads[0]["deployment"] == {
            "project": "acme/shop",
            "name": "customer",
            "credential": "captured-private",
        }
        for session in (first, second):
            assert session.publications
            assert (
                session.environment is not None
                and session.environment["TNL_STATE_DIR"] == "/private/original"
            )
            assert "publisher_credential_file" not in session.payloads[0]
            assert "access_mode" not in session.payloads[0]
        assert "captured-private" not in repr(named)
        await a.aclose()
        assert first.stopped and not second.stopped
        async with httpx.AsyncClient(trust_env=False) as http:
            assert (await http.get(str(second.registration["target"]))).text == "ASGI application"
        async with temporary:
            assert temporary.url == second.url
        await b.aclose()
        assert named._serve_task.done() and temporary._serve_task.done()

    asyncio.run(scenario())


def test_local_named_uses_framework_registration_and_saved_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        local = tnl.create_client(
            project="acme/shop",
            services={"web": {"protocol": "http"}, "db": {"protocol": "postgres"}},
        ).deployment("local")
        with pytest.raises(tnl.TnlError):
            await local.publish("db", tnl.handler(endpoint))
        with pytest.raises(tnl.TnlError):
            await local.publish("web", tnl.handler(endpoint), access="anonymous")
        assert not native.sessions
        publication = await local.publish("web", tnl.handler(endpoint))
        assert "prepare" in native.operations and "register" in native.operations
        assert "publications/register" not in native.operations
        await local.aclose()
        assert publication._serve_task.done()

    asyncio.run(scenario())


def test_readiness_and_cancellation_join_late_registration_and_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.routable.clear()
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publishing = asyncio.create_task(deployment.publish(tnl.handler(endpoint)))
        await native.status_entered.wait()
        assert not publishing.done()
        native.routable.set()
        publication = await publishing
        await publication.aclose()
        native.registered.clear()
        native.reply.clear()
        native.drained.clear()
        publishing = asyncio.create_task(deployment.publish(tnl.handler(endpoint)))
        await native.registered.wait()
        publishing.cancel()
        await asyncio.sleep(0)
        assert not publishing.done()
        native.reply.set()
        native.draining.clear()
        await native.draining.wait()
        publishing.cancel()
        await asyncio.sleep(0)
        assert not publishing.done()
        native.drained.set()
        with pytest.raises(asyncio.CancelledError):
            await publishing
        await deployment.aclose()
        assert all(session.stopped for session in native.sessions.values())

    asyncio.run(scenario())


def test_lost_reply_retains_exact_intent_and_retryable_start_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.lose_reply, native.failed_cleanup = True, True
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        with pytest.raises(ExceptionGroup) as failure:
            await deployment.publish(tnl.handler(endpoint), access="anonymous")
        assert [
            value.code for value in failure.value.exceptions if isinstance(value, tnl.TnlError)
        ] == ["sdk.dev_unavailable", "sdk.request_rejected"]
        session = next(iter(native.sessions.values()))
        assert len(session.payloads) == 2 and session.payloads[0] == session.payloads[1]
        assert len(deployment._publications) == 1
        publication = next(iter(deployment._publications))
        assert not publication._serve_task.done()
        native.failed_cleanup = False
        native.draining.clear()
        native.drained.clear()
        closing = asyncio.create_task(deployment.aclose())
        await native.draining.wait()
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert deployment._closing is not None and not deployment._closing.done()
        assert not publication._serve_task.done()
        native.drained.set()
        await deployment.aclose()
        assert publication._serve_task.done()

    asyncio.run(scenario())


def test_publication_rejects_inherited_process_and_foreign_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        setup(monkeypatch)
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publication = await deployment.publish(tnl.handler(endpoint))
        pid, loop = publication._pid, publication._loop
        publication._pid = pid + 1
        with pytest.raises(tnl.TnlError) as failed:
            await publication.aclose()
        assert failed.value.code == "sdk.client_context_changed"
        publication._pid = pid
        other = asyncio.new_event_loop()
        try:
            publication._loop = other
            with pytest.raises(tnl.TnlError) as failed:
                await publication.wait()
            assert failed.value.code == "sdk.client_context_changed"
        finally:
            publication._loop = loop
            other.close()
            await deployment.aclose()

    asyncio.run(scenario())


def test_context_preserves_body_failure_and_retryable_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publication = await deployment.publish(tnl.handler(endpoint))
        primary = ValueError("application failure")
        native.failed_cleanup = True
        with pytest.raises(ExceptionGroup) as failure:
            async with publication:
                raise primary
        assert failure.value.exceptions[0] is primary
        assert not publication._serve_task.done()
        native.failed_cleanup = False
        await deployment.aclose()
        assert publication._serve_task.done()

    asyncio.run(scenario())
