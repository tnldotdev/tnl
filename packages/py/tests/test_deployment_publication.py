"""deployment publication uses the shared native monitor and real ASGI listener."""

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
    directory: str
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
        self.status_entered = asyncio.Event()
        self.routable = asyncio.Event()
        self.routable.set()
        self.registered = asyncio.Event()
        self.reply = asyncio.Event()
        self.reply.set()
        self.draining = asyncio.Event()
        self.drained = asyncio.Event()
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
        self.sessions[endpoint.capability] = Session(endpoint, directory, environment, publications)
        return endpoint

    async def request(
        self,
        endpoint: Endpoint,
        operation: str,
        payload: dict[str, object] | None = None,
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
                        },
                    },
                },
            }
        if operation in {"ad-hoc/register", "register"}:
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
                        "publish_run_number": 1,
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


def test_remote_publication_without_facts_captures_selection_and_joins_only_its_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        monkeypatch.setenv("TNL_TOKEN", "captured-private")
        monkeypatch.setenv("TNL_STATE_DIR", "/private/original-state")
        client = tnl.create_client(project="acme/shop")
        first, sibling = client.deployment("production"), client.deployment("customer")
        monkeypatch.setenv("TNL_TOKEN", "wrong-tenant")
        monkeypatch.setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/wrong/file")
        monkeypatch.setenv("TNL_STATE_DIR", "/private/changed-state")
        named = await first.publish("web", tnl.handler(endpoint))
        temporary = await sibling.publish(tnl.handler(endpoint))
        a, b = native.sessions.values()
        assert a.payloads[0]["deployment"] == {
            "project": "acme/shop",
            "name": "production",
            "service": "web",
            "credential": "captured-private",
        }
        assert b.payloads[0]["deployment"] == {
            "project": "acme/shop",
            "name": "customer",
            "credential": "captured-private",
        }
        for session in (a, b):
            assert session.publications
            assert session.environment is not None
            assert session.environment["TNL_STATE_DIR"] == "/private/original-state"
            assert "publisher_credential_file" not in session.payloads[0]
            assert "access_mode" not in session.payloads[0]
        assert "captured-private" not in repr(named)
        await first.aclose()
        assert a.stopped and not b.stopped
        assert named._serve_task.done() and not temporary._serve_task.done()
        async with httpx.AsyncClient(trust_env=False) as http:
            assert (await http.get(str(b.registration["target"]))).text == "ASGI application"
        async with temporary:
            assert temporary.url == b.url
        await sibling.aclose()
        assert b.stopped and temporary._serve_task.done()

    asyncio.run(scenario())


def test_local_named_publication_uses_framework_registration_and_saved_policy(
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
        session = next(iter(native.sessions.values()))
        assert not session.publications and session.endpoint.scope == "app"
        assert publication.url == session.url
        assert "prepare" in native.operations and "register" in native.operations
        assert "ad-hoc/register" not in native.operations
        await local.aclose()
        assert session.stopped

    asyncio.run(scenario())


def test_publication_waits_for_routability_and_cancellation_joins_registration_and_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.routable.clear()
        native.reply.clear()
        native.drained.clear()
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publishing = asyncio.create_task(deployment.publish(tnl.handler(endpoint)))
        await native.registered.wait()
        assert not publishing.done()
        publishing.cancel()
        await asyncio.sleep(0)
        assert not publishing.done()
        native.reply.set()
        await native.draining.wait()
        assert not publishing.done()
        session = next(iter(native.sessions.values()))
        async with httpx.AsyncClient(trust_env=False) as http:
            assert (await http.get(str(session.registration["target"]))).status_code == 200
        publishing.cancel()
        await asyncio.sleep(0)
        assert not publishing.done()
        native.drained.set()
        with pytest.raises(asyncio.CancelledError):
            await publishing
        assert session.stopped
        await deployment.aclose()

    asyncio.run(scenario())


def test_lost_initial_reply_recovers_original_intent_before_asgi_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.lose_reply = True
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        with pytest.raises(NativeUnavailable):
            await deployment.publish(tnl.handler(endpoint), access="anonymous")
        session = next(iter(native.sessions.values()))
        assert len(native.sessions) == 1 and len(session.payloads) == 2
        assert session.payloads[0] == session.payloads[1]
        assert session.payloads[0]["access_mode"] == "anonymous"
        assert session.stopped
        await deployment.aclose()

    asyncio.run(scenario())


def test_deployment_close_retries_retained_start_cleanup_and_defers_its_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.lose_reply = True
        native.failed_cleanup = True
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        with pytest.raises(ExceptionGroup) as failure:
            await deployment.publish(tnl.handler(endpoint))
        assert [
            value.code for value in failure.value.exceptions if isinstance(value, tnl.TnlError)
        ] == [
            "sdk.dev_unavailable",
            "sdk.request_rejected",
        ]
        assert len(deployment._publications) == 1
        publication = next(iter(deployment._publications))
        assert not publication._serve_task.done()
        native.failed_cleanup = False
        native.draining.clear()
        native.drained.clear()
        closing = asyncio.create_task(deployment.aclose())
        await native.draining.wait()
        closing.cancel()
        await asyncio.sleep(0)
        assert not closing.done() and not publication._serve_task.done()
        native.drained.set()
        with pytest.raises(asyncio.CancelledError):
            await closing
        assert publication._serve_task.done()

    asyncio.run(scenario())


def test_publication_context_retains_body_failure_and_retryable_native_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publication = await deployment.publish(tnl.handler(endpoint))
        primary = ValueError("application operation failed")
        native.failed_cleanup = True
        with pytest.raises(ExceptionGroup) as failure:
            async with publication:
                raise primary
        assert failure.value.exceptions[0] is primary
        cleanup = failure.value.exceptions[1]
        assert isinstance(cleanup, tnl.TnlError) and cleanup.code == "sdk.request_rejected"
        assert not publication._serve_task.done()
        native.failed_cleanup = False
        await deployment.aclose()
        assert publication._serve_task.done()

    asyncio.run(scenario())
