"""deployment publication composes the native monitor and a real ASGI listener."""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Mapping
from dataclasses import dataclass, field

import httpx
import pytest
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import Receive, Scope, Send

import tnl
from tnl import _asgi, _connections
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, NativeUnavailable, PublicationCleanupFailed, RegistrationLost


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
        self.retired_cleanup = False
        self.retired_error = PublicationCleanupFailed()
        self.private_http = False
        self.initial_retired = False

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
            if self.private_http:
                return {
                    "version": 1,
                    "registration_id": "reg_" + endpoint.owner_id,
                    "service": endpoint.service,
                    "hostname": "",
                    "public_url": "",
                    "project": {"dev": True, "namespace": "", "services": {}},
                }
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
            if self.initial_retired:
                session.stopped = True
                raise PublicationCleanupFailed()
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
            if self.retired_cleanup:
                session.stopped = True
                raise self.retired_error
            if self.failed_cleanup:
                raise tnl.TnlError("sdk.request_rejected", "cleanup failed")
            if session.registration:
                assert payload == session.registration
            else:
                assert payload is not None
                session.registration = dict(payload)
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


def test_private_http_prepare_releases_acknowledged_reservation_and_asgi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.private_http = True
        local = tnl.create_client(
            project="acme/shop", services={"web": {"protocol": "http"}}
        ).deployment("local")
        with pytest.raises(tnl.TnlError) as failure:
            await local.publish("web", tnl.handler(endpoint))
        assert failure.value.code == "sdk.response_invalid"
        assert native.operations.count("prepare") == 1
        assert native.operations.count("register") == 0
        assert native.operations.count("unregister") == 1
        session = next(iter(native.sessions.values()))
        assert session.stopped and not local._publications
        async with httpx.AsyncClient(trust_env=False) as http:
            with pytest.raises(httpx.ConnectError):
                await http.get(str(session.registration["target"]))
        await local.aclose()
        assert native.operations.count("prepare") == 1

    asyncio.run(scenario())


def test_permanent_startup_cleanup_closes_asgi_without_replaying_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.initial_retired = True
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        with pytest.raises(PublicationCleanupFailed):
            await deployment.publish(tnl.handler(endpoint))
        session = next(iter(native.sessions.values()))
        assert session.stopped and not deployment._publications
        assert native.operations.count("publications/register") == 1
        assert native.operations.count("unregister") == 0
        async with httpx.AsyncClient(trust_env=False) as http:
            with pytest.raises(httpx.ConnectError):
                await http.get(str(session.registration["target"]))
        await deployment.aclose()

    asyncio.run(scenario())


def test_lost_reply_and_permanent_cleanup_preserve_both_failures_and_close_asgi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.lose_reply, native.retired_cleanup = True, True
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        with pytest.raises(ExceptionGroup) as failure:
            await deployment.publish(tnl.handler(endpoint))
        assert [
            error.code for error in failure.value.exceptions if isinstance(error, tnl.TnlError)
        ] == ["sdk.dev_unavailable", "sdk.publication_cleanup_failed"]
        session = next(iter(native.sessions.values()))
        assert len(session.payloads) == 2 and session.payloads[0] == session.payloads[1]
        assert session.stopped and not deployment._publications
        async with httpx.AsyncClient(trust_env=False) as http:
            with pytest.raises(httpx.ConnectError):
                await http.get(str(session.registration["target"]))
        await deployment.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("owner", ["publication", "deployment"])
def test_permanent_cleanup_failure_closes_asgi_and_preserves_the_error(
    monkeypatch: pytest.MonkeyPatch, owner: str
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publication = await deployment.publish(tnl.handler(endpoint))
        session = next(iter(native.sessions.values()))
        native.retired_cleanup = True
        if owner == "publication":
            with pytest.raises(PublicationCleanupFailed):
                await publication.aclose()
        else:
            primary = tnl.TnlError("sdk.listener_failed", "listener failed independently")
            publication._fail(primary)
            with pytest.raises(ExceptionGroup) as failure:
                await deployment.aclose()
            assert primary in failure.value.exceptions
            assert any(
                isinstance(error, PublicationCleanupFailed) for error in failure.value.exceptions
            )
        assert session.stopped and publication._serve_task.done()
        assert not deployment._publications
        async with httpx.AsyncClient(trust_env=False) as http:
            with pytest.raises(httpx.ConnectError):
                await http.get(str(session.registration["target"]))
        await deployment.aclose()
        assert native.operations.count("unregister") == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("independent_failure", [False, True])
def test_server_driven_shutdown_finishes_owned_resources_after_terminal_unregister(
    monkeypatch: pytest.MonkeyPatch, independent_failure: bool
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        shutdown_finished = asyncio.Event()
        independent = ValueError("ASGI shutdown failed independently")
        if independent_failure:
            original = _asgi.uvicorn.Server.shutdown

            async def shutdown(
                server: _asgi.uvicorn.Server, sockets: list[socket.socket] | None = None
            ) -> None:
                await original(server, sockets)
                raise independent

            monkeypatch.setattr(_asgi.uvicorn.Server, "shutdown", shutdown)

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "lifespan":
                while True:
                    message = await receive()
                    if message["type"] == "lifespan.startup":
                        await send({"type": "lifespan.startup.complete"})
                    elif message["type"] == "lifespan.shutdown":
                        shutdown_finished.set()
                        await send({"type": "lifespan.shutdown.complete"})
                        return
            elif scope["type"] == "http":
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"keep alive"})

        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publication = await deployment.publish(app)
        native.retired_cleanup = True
        native.drained.clear()
        async with httpx.AsyncClient(trust_env=False) as client:
            assert (await client.get(publication._target)).text == "keep alive"
            assert publication._server.server_state.connections
            publication._server.should_exit = True
            await asyncio.wait_for(native.draining.wait(), 4)
            waiting = asyncio.create_task(publication.wait())
            await asyncio.sleep(0)
            assert not waiting.done() and not shutdown_finished.is_set()
            native.drained.set()
            with pytest.raises(BaseExceptionGroup) as observed:
                await asyncio.wait_for(waiting, 4)
            leaves: list[BaseException] = []

            def collect(error: BaseException) -> None:
                if isinstance(error, BaseExceptionGroup):
                    for cause in error.exceptions:
                        collect(cause)
                else:
                    leaves.append(error)

            collect(observed.value)
            assert native.retired_error in leaves
            assert any(
                isinstance(error, tnl.TnlError) and error.code == "sdk.listener_failed"
                for error in leaves
            )
            if independent_failure:
                assert independent in leaves
            with pytest.raises(BaseException) as closing:
                await publication.aclose()
            if independent_failure:
                assert isinstance(closing.value, BaseExceptionGroup)
                assert closing.value.exceptions == (native.retired_error, independent)
            else:
                assert closing.value is native.retired_error
            assert publication._close_complete and publication._serve_task.done()
            assert shutdown_finished.is_set()
            assert not publication._server.server_state.connections
            assert not deployment._publications
            with pytest.raises(httpx.ConnectError):
                await client.get(publication._target)
        await deployment.aclose()
        assert native.operations.count("unregister") == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("caller_cancels", [False, True])
@pytest.mark.parametrize("independent_failure", [False, True])
def test_internal_shutdown_deadline_cancels_and_joins_a_hung_lifespan(
    monkeypatch: pytest.MonkeyPatch, caller_cancels: bool, independent_failure: bool
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        entered, canceled, joined, release = (
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
        )
        independent = ValueError("lifespan cancellation cleanup failed")
        # arm the real timeout only after lifespan shutdown reaches its gate.
        deadline = asyncio.timeout(None)
        monkeypatch.setattr(_asgi, "_server_shutdown_deadline", lambda: deadline)

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            if scope["type"] == "lifespan":
                try:
                    while True:
                        message = await receive()
                        if message["type"] == "lifespan.startup":
                            await send({"type": "lifespan.startup.complete"})
                        elif message["type"] == "lifespan.shutdown":
                            entered.set()
                            try:
                                await release.wait()
                            except asyncio.CancelledError:
                                canceled.set()
                                if independent_failure:
                                    raise independent from None
                                raise
                            await send({"type": "lifespan.shutdown.complete"})
                            return
                finally:
                    joined.set()
            elif scope["type"] == "http":
                await send({"type": "http.response.start", "status": 200, "headers": []})
                await send({"type": "http.response.body", "body": b"keep alive"})

        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publication = await deployment.publish(app)
        native.retired_cleanup = True
        async with httpx.AsyncClient(trust_env=False) as client:
            assert (await client.get(publication._target)).text == "keep alive"
            assert publication._server.server_state.connections
            closing = asyncio.create_task(publication.aclose())
            try:
                await asyncio.wait_for(entered.wait(), 2)
                workers = tuple(publication._server._asgi_workers)
                assert workers and not closing.done()
                if caller_cancels:
                    closing.cancel()
                    await asyncio.sleep(0)
                    assert not closing.done() and not canceled.is_set()
                deadline.reschedule(asyncio.get_running_loop().time())
                done, _ = await asyncio.wait({closing}, timeout=2)
                assert done, "internal shutdown deadline waited forever for ASGI lifespan"
                with pytest.raises(BaseException) as observed:
                    await closing
                leaves: list[BaseException] = []

                def collect(error: BaseException) -> None:
                    if isinstance(error, BaseExceptionGroup):
                        for cause in error.exceptions:
                            collect(cause)
                    else:
                        leaves.append(error)

                collect(observed.value)
                assert any(isinstance(error, TimeoutError) for error in leaves)
                assert native.retired_error in leaves
                assert any(isinstance(error, asyncio.CancelledError) for error in leaves) == (
                    caller_cancels
                )
                if independent_failure:
                    assert independent in leaves
                assert publication._close_complete and publication._serve_task.done()
                assert canceled.is_set() and joined.is_set()
                assert all(worker.done() for worker in workers)
                assert not publication._server._asgi_workers
                assert not publication._server.server_state.tasks
                assert not publication._server.server_state.connections
                assert publication._listener.fileno() == -1
                assert not deployment._publications
                with pytest.raises(BaseException) as retried:
                    await publication.aclose()
                with pytest.raises(BaseException) as finished:
                    await publication.wait()
                assert retried.value is finished.value
                with pytest.raises(httpx.ConnectError):
                    await client.get(publication._target)
            finally:
                release.set()
                await asyncio.gather(closing, return_exceptions=True)
        await deployment.aclose()
        assert native.operations.count("unregister") == 1

    asyncio.run(scenario())


def test_lost_unregister_result_is_not_acknowledged_by_a_replacement_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        original = native.request
        calls = 0
        restored = False

        async def request(
            endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
        ) -> object:
            nonlocal calls
            if operation == "unregister":
                calls += 1
                if calls == 1:
                    raise NativeUnavailable()
                if not restored:
                    raise RegistrationLost()
            return await original(endpoint, operation, payload)

        monkeypatch.setattr(native, "request", request)
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        publication = await deployment.publish(tnl.handler(endpoint))
        with pytest.raises(NativeUnavailable):
            await publication.aclose()
        with pytest.raises(NativeUnavailable):
            await publication.aclose()
        assert publication._registration is not None and not publication._close_complete
        waiting = asyncio.create_task(publication.wait())
        await asyncio.sleep(0)
        assert not waiting.done()
        async with httpx.AsyncClient(trust_env=False) as client:
            assert (await client.get(publication._target)).text == "ASGI application"
        restored, native.retired_cleanup = True, True
        with pytest.raises(PublicationCleanupFailed) as closing:
            await publication.aclose()
        with pytest.raises(PublicationCleanupFailed) as finished:
            await waiting
        assert finished.value is closing.value
        assert publication._close_complete
        await deployment.aclose()

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


def test_retained_startup_cleanup_retires_asgi_after_permanent_authority_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = setup(monkeypatch)
        native.lose_reply, native.failed_cleanup = True, True
        deployment = tnl.create_client(project="acme/shop", token="private").deployment(
            "production"
        )
        with pytest.raises(ExceptionGroup):
            await deployment.publish(tnl.handler(endpoint))
        publication = next(iter(deployment._publications))
        session = next(iter(native.sessions.values()))
        assert len(session.payloads) == 2 and session.payloads[0] == session.payloads[1]
        assert not publication._serve_task.done()
        native.retired_cleanup = True
        with pytest.raises(ExceptionGroup) as failure:
            await deployment.aclose()
        assert len(failure.value.exceptions) == 1
        assert isinstance(failure.value.exceptions[0], PublicationCleanupFailed)
        assert publication._serve_task.done() and not deployment._publications
        await deployment.aclose()

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
