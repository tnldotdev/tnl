"""application proof exchange, exact HTTP resources, and ordinary-client ownership."""

from __future__ import annotations

import asyncio
import base64
import copy
import json
import time
from collections.abc import AsyncIterator, Callable, Mapping
from datetime import UTC, datetime
from typing import cast

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import tnl
from tnl import _application, _connections, _credential

URL = "url_" + "U" * 22
SERVICE = "svc_" + "S" * 22
PUBLISH = "url_" + "P" * 22
VISIT = "pgrant_" + "U" * 22


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def decoded(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def document() -> dict[str, object]:
    key = Ed25519PrivateKey.generate()
    return {
        "version": 1,
        "control_url": "https://control.example",
        "client_id": "pub_" + "A" * 22,
        "key_id": "pkey_" + "K" * 22,
        "team_id": "team",
        "private_key": encoded(key.private_bytes_raw() + key.public_key().public_bytes_raw()),
        "grants": [
            {"id": VISIT, "operation": "visit", "kind": "saved_public_url", "public_url_id": URL},
            {
                "id": "pgrant_" + "S" * 22,
                "operation": "visit",
                "kind": "service",
                "service_id": SERVICE,
            },
            {
                "id": "pgrant_" + "P" * 22,
                "operation": "publish",
                "kind": "saved_public_url",
                "public_url_id": PUBLISH,
            },
            {
                "id": "pgrant_" + "N" * 22,
                "operation": "allocate",
                "kind": "namespace",
                "domain_id": "dom_" + "N" * 22,
                "namespace": "member.example",
            },
        ],
    }


def grants(value: Mapping[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], value["grants"])


def create(settings: tnl.HTTPClientSettings) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=settings.url, transport=settings.transport)


class Authority:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, credential: dict[str, object]) -> None:
        self.document = copy.deepcopy(credential)
        self.now = time.time()
        self.duration = 60
        self.port = 20001
        self.trust = 1
        self.posts: list[tuple[str, dict[str, object]]] = []
        self.visits: list[httpx.Request] = []
        self.bodies: list[bytes] = []
        self.nonces: set[str] = set()
        self.permissions = 0
        self.stage = "/v1/visitor-tokens"
        self.status = 200
        self.access_change: Callable[[dict[str, object]], object] | None = None
        self.permission_change: Callable[[dict[str, object]], object] | None = None
        self.raw: bytes | None = None
        self.wait = False
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.closed = 0
        self.fail_close = False
        authority = self
        monkeypatch.setattr(_application.time, "time", lambda: self.now)

        class Transport(httpx.AsyncBaseTransport):
            def __init__(self, **options: object) -> None:
                assert options == {"trust_env": False, "retries": 0}
                self.control = False

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                if request.url.host != "control.example":
                    authority.visits.append(request)
                    authority.bodies.append(await request.aread())
                    assert "Cookie" not in request.headers
                    assert "pta_" not in request.headers["Tnl-Visitor-Token"]
                    return httpx.Response(200, stream=httpx.ByteStream(b"application response"))
                assert request.method == "POST" and "Cookie" not in request.headers
                self.control = True
                assert "Authorization" not in request.headers
                assert "Tnl-Visitor-Token" not in request.headers
                body = json.loads(await request.aread())
                assert isinstance(body, dict)
                authority.posts.append((request.url.path, body))
                if request.url.path == authority.stage and authority.status != 200:
                    return httpx.Response(
                        authority.status,
                        headers={"Location": "https://untrusted.example/"},
                        stream=httpx.ByteStream(b"private error"),
                    )
                if request.url.path == "/v1/publisher-token":
                    result = authority.access(body)
                    if authority.wait:
                        authority.started.set()
                        await authority.release.wait()
                    output = authority.access_change(result) if authority.access_change else result
                else:
                    assert request.url.path == "/v1/visitor-tokens"
                    assert body["source"] == {
                        "kind": "application",
                        "credential": "pta_" + "A" * 43,
                    }
                    output = authority.permission(body)
                    if authority.permission_change:
                        output = authority.permission_change(output)
                raw = (
                    authority.raw
                    if authority.raw is not None and request.url.path == authority.stage
                    else json.dumps(output).encode()
                )
                return httpx.Response(
                    200,
                    headers={"set-cookie": "personal=not-authority"},
                    stream=httpx.ByteStream(raw),
                )

            async def aclose(self) -> None:
                if self.control and authority.fail_close:
                    raise RuntimeError("private authority close failure: pta_" + "A" * 43)
                authority.closed += 1

        monkeypatch.setattr(httpx, "AsyncHTTPTransport", Transport)

        def unexpected_native() -> None:
            raise AssertionError("application HTTP must not start a native binary")

        monkeypatch.setattr(_connections, "native_binary", unexpected_native)

    def access(self, body: dict[str, object]) -> dict[str, object]:
        assert set(body) == {
            "grant_type",
            "client_id",
            "grant_id",
            "client_assertion_type",
            "client_assertion",
        }
        assert body["grant_type"] == "client_credentials"
        assert body["client_id"] == self.document["client_id"]
        assert (
            body["client_assertion_type"]
            == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        )
        proof = body["client_assertion"]
        assert isinstance(proof, str)
        header, claims, signature = proof.split(".")
        assert json.loads(decoded(header)) == {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": self.document["key_id"],
        }
        signed = json.loads(decoded(claims))
        assert signed["iss"] == signed["sub"] == self.document["client_id"]
        assert signed["aud"] == "https://control.example/v1/publisher-token"
        assert signed["grant_id"] == body["grant_id"]
        assert signed["iat"] == int(self.now) and signed["exp"] == int(self.now) + 60
        assert len(decoded(signed["jti"])) == 24 and signed["jti"] not in self.nonces
        self.nonces.add(signed["jti"])
        key = decoded(cast(str, self.document["private_key"]))
        Ed25519PrivateKey.from_private_bytes(key[:32]).public_key().verify(
            decoded(signature), (header + "." + claims).encode()
        )
        return {
            "access_token": "pta_" + "A" * 43,
            "token_type": "Bearer",
            "expires_in": self.duration,
            "grant_id": body["grant_id"],
        }

    def permission(self, body: dict[str, object]) -> dict[str, object]:
        resource = cast(dict[str, str], body["resource"])
        assert resource in [{"kind": "public_url", "id": URL}, {"kind": "service", "id": SERVICE}]
        self.permissions += 1
        service = resource["kind"] == "service"
        prefix = "vsg1.shg_" if service else "vsh1.shr_"
        result: dict[str, object] = {
            "resource": resource,
            "hostname": "api.example" if service else "preview.example",
            "port": self.port if service else 443,
            "visitor_token": prefix + "A" * 22 + "." + encoded(bytes([self.permissions]) * 32),
            "visitor_policy_revision": 1,
            "expires_at": datetime.fromtimestamp(self.now + 120, UTC).isoformat(),
        }
        if service:
            result.update(
                {
                    "service_protocol": "http",
                    "service_trust_revision": self.trust,
                    "service_endpoint": {
                        "hostname": "api.example",
                        "port": self.port,
                        "public": True,
                    },
                }
            )
        return result


@pytest.mark.parametrize("serialized", [False, True])
def test_json_and_parsed_credentials_sign_exact_grants_without_native_or_personal_access(
    monkeypatch: pytest.MonkeyPatch,
    serialized: bool,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)
    monkeypatch.setenv("TNL_WORKLOAD", "personal-fallback-is-not-allowed")
    monkeypatch.setenv("TNL_CREDENTIAL", "wrong ambient input")
    app = tnl.create_tnl(credential=json.dumps(value) if serialized else value)
    selected = app.connect(URL)
    assert not authority.posts
    with pytest.raises(tnl.TnlError) as unprepared:
        _ = selected.url
    assert unprepared.value.code == "sdk.connection_unprepared"
    value["control_url"] = "https://untrusted.example"
    grants(value)[0]["public_url_id"] = PUBLISH

    async def scenario() -> None:
        async with app:
            ready = await selected
            assert ready.url == "https://preview.example" and selected.url == ready.url
            get = app.client(URL, create=create, close=httpx.AsyncClient.aclose)
            ordinary = await get()
            assert await get() is ordinary and len(authority.posts) == 2
            response = await ordinary.post(
                "/body", content=b"private body", headers={"Authorization": "Bearer application"}
            )
            assert response.text == "application response"
            assert authority.bodies == [b"private body"]
            assert authority.visits[0].headers["Authorization"] == "Bearer application"
            assert "Tnl-Visitor-Token" not in response.request.headers
            service = await app.connect(SERVICE)
            assert service.url == "https://api.example:20001"
            assert [
                body["grant_id"] for path, body in authority.posts if path == "/v1/publisher-token"
            ] == [VISIT, "pgrant_" + "S" * 22]
            assert str(value["private_key"]) not in repr((app, selected, ready, ordinary))
        assert ordinary.is_closed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "resource", [PUBLISH, "https://preview.example", "inventory", "svc_" + "X" * 22]
)
def test_missing_or_nonvisit_grants_fail_without_exchange(
    monkeypatch: pytest.MonkeyPatch,
    resource: str,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            with pytest.raises(tnl.TnlError) as denied:
                await app.connect(resource)
            assert denied.value.code == "sdk.credential_denied" and not authority.posts

    asyncio.run(scenario())


def test_expiry_refresh_reuses_clients_but_binding_changes_and_denial_never_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)
    created: list[httpx.AsyncClient] = []

    def make(settings: tnl.HTTPClientSettings) -> httpx.AsyncClient:
        ordinary = create(settings)
        created.append(ordinary)
        return ordinary

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            get = app.client(SERVICE, create=make, close=httpx.AsyncClient.aclose)
            first = await get()
            await first.get("/")
            before = authority.visits[-1].headers["Tnl-Visitor-Token"]
            authority.now += 31
            assert await get() is first
            await first.get("/")
            assert authority.visits[-1].headers["Tnl-Visitor-Token"] != before
            assert len(created) == 1 and len(authority.posts) == 4
            authority.now += 31
            authority.port, authority.trust = 20002, 2
            with pytest.raises(tnl.TnlError) as changed:
                await first.post("/no-replay", content=b"once")
            assert changed.value.code == "sdk.credential_denied"
            assert b"once" not in authority.bodies
            second = await get()
            assert second is not first and not first.is_closed
            await second.post("/next", content=b"next")
            assert authority.visits[-1].url.port == 20002
            authority.now += 31
            authority.status = 403
            with pytest.raises(tnl.TnlError) as removed:
                await second.get("/")
            assert removed.value.code == "sdk.credential_denied"
            assert authority.bodies == [b"", b"", b"next"]
        assert all(ordinary.is_closed for ordinary in created)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault",
    [
        "resource",
        "hostname",
        "port",
        "trust",
        "endpoint",
        "policy",
        "extra",
        "expiry",
        "protocol",
        "private",
    ],
)
def test_permission_response_is_bound_and_bounded_before_any_target_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)

    def change(response: dict[str, object]) -> object:
        if fault == "resource":
            response["resource"] = {"kind": "service", "id": "svc_" + "X" * 22}
        if fault == "hostname":
            response["hostname"] = "127.0.0.1"
        if fault == "port":
            response["port"] = True
        if fault == "trust":
            response["service_trust_revision"] = None
        if fault == "endpoint":
            cast(dict[str, object], response["service_endpoint"])["port"] = 20002
        if fault == "policy":
            response["visitor_policy_revision"] = 0
        if fault == "extra":
            response["target_tls"] = "must not be visitor trust"
        if fault == "expiry":
            response["expires_at"] = "2000-01-01T00:00:00Z"
        if fault == "protocol":
            response["service_protocol"] = "postgres"
        if fault == "private":
            cast(dict[str, object], response["service_endpoint"])["public"] = False
        return response

    authority.permission_change = change

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            with pytest.raises(tnl.TnlError) as failure:
                await app.connect(SERVICE)
            expected = (
                "sdk.protocol_unsupported"
                if fault == "protocol"
                else "sdk.credential_denied"
                if fault in {"expiry", "private"}
                else "sdk.credential_response_invalid"
            )
            assert failure.value.code == expected and not authority.visits

    asyncio.run(scenario())


@pytest.mark.parametrize("status", [401, 403, 404, 409, 410, 429, 500, 307, 400])
def test_control_statuses_are_owned_and_redirects_never_select_another_authority(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)
    authority.status, authority.stage = status, "/v1/publisher-token"

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            with pytest.raises(tnl.TnlError) as failure:
                await app.connect(URL)
            expected = (
                "denied"
                if status in {401, 403, 404, 409, 410}
                else "unavailable"
                if status in {429, 500}
                else "response_invalid"
            )
            assert failure.value.code == "sdk.credential_" + expected
            assert "private" not in str(failure.value) and failure.value.__context__ is None
            assert len(authority.posts) == 1 and not authority.visits

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "body", [b"x" * 65537, b'{"resource":1,"resource":2}', b"private-invalid-json", b"\xff"]
)
def test_untrusted_control_bodies_are_bounded_and_never_become_private_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)
    authority.raw = body

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            with pytest.raises(tnl.TnlError) as failure:
                await app.connect(URL)
            assert failure.value.code == "sdk.credential_response_invalid"
            assert "private-invalid-json" not in str(failure.value)
            assert failure.value.__context__ is None

    asyncio.run(scenario())


def test_cancellation_isolated_from_shared_exchange_and_runtime_close_joins_pending_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)

    async def scenario() -> None:
        app = tnl.create_tnl(credential=value)
        authority.wait = True
        first = asyncio.ensure_future(app.connect(URL))
        await authority.started.wait()
        second = asyncio.ensure_future(app.connect(URL))
        first.cancel("one caller")
        with pytest.raises(asyncio.CancelledError):
            await first
        authority.release.set()
        assert (await second).url == "https://preview.example"
        assert len(authority.posts) == 2
        authority.now += 31
        authority.release.clear()
        authority.started.clear()
        get = app.client(URL, create=create, close=httpx.AsyncClient.aclose)
        pending = asyncio.create_task(get())
        await authority.started.wait()
        await app.aclose()
        with pytest.raises(tnl.TnlError) as closed:
            await pending
        assert closed.value.code == "sdk.client_closed" and not authority.visits

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault",
    [
        "version",
        "key",
        "pairing",
        "grant",
        "duplicate",
        "operation",
        "mixed",
        "extra",
        "empty",
        "expiry",
    ],
)
def test_invalid_application_documents_are_rejected_without_private_cause(fault: str) -> None:
    value = document()
    if fault == "version":
        value["version"] = True
    if fault == "key":
        value["private_key"] = "private-invalid-key"
    if fault == "pairing":
        value["private_key"] = encoded(b"X" * 64)
    if fault == "grant":
        grants(value)[0]["id"] = "pgrant_invalid"
    if fault == "duplicate":
        grants(value).append(copy.deepcopy(grants(value)[0]))
    if fault == "operation":
        grants(value)[0]["operation"] = "allocate"
    if fault == "mixed":
        grants(value)[0]["service_id"] = SERVICE
    if fault == "extra":
        value["personal_session"] = "secret"
    if fault == "empty":
        value["grants"] = []
    if fault == "expiry":
        grants(value)[0]["expires_at"] = None
    with pytest.raises(tnl.TnlError) as failure:
        tnl.create_tnl(credential=value)
    assert failure.value.code == "sdk.credential_invalid"
    assert failure.value.__context__ is None and "private-invalid-key" not in str(failure.value)


def test_expired_grants_and_duplicate_json_fields_cannot_gain_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)
    grants(value)[0]["expires_at"] = "2000-01-01T00:00:00Z"

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            with pytest.raises(tnl.TnlError) as expired:
                await app.connect(URL)
            assert expired.value.code == "sdk.credential_denied" and not authority.posts

    asyncio.run(scenario())
    raw = json.dumps(value).replace('"version": 1', '"version": 1, "version": 1')
    with pytest.raises(tnl.TnlError) as duplicate:
        _credential.application_document(raw)
    assert duplicate.value.code == "sdk.credential_invalid"


@pytest.mark.parametrize("fault", ["grant", "duration", "bearer", "extra"])
def test_access_exchange_cannot_replace_the_exact_grant_or_return_unbounded_authority(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)

    def change(response: dict[str, object]) -> object:
        if fault == "grant":
            response["grant_id"] = "pgrant_" + "P" * 22
        if fault == "duration":
            response["expires_in"] = 301
        if fault == "bearer":
            response["token_type"] = "personal"
        if fault == "extra":
            response["refresh_token"] = "must not create a personal session"
        return response

    authority.access_change = change

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            with pytest.raises(tnl.TnlError) as failure:
                await app.connect(URL)
            assert failure.value.code == "sdk.credential_response_invalid"
            assert len(authority.posts) == 1 and not authority.visits

    asyncio.run(scenario())


def test_parent_grant_expiry_fences_cached_permissions_without_replacing_an_ordinary_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)
    grants(value)[0]["expires_at"] = datetime.fromtimestamp(authority.now + 5, UTC).isoformat()

    async def scenario() -> None:
        async with tnl.create_tnl(credential=value) as app:
            get = app.client(URL, create=create, close=httpx.AsyncClient.aclose)
            ordinary = await get()
            authority.now += 6
            with pytest.raises(tnl.TnlError) as expired:
                await ordinary.get("/expired")
            assert expired.value.code == "sdk.credential_denied"
            assert not authority.visits and not ordinary.is_closed
            assert len(authority.posts) == 2
        assert ordinary.is_closed

    asyncio.run(scenario())


def test_denied_preflight_closes_an_unconsumed_upload_and_retains_failed_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)

    class Upload(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.consumed = False
            self.closed = False
            self.fail = True

        async def __aiter__(self) -> AsyncIterator[bytes]:
            self.consumed = True
            yield b"must not replay"

        async def aclose(self) -> None:
            if self.fail:
                raise RuntimeError("private upload cleanup failure")
            self.closed = True

    async def scenario() -> None:
        app = tnl.create_tnl(credential=value)
        get = app.client(URL, create=create, close=httpx.AsyncClient.aclose)
        ordinary = await get()
        authority.now += 31
        authority.status = 403
        upload = Upload()
        with pytest.raises(tnl.TnlError) as denied:
            await ordinary.send(
                httpx.Request(
                    "POST",
                    ordinary.base_url,
                    headers={"Host": ordinary.base_url.netloc.decode()},
                    stream=upload,
                )
            )
        assert denied.value.code == "sdk.credential_denied"
        assert not upload.consumed and not upload.closed
        with pytest.raises(ExceptionGroup):
            await app.aclose()
        assert ordinary.is_closed
        upload.fail = False
        await app.aclose()
        assert upload.closed and not authority.visits

    asyncio.run(scenario())


def test_authority_cleanup_failure_stays_private_and_retryable_without_stopping_a_sibling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)

    async def scenario() -> None:
        app, sibling = tnl.create_tnl(credential=value), tnl.create_tnl(credential=value)
        get = app.client(URL, create=create, close=httpx.AsyncClient.aclose)
        peer = sibling.client(URL, create=create, close=httpx.AsyncClient.aclose)
        first, second = await get(), await peer()
        authority.fail_close = True
        with pytest.raises(ExceptionGroup) as failure:
            await app.aclose()
        assert first.is_closed and not second.is_closed
        assert "private authority" not in str(failure.value)
        assert "pta_" not in repr(failure.value)
        await second.get("/sibling")
        authority.fail_close = False
        await app.aclose()
        await sibling.aclose()
        assert second.is_closed

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel", [False, True])
def test_request_failure_does_not_wait_for_upload_cleanup_but_runtime_close_joins_it(
    monkeypatch: pytest.MonkeyPatch,
    cancel: bool,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)

    class Upload(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.closed = False
            self.attempts = 0

        async def __aiter__(self) -> AsyncIterator[bytes]:
            raise AssertionError("preflight must not consume the upload")
            yield b"unreachable"

        async def aclose(self) -> None:
            self.attempts += 1
            self.started.set()
            await self.release.wait()
            self.closed = True

    async def scenario() -> None:
        app = tnl.create_tnl(credential=value)
        get = app.client(URL, create=create, close=httpx.AsyncClient.aclose)
        ordinary = await get()
        authority.now += 31
        authority.wait = cancel
        authority.status = 200 if cancel else 403
        upload = Upload()
        request = asyncio.create_task(
            ordinary.send(
                httpx.Request(
                    "POST",
                    ordinary.base_url,
                    headers={"Host": ordinary.base_url.netloc.decode()},
                    stream=upload,
                )
            )
        )
        closing: asyncio.Task[None] | None = None
        try:
            if cancel:
                await asyncio.wait_for(authority.started.wait(), 1)
                request.cancel("only this request")
                with pytest.raises(asyncio.CancelledError) as canceled:
                    await asyncio.wait_for(request, 1)
                assert canceled.value.args == ("only this request",)
            else:
                with pytest.raises(tnl.TnlError) as denied:
                    await asyncio.wait_for(request, 1)
                assert denied.value.code == "sdk.credential_denied"
            await asyncio.wait_for(upload.started.wait(), 1)
            assert not upload.closed and upload.attempts == 1
            closing = asyncio.create_task(app.aclose())
            await asyncio.sleep(0)
            assert not closing.done()
            upload.release.set()
            await asyncio.wait_for(asyncio.shield(closing), 1)
            assert upload.closed and upload.attempts == 1
            assert ordinary.is_closed and not authority.visits
        finally:
            upload.release.set()
            authority.release.set()
            await asyncio.gather(request, return_exceptions=True)
            if closing is not None:
                await asyncio.gather(closing, return_exceptions=True)
            await app.aclose()

    asyncio.run(scenario())
