"""explicit HTTP tokens, ordinary clients, and joined runtime transport ownership."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
from typing import cast

import httpx
import pytest

import tnl
from tnl import _connections, _http

TOKEN = "vsh1.shr_" + "A" * 22 + "." + base64.urlsafe_b64encode(b"s" * 32).decode().rstrip("=")


class Stream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.closed = False
        self.block = False
        self.fail_close = False
        self.fail_read = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.started.set()
        if self.block:
            await self.release.wait()
        if self.fail_read:
            raise httpx.ReadError(TOKEN)
        yield b"response"

    async def aclose(self) -> None:
        if self.fail_close:
            raise RuntimeError(TOKEN)
        self.closed = True


class Network:
    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.options: list[dict[str, object]] = []
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []
        self.streams: list[Stream] = []
        self.status = 200
        self.location = "https://other.example/"
        self.fail = False
        self.fail_close = False
        self.closed = 0
        self.block = False
        self.ignore_cancellation = False
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        network = self

        class Transport(httpx.AsyncBaseTransport):
            def __init__(self, **options: object) -> None:
                network.options.append(options)

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                network.requests.append(request)
                network.bodies.append(await request.aread())
                network.started.set()
                if network.block:
                    try:
                        await network.release.wait()
                    except asyncio.CancelledError:
                        if not network.ignore_cancellation:
                            raise
                if network.fail:
                    raise httpx.ConnectError(TOKEN, request=request)
                stream = Stream()
                network.streams.append(stream)
                return httpx.Response(
                    network.status,
                    headers={"Location": network.location, "set-cookie": "session=ambient"},
                    stream=stream,
                    request=request,
                )

            async def aclose(self) -> None:
                if network.fail_close:
                    raise RuntimeError(TOKEN)
                network.closed += 1

        monkeypatch.setattr(_http.httpx, "AsyncHTTPTransport", Transport)

        def unexpected_native() -> None:
            raise AssertionError("token HTTP must not resolve or start a native binary")

        monkeypatch.setattr(_connections, "native_binary", unexpected_native)


def client(settings: tnl.HTTPClientSettings) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=settings.url, transport=settings.transport)


def test_settings_are_synchronous_and_never_select_native_or_ambient_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Network(monkeypatch)
    monkeypatch.setenv("TNL_CREDENTIAL", "invalid ambient credential")
    monkeypatch.setenv("TNL_SERVER", "http://invalid.example")
    monkeypatch.setenv("TNL_STATE_DIR", "/missing")
    monkeypatch.setenv("TNL_WORKLOAD", "another-identity")
    app = tnl.create_tnl(credential=TOKEN)
    settings = app.connect("https://preview.example")
    assert app.connect(settings.url) is settings
    assert TOKEN not in repr((app, settings, settings.transport))
    assert not network.options and not network.requests

    async def scenario() -> None:
        get = app.client(settings.url, create=client, close=httpx.AsyncClient.aclose)
        ordinary = await get()
        assert await get() is ordinary
        response = await ordinary.post("/path", content=b"body")
        assert response.text == "response"
        assert "Tnl-Visitor-Token" not in response.request.headers
        assert network.requests[0].headers["Tnl-Visitor-Token"] == TOKEN
        assert network.bodies == [b"body"]
        assert network.options == [{"trust_env": False, "retries": 0}]
        await app.aclose()
        assert ordinary.is_closed and network.closed == 1
        with pytest.raises(tnl.TnlError) as closed:
            await get()
        assert closed.value.code == "sdk.client_closed"
        with pytest.raises(tnl.TnlError) as connection:
            app.connect(settings.url)
        assert connection.value.code == "sdk.client_closed"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "origin",
    [
        "api",
        "http://preview.example",
        "https://preview.example/",
        "https://preview.example/path",
        "https://user:secret@preview.example",
        "https://preview.example?",
        "https://preview.example#",
        "https://preview.example:99999",
        "https://PREVIEW.example",
        "https://preview.example:443",
        "https://preview.example\n",
        "https://preview.example\\other",
    ],
)
def test_noncanonical_origins_fail_before_dispatch(origin: str) -> None:
    app = tnl.create_tnl(credential=TOKEN)
    with pytest.raises(tnl.TnlError) as failure:
        app.connect(origin)
    assert failure.value.code == "sdk.configuration_invalid"
    assert origin not in str(failure.value)


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        " ",
        "secret",
        "vsh1.shr_" + "A" * 22 + "." + "x" * 43,
        {"workload": "job"},
        '{"private_key":"secret"}',
    ],
)
def test_invalid_explicit_credentials_never_fall_back(token: object) -> None:
    with pytest.raises(tnl.TnlError) as failure:
        tnl.create_tnl(credential=cast(str, token))
    assert failure.value.code == "sdk.configuration_invalid"
    assert "secret" not in str(failure.value) and failure.value.__context__ is None


@pytest.mark.parametrize("kind", ["vsh1", "vsg1", "signed"])
def test_visitor_credentials_are_opaque_and_do_not_get_a_client_side_expiry(kind: str) -> None:
    token = TOKEN if kind == "vsh1" else TOKEN.replace("vsh1.shr_", "vsg1.shg_")
    if kind == "signed":
        token = "eyopaque.payload.signature"
    assert _http.visitor_token(token) == token


@pytest.mark.parametrize(
    "header", ["Tnl-Visitor-Token", "Tnl-Access-Token", "Tnl-Share-Token", "Host"]
)
def test_caller_cannot_override_visitor_authority_or_target(
    monkeypatch: pytest.MonkeyPatch,
    header: str,
) -> None:
    network = Network(monkeypatch)

    async def scenario() -> None:
        async with tnl.create_tnl(credential=TOKEN) as app:
            settings = app.connect("https://preview.example")
            async with client(settings) as ordinary:
                with pytest.raises(tnl.TnlError) as failure:
                    await ordinary.get("/", headers={header: "secret"})
                assert failure.value.code == "sdk.configuration_invalid"
                assert not network.requests

    asyncio.run(scenario())


@pytest.mark.parametrize("location", ["https://other.example/", "/same-origin"])
def test_redirects_are_returned_without_replay_and_cookies_and_tls_overrides_are_not_forwarded(
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    network = Network(monkeypatch)
    network.status, network.location = 307, location

    async def scenario() -> None:
        async with tnl.create_tnl(credential=TOKEN) as app:
            settings = app.connect("https://preview.example")
            async with client(settings) as ordinary:
                response = await ordinary.post(
                    "/",
                    content=b"do not replay",
                    follow_redirects=True,
                    headers={"Cookie": "browser_access=personal", "Authorization": "Bearer app"},
                    extensions={"sni_hostname": "other.example", "trace": "private"},
                )
                assert response.status_code == 307 and response.headers["Location"] == location
                assert response.history == [] and response.next_request is None
                await ordinary.post("/second", content=b"next")
                for request in network.requests:
                    assert "Cookie" not in request.headers
                    assert (
                        "sni_hostname" not in request.extensions
                        and "trace" not in request.extensions
                    )
                assert network.requests[0].headers["Authorization"] == "Bearer app"
                assert network.bodies == [b"do not replay", b"next"]
                with pytest.raises(tnl.TnlError) as failure:
                    await ordinary.get("https://other.example/leak")
                assert failure.value.code == "sdk.configuration_invalid"
                assert len(network.requests) == 2

    asyncio.run(scenario())


def test_factories_and_instances_close_independently_and_failed_cleanup_is_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Network(monkeypatch)

    async def scenario() -> None:
        first, sibling = tnl.create_tnl(credential=TOKEN), tnl.create_tnl(credential=TOKEN)
        fail = True
        attempts: list[httpx.AsyncClient] = []

        async def close(ordinary: httpx.AsyncClient) -> None:
            attempts.append(ordinary)
            if fail:
                raise RuntimeError("application close failed")
            await ordinary.aclose()

        get = first.client("https://preview.example", create=client, close=close)
        peer = first.client(
            "https://preview.example", create=client, close=httpx.AsyncClient.aclose
        )
        other = sibling.client(
            "https://preview.example", create=client, close=httpx.AsyncClient.aclose
        )
        a, b, c = await get(), await peer(), await other()
        assert a is not b and c is not a
        await a.get("/")
        await b.get("/")
        await c.get("/")
        await peer.aclose()
        assert not network.closed
        await a.get("/still-active")
        with pytest.raises(ExceptionGroup):
            await first.aclose()
        assert attempts == [a] and not a.is_closed and network.closed == 0
        await c.get("/unrelated")
        fail = False
        await first.aclose()
        assert attempts == [a, a] and a.is_closed and network.closed == 1
        await c.get("/unrelated")
        await sibling.aclose()
        assert network.closed == 2

    asyncio.run(scenario())


def test_runtime_close_cancels_and_joins_dispatch_and_stream_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Network(monkeypatch)

    async def scenario() -> None:
        app = tnl.create_tnl(credential=TOKEN)
        ordinary = client(app.connect("https://preview.example"))
        response = await ordinary.send(ordinary.build_request("GET", "/"), stream=True)
        network.streams[0].block = True
        read = asyncio.create_task(response.aread())
        await network.streams[0].started.wait()
        network.block = True
        network.started.clear()
        dispatch = asyncio.create_task(ordinary.get("/pending"))
        await network.started.wait()
        await app.aclose()
        results = await asyncio.gather(read, dispatch, return_exceptions=True)
        assert all(isinstance(result, asyncio.CancelledError) for result in results)
        assert network.streams[0].closed and network.closed == 1
        with pytest.raises(tnl.TnlError) as closed:
            await ordinary.get("/closed")
        assert closed.value.code == "sdk.client_closed"
        await ordinary.aclose()

    asyncio.run(scenario())


def test_network_and_cleanup_errors_never_expose_the_injected_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Network(monkeypatch)

    async def scenario() -> None:
        app = tnl.create_tnl(credential=TOKEN)
        ordinary = client(app.connect("https://preview.example"))
        network.fail = True
        with pytest.raises(tnl.TnlError) as failed:
            await ordinary.get("/")
        assert failed.value.code == "sdk.http_unavailable"
        assert failed.value.__context__ is None and TOKEN not in repr(failed.value)
        network.fail = False
        response = await ordinary.send(ordinary.build_request("GET", "/"), stream=True)
        network.streams[0].fail_close = True
        with pytest.raises(ExceptionGroup) as cleanup:
            await app.aclose()
        assert TOKEN not in repr(cleanup.value)
        for failure in cleanup.value.exceptions:
            assert isinstance(failure, tnl.TnlError) and failure.__context__ is None
        assert network.closed == 0
        network.streams[0].fail_close = False
        network.fail_close = True
        with pytest.raises(ExceptionGroup):
            await app.aclose()
        assert network.streams[0].closed
        network.fail_close = False
        await app.aclose()
        assert network.closed == 1
        await response.aclose()
        await ordinary.aclose()

    asyncio.run(scenario())


def test_workload_credential_supports_native_name_only_acquisition() -> None:
    assert tnl.Workload("deploy").configuration() == ("deploy", None, None)
    app = tnl.create_tnl(credential=tnl.Workload("deploy"))
    assert app._scope.configuration == ("deploy", None, None)
    assert app._scope.uses_workload()
    asyncio.run(app.aclose())
    with pytest.raises(tnl.TnlError):
        tnl.Workload("deploy", token=lambda: "proof", token_file="/run/proof")
    with pytest.raises(TypeError):
        tnl.create_tnl(**cast(dict[str, str], {"workload": "removed"}))
    assert not hasattr(tnl, "configure_workload")


def test_allocated_ports_remain_exact_and_origin_capacity_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Network(monkeypatch)

    async def scenario() -> None:
        async with tnl.create_tnl(credential=TOKEN) as app:
            settings = app.connect("https://api.example:20001")
            assert settings.url == "https://api.example:20001"
            async with client(settings) as ordinary:
                assert (await ordinary.get("/stock")).status_code == 200
                with pytest.raises(tnl.TnlError) as failure:
                    await ordinary.get("https://api.example/stock")
                assert failure.value.code == "sdk.configuration_invalid"
                assert len(network.requests) == 1
            for index in range(63):
                app.connect(f"https://preview{index}.example")
            with pytest.raises(tnl.TnlError) as capacity:
                app.connect("https://overflow.example")
            assert capacity.value.code == "sdk.client_capacity"

    asyncio.run(scenario())


def test_canceled_factory_getter_and_close_still_join_late_client_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Network(monkeypatch)

    async def scenario() -> None:
        app = tnl.create_tnl(credential=TOKEN)
        entered, release = asyncio.Event(), asyncio.Event()
        created: list[httpx.AsyncClient] = []

        async def create(settings: tnl.HTTPClientSettings) -> httpx.AsyncClient:
            entered.set()
            await release.wait()
            result = client(settings)
            created.append(result)
            return result

        get = app.client("https://preview.example", create=create, close=httpx.AsyncClient.aclose)
        pending = asyncio.create_task(get())
        await entered.wait()
        pending.cancel("only this waiter")
        with pytest.raises(asyncio.CancelledError):
            await pending
        closing = asyncio.create_task(app.aclose())
        await asyncio.sleep(0)
        assert not closing.done()
        closing.cancel("only this close waiter")
        release.set()
        # runtime close joins its shielded cleanup even when its waiter cancels.
        await asyncio.gather(closing, return_exceptions=True)
        await app.aclose()
        assert len(created) == 1 and created[0].is_closed and not network.requests

    asyncio.run(scenario())


def test_late_response_during_shutdown_is_retained_until_its_cleanup_joins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Network(monkeypatch)
    network.block, network.ignore_cancellation = True, True

    async def scenario() -> None:
        app = tnl.create_tnl(credential=TOKEN)
        ordinary = client(app.connect("https://preview.example"))
        pending = asyncio.create_task(ordinary.get("/late"))
        await network.started.wait()
        await app.aclose()
        with pytest.raises(tnl.TnlError) as closed:
            await pending
        assert closed.value.code == "sdk.client_closed"
        assert len(network.streams) == 1 and network.streams[0].closed
        assert network.closed == 1
        await ordinary.aclose()

    asyncio.run(scenario())


def test_stream_read_failure_is_sanitized_and_runtime_context_checks_precede_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network = Network(monkeypatch)

    async def scenario() -> None:
        async with tnl.create_tnl(credential=TOKEN) as app:
            async with client(app.connect("https://preview.example")) as ordinary:
                response = await ordinary.send(ordinary.build_request("GET", "/"), stream=True)
                network.streams[0].fail_read = True
                with pytest.raises(tnl.TnlError) as read:
                    await response.aread()
                assert read.value.code == "sdk.http_unavailable"
                assert read.value.__context__ is None and TOKEN not in str(read.value)
                await response.aclose()

                async def another_loop() -> None:
                    with pytest.raises(tnl.TnlError) as context:
                        await ordinary.get("/")
                    assert context.value.code == "sdk.client_context_invalid"

                await asyncio.to_thread(lambda: asyncio.run(another_loop()))
                with monkeypatch.context() as child:
                    child.setattr(app, "_pid", -1)
                    with pytest.raises(tnl.TnlError) as forked:
                        await ordinary.get("/")
                    assert forked.value.code == "sdk.client_closed"
                    await app.aclose()
                    assert network.closed == 0
                assert len(network.requests) == 1

    asyncio.run(scenario())
