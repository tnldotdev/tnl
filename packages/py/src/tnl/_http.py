"""explicit HTTP credentials, bound settings, and joined transport ownership."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable, Generator, Hashable
from dataclasses import dataclass
from typing import Protocol

import httpx

from ._application import ApplicationHTTP
from ._credential import ApplicationDocument, application_document, https_origin, visitor_token
from ._protocol import TnlError


class HTTPClientSettings(Protocol):
    """pass url and transport to an ordinary httpx.AsyncClient."""

    @property
    def url(self) -> str: ...

    @property
    def transport(self) -> httpx.AsyncBaseTransport: ...

    def __await__(self) -> Generator[object, None, HTTPClientSettings]: ...


@dataclass(frozen=True, slots=True, repr=False)
class _ReadySettings:
    url: str
    transport: httpx.AsyncBaseTransport
    _check: Callable[[], None]

    def __repr__(self) -> str:
        return "<tnl HTTP client settings (private)>"

    def __await__(self) -> Generator[object, None, HTTPClientSettings]:
        async def ready() -> HTTPClientSettings:
            self._check()
            return self

        return ready().__await__()


class _ApplicationSettings:
    def __init__(self, owner: _HTTPResources, resource: str) -> None:
        self._owner, self._resource = owner, resource
        self._current: HTTPClientSettings | None = None

    def __repr__(self) -> str:
        return "<tnl HTTP connection handle (private)>"

    def _settings(self) -> HTTPClientSettings:
        self._owner._check()
        if self._current is None:
            raise TnlError(
                "sdk.connection_unprepared", "await this exact application resource first"
            )
        return self._current

    @property
    def url(self) -> str:
        return self._settings().url

    @property
    def transport(self) -> httpx.AsyncBaseTransport:
        return self._settings().transport

    def __await__(self) -> Generator[object, None, HTTPClientSettings]:
        async def prepare() -> HTTPClientSettings:
            _, self._current = await self._owner.acquire(self._resource)
            return self._current

        return prepare().__await__()


def _unavailable() -> TnlError:
    return TnlError("sdk.http_unavailable", "the HTTP request or response failed")


class _Response(httpx.Response):
    @property
    def has_redirect_location(self) -> bool:
        # retain status and Location, but never replay an upload through the
        # ordinary client's automatic redirect loop, even on the same origin.
        return False


class _OwnedStream(httpx.AsyncByteStream):
    def __init__(self, owner: _HTTPTransport, stream: httpx.AsyncByteStream) -> None:
        self._owner, self._stream = owner, stream
        self._closing: asyncio.Task[None] | None = None

    async def __aiter__(self) -> AsyncIterator[bytes]:
        iterator = self._stream.__aiter__()
        while True:
            self._owner._check()
            pending = asyncio.ensure_future(anext(iterator))
            self._owner._reading.add(pending)
            try:
                chunk = await pending
            except StopAsyncIteration:
                return
            except Exception:
                break
            finally:
                self._owner._reading.discard(pending)
            self._owner._check()
            yield chunk
        raise _unavailable() from None

    async def aclose(self) -> None:
        await asyncio.shield(self.start_close())

    def start_close(self) -> asyncio.Task[None]:
        if self._closing is None:
            self._closing = asyncio.create_task(self._close())

            def finished(task: asyncio.Task[None]) -> None:
                if task.cancelled() or task.exception() is not None:
                    if self._closing is task:
                        self._closing = None

            self._closing.add_done_callback(finished)
        return self._closing

    async def _close(self) -> None:
        try:
            await self._stream.aclose()
        except Exception:
            pass
        else:
            self._owner._streams.discard(self)
            return
        raise _unavailable() from None


class _HTTPTransport(httpx.AsyncBaseTransport):
    def __init__(
        self, origin: httpx.URL, authorize: Callable[[], Awaitable[str]], check: Callable[[], None]
    ) -> None:
        self._origin, self._authorize, self._check = origin, authorize, check
        self._transport: httpx.AsyncHTTPTransport | None = None
        self._pending: set[asyncio.Task[httpx.Response]] = set()
        self._reading: set[asyncio.Future[bytes]] = set()
        self._streams: set[_OwnedStream] = set()

    def __repr__(self) -> str:
        return "<tnl HTTP transport (private)>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._check()
        try:
            return await self._handle(request)
        except BaseException:
            if isinstance(request.stream, httpx.AsyncByteStream):
                stream = _OwnedStream(self, request.stream)
                self._streams.add(stream)
                # request failure and cancellation do not wait on a caller's
                # stream close. the runtime retains and joins that exact cleanup.
                stream.start_close()
            raise

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if (
            (url.scheme, url.host, url.port)
            != (self._origin.scheme, self._origin.host, self._origin.port)
            or url.userinfo
            or any(
                name in request.headers
                for name in ("Tnl-Visitor-Token", "Tnl-Access-Token", "Tnl-Share-Token")
            )
            or request.headers.get("host", "") != self._origin.netloc.decode()
        ):
            raise TnlError("sdk.configuration_invalid", "the request must use its selected origin")
        pending = asyncio.create_task(self._dispatch(request))
        self._pending.add(pending)
        try:
            return await pending
        finally:
            self._pending.discard(pending)

    async def _dispatch(self, request: httpx.Request) -> httpx.Response:
        credential = await self._authorize()
        self._check()
        headers = request.headers.copy()
        # browser access cookies cannot substitute ambient sign-in for this token.
        headers.pop("cookie", None)
        headers["Tnl-Visitor-Token"] = credential
        private = httpx.Request(
            request.method,
            request.url,
            headers=headers,
            stream=request.stream,
            extensions={
                key: value for key, value in request.extensions.items() if key == "timeout"
            },
        )
        if self._transport is None:
            self._transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0)
        try:
            response = await self._transport.handle_async_request(private)
        except asyncio.CancelledError:
            raise
        except Exception:
            response = None
        if response is None:
            raise _unavailable() from None
        assert isinstance(response.stream, httpx.AsyncByteStream)
        stream = _OwnedStream(self, response.stream)
        self._streams.add(stream)
        try:
            self._check()
        except TnlError:
            await stream.aclose()
            raise
        # never return a request with the injected credential in diagnostics.
        return _Response(
            response.status_code,
            headers=response.headers,
            stream=stream,
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        # ordinary clients own themselves, not a sibling's shared runtime pool.
        # the runtime joins clients before closing this source via close().
        pass

    async def close(self) -> None:
        for pending in tuple(self._pending):
            pending.cancel()
        for reading in tuple(self._reading):
            reading.cancel()
        await asyncio.gather(*tuple(self._pending), return_exceptions=True)
        await asyncio.gather(*tuple(self._reading), return_exceptions=True)
        results = await asyncio.gather(
            *(stream.aclose() for stream in tuple(self._streams)), return_exceptions=True
        )
        if any(isinstance(result, BaseException) for result in results):
            raise _unavailable()
        if self._transport is not None:
            try:
                await self._transport.aclose()
            except Exception:
                pass
            else:
                self._transport = None
                return
            raise _unavailable() from None


class _HTTPResources:
    def __init__(
        self, credential: object, check: Callable[[], None], context: Callable[[], None]
    ) -> None:
        self._application: ApplicationHTTP | None = None
        if isinstance(credential, str) and not credential.lstrip().startswith("{"):
            self._credential: str | None = visitor_token(credential)
        else:
            self._credential = None
            document = (
                credential
                if isinstance(credential, ApplicationDocument)
                else application_document(credential)
            )
            self._application = ApplicationHTTP(document, context)
        self._check = check
        self._context = context
        self._connections: dict[Hashable, HTTPClientSettings] = {}
        self._transports: set[_HTTPTransport] = set()

    def connect(self, resource: str) -> HTTPClientSettings:
        self._check()
        if self._application is not None:
            self._application.resource(resource)
            return _ApplicationSettings(self, resource)
        https_origin(resource)

        async def authorize() -> str:
            assert self._credential is not None
            return self._credential

        return self._connection(resource, resource, authorize)

    def _connection(
        self, url: str, key: Hashable, authorize: Callable[[], Awaitable[str]]
    ) -> HTTPClientSettings:
        if key not in self._connections:
            if len(self._connections) >= 64:
                raise TnlError("sdk.client_capacity", "the runtime has too many HTTP bindings")
            transport = _HTTPTransport(https_origin(url), authorize, self._context)
            self._transports.add(transport)
            self._connections[key] = _ReadySettings(url, transport, self._context)
        return self._connections[key]

    async def acquire(self, resource: str) -> tuple[Hashable, HTTPClientSettings]:
        self._context()
        if self._application is None:
            return resource, self.connect(resource)
        application = self._application
        selected = await application.resolve(resource)
        self._check()

        async def authorize() -> str:
            current = await application.resolve(resource)
            if current.key != selected.key:
                raise TnlError("sdk.credential_denied", "the application resource binding changed")
            return current.credential

        return selected.key, self._connection(selected.url, selected.key, authorize)

    def fence(self) -> None:
        if self._application is not None:
            self._application.fence()

    async def close(self) -> None:
        async def close(transport: _HTTPTransport) -> None:
            await transport.close()
            self._transports.discard(transport)

        work = [close(transport) for transport in tuple(self._transports)]
        if self._application is not None:
            work.append(self._application.close())
        results = await asyncio.gather(*work, return_exceptions=True)
        failures = [result for result in results if isinstance(result, BaseException)]
        if failures:
            raise BaseExceptionGroup("HTTP cleanup failed", failures)
        self._connections.clear()
