"""explicit visitor-token HTTP settings; no native or personal authentication."""

from __future__ import annotations

import asyncio
import base64
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass

import httpx

from ._protocol import TnlError


def visitor_token(value: object) -> str:
    if isinstance(value, str) and 0 < len(value) <= 2048:
        parts = value.split(".")
        if len(parts) == 3 and all(re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in parts):
            kind, identifier, secret = parts
            if kind in {"vsh1", "vsg1"}:
                prefix = "shr_" if kind == "vsh1" else "shg_"
                if re.fullmatch(prefix + r"[A-Za-z0-9]{22}", identifier) and len(secret) == 43:
                    decoded = base64.urlsafe_b64decode(secret + "=")
                    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") == secret:
                        return value
            elif kind.startswith("ey"):
                # signed permissions remain opaque; the publisher verifies them.
                return value
    raise TnlError("sdk.configuration_invalid", "supply a valid explicit visitor credential")


def https_origin(value: str) -> httpx.URL:
    try:
        url = httpx.URL(value)
        if (
            url.scheme == "https"
            and url.host
            and not url.userinfo
            and not url.query
            and not url.fragment
            and url.raw_path == b"/"
            and str(url) == value == "https://" + url.netloc.decode()
            and len(value) <= 4096
            and "\\" not in value
            and not any(character.isspace() or ord(character) < 32 for character in value)
            and (url.port is None or 1 <= url.port <= 65535)
        ):
            return url
    except (httpx.InvalidURL, ValueError, TypeError):
        pass
    raise TnlError("sdk.configuration_invalid", "select one canonical HTTPS origin without a path")


@dataclass(frozen=True, slots=True, repr=False)
class HTTPClientSettings:
    """pass url and transport to an ordinary httpx.AsyncClient."""

    url: str
    transport: httpx.AsyncBaseTransport

    def __repr__(self) -> str:
        return "<tnl HTTP client settings (private)>"


def _unavailable() -> TnlError:
    return TnlError("sdk.http_unavailable", "the HTTP request or response failed")


class _Response(httpx.Response):
    @property
    def has_redirect_location(self) -> bool:
        # retain status and Location, but never replay an upload through the
        # ordinary client's automatic redirect loop, even on the same origin.
        return False


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, owner: _TokenTransport, stream: httpx.AsyncByteStream) -> None:
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
        if self._closing is None:
            self._closing = asyncio.create_task(self._close())

            def finished(task: asyncio.Task[None]) -> None:
                if task.cancelled() or task.exception() is not None:
                    if self._closing is task:
                        self._closing = None

            self._closing.add_done_callback(finished)
        await asyncio.shield(self._closing)

    async def _close(self) -> None:
        try:
            await self._stream.aclose()
        except Exception:
            pass
        else:
            self._owner._streams.discard(self)
            return
        raise _unavailable() from None


class _TokenTransport(httpx.AsyncBaseTransport):
    def __init__(self, origin: httpx.URL, credential: str, check: Callable[[], None]) -> None:
        self._origin, self._credential, self._check = origin, credential, check
        self._transport: httpx.AsyncHTTPTransport | None = None
        self._pending: set[asyncio.Task[httpx.Response]] = set()
        self._reading: set[asyncio.Future[bytes]] = set()
        self._streams: set[_ResponseStream] = set()

    def __repr__(self) -> str:
        return "<tnl HTTP transport (private)>"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._check()
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
        headers = request.headers.copy()
        # browser access cookies cannot substitute ambient sign-in for this token.
        headers.pop("cookie", None)
        headers["Tnl-Visitor-Token"] = self._credential
        private = httpx.Request(
            request.method,
            url,
            headers=headers,
            stream=request.stream,
            extensions={
                key: value for key, value in request.extensions.items() if key == "timeout"
            },
        )
        if self._transport is None:
            self._transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0)
        pending = asyncio.create_task(self._dispatch(private, request))
        self._pending.add(pending)
        try:
            return await pending
        finally:
            self._pending.discard(pending)

    async def _dispatch(self, private: httpx.Request, request: httpx.Request) -> httpx.Response:
        assert self._transport is not None
        try:
            response = await self._transport.handle_async_request(private)
        except asyncio.CancelledError:
            raise
        except Exception:
            response = None
        if response is None:
            raise _unavailable() from None
        assert isinstance(response.stream, httpx.AsyncByteStream)
        stream = _ResponseStream(self, response.stream)
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
        self, credential: str, check: Callable[[], None], context: Callable[[], None]
    ) -> None:
        self._credential, self._check = visitor_token(credential), check
        self._context = context
        self._connections: dict[str, HTTPClientSettings] = {}
        self._transports: set[_TokenTransport] = set()

    def connect(self, origin: str) -> HTTPClientSettings:
        self._check()
        url = https_origin(origin)
        if origin not in self._connections:
            if len(self._connections) >= 64:
                raise TnlError("sdk.client_capacity", "the runtime has too many HTTP origins")
            transport = _TokenTransport(url, self._credential, self._context)
            self._transports.add(transport)
            self._connections[origin] = HTTPClientSettings(origin, transport)
        return self._connections[origin]

    async def close(self) -> None:
        async def close(transport: _TokenTransport) -> None:
            await transport.close()
            self._transports.discard(transport)

        results = await asyncio.gather(
            *(close(transport) for transport in tuple(self._transports)), return_exceptions=True
        )
        failures = [result for result in results if isinstance(result, BaseException)]
        if failures:
            raise BaseExceptionGroup("HTTP cleanup failed", failures)
        self._connections.clear()
