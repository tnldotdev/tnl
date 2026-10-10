"""run ASGI lifespan and one ad-hoc publication on the shared native socket."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import socket
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from starlette.types import ASGIApp

from ._native import NativeRuntime
from ._protocol import (
    CredentialRequired,
    InvalidResponse,
    NativeUnavailable,
    RegistrationLost,
    Status,
    TnlError,
    parse_status,
)

_native = NativeRuntime()
_credential = re.compile(r"tnl_eph_[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")
_duration = re.compile(r"(?:(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:ns|us|µs|ms|s|m|h))+")
_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


@dataclass(frozen=True, slots=True)
class RateLimit:
    requests: int
    per: str


@dataclass(frozen=True, slots=True)
class Limits:
    requests: int | None = None
    rate: RateLimit | None = None
    concurrency: int | None = None


def _limit_payload(value: Limits | None) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, Limits):
        raise TnlError("sdk.configuration_invalid", "limits must be a Limits value")
    if (
        value.requests is not None
        and (type(value.requests) is not int or value.requests < 1)
        or value.concurrency is not None
        and (type(value.concurrency) is not int or value.concurrency < 1)
    ):
        raise TnlError("sdk.configuration_invalid", "request limits must be positive")
    result: dict[str, object] = {}
    if value.requests is not None:
        result["requests"] = value.requests
    if value.concurrency is not None:
        result["concurrency"] = value.concurrency
    if value.rate is not None:
        if (
            not isinstance(value.rate, RateLimit)
            or type(value.rate.requests) is not int
            or value.rate.requests < 1
            or not isinstance(value.rate.per, str)
            or _duration.fullmatch(value.rate.per) is None
            or not any(character in "123456789" for character in value.rate.per)
        ):
            raise TnlError("sdk.configuration_invalid", "rate requires positive requests and per")
        result["rate"] = {"requests": value.rate.requests, "per": value.rate.per}
    return result


class Tunnel:
    """one routable ad-hoc URL and its owned ASGI listener."""

    def __init__(
        self,
        native: NativeRuntime,
        server: uvicorn.Server,
        serve_task: asyncio.Task[None],
        listener: socket.socket,
        directory: str,
        credential: str,
        server_url: str | None,
        allow_ip: Sequence[str] | None,
        allow_all_ips: bool,
        limits: Limits | None,
    ) -> None:
        self._native = native
        self._server = server
        self._serve_task = serve_task
        self._listener = listener
        self._directory = directory
        self._socket = ""
        self._id = "ivk_" + "".join(secrets.choice(_alphabet) for _ in range(22))
        self._owner = secrets.token_hex(16)
        self._registration: dict[str, object] = {
            "version": 1,
            "registration_id": self._id,
            "owner": self._owner,
        }
        self._payload: dict[str, object] = {
            **self._registration,
            "pid": os.getpid(),
            "target": f"http://127.0.0.1:{listener.getsockname()[1]}",
            "credential": credential,
        }
        if server_url is not None:
            self._payload["server_url"] = server_url
        if allow_ip is not None:
            self._payload["allow_ip"] = list(allow_ip)
        if allow_all_ips:
            self._payload["allow_all_ips"] = True
        if limits is not None:
            self._payload["limits"] = _limit_payload(limits)
        self._registered = False
        self._closed = False
        self._close_lock = asyncio.Lock()
        self._monitor: asyncio.Task[None] | None = None
        self._url: str | None = None
        self._url_id: str | None = None
        loop = asyncio.get_running_loop()
        self._ready: asyncio.Future[None] = loop.create_future()
        self._finished: asyncio.Future[None] = loop.create_future()
        # a background failure can precede the first wait call.
        self._finished.add_done_callback(
            lambda future: future.exception() if not future.cancelled() else None
        )

    @property
    def url(self) -> str:
        if self._url is None or not self._ready.done() or self._ready.exception() is not None:
            raise InvalidResponse()
        return self._url

    async def start(self) -> None:
        self._socket = await self._native.start(self._directory)
        try:
            status = parse_status(
                await self._native.request(self._socket, "register", self._payload), self._id
            )
        except BaseException:
            # a lost acknowledgement may still have registered the invocation.
            try:
                await self._native.request(self._socket, "unregister", self._registration)
            except TnlError:
                pass
            raise
        self._registered = True
        self._monitor = asyncio.create_task(self._follow(status))
        await self._ready

    def _observe(self, status: Status) -> None:
        if status.public_url_id is not None:
            if self._url_id is not None and status.public_url_id != self._url_id:
                raise InvalidResponse()
            self._url_id = status.public_url_id
        if status.public_url is not None:
            if self._url is not None and status.public_url != self._url:
                raise InvalidResponse()
            self._url = status.public_url
        if status.state == "routable":
            if not self._ready.done():
                self._ready.set_result(None)
        elif status.state == "stopped":
            if not self._ready.done():
                self._ready.set_exception(
                    TnlError("sdk.publication_failed", "publisher stopped before ready")
                )
            if not self._finished.done():
                self._finished.set_result(None)
        elif status.state == "failed":
            code = (
                "sdk.credential_rejected"
                if status.failure_code == "runtime.credential_rejected"
                else "sdk.publication_failed"
            )
            error = TnlError(code, "the ad-hoc public URL could not be published")
            if not self._ready.done():
                self._ready.set_exception(error)
            if not self._finished.done():
                self._finished.set_exception(error)

    async def _follow(self, status: Status) -> None:
        last_renew = asyncio.get_running_loop().time()
        strict = self._payload.get("limits") is not None and (
            isinstance(self._payload["limits"], dict)
            and ("requests" in self._payload["limits"] or "rate" in self._payload["limits"])
        )
        while not self._closed and not self._finished.done():
            try:
                if self._serve_task.done():
                    if self._registered:
                        try:
                            await self._native.request(
                                self._socket, "unregister", self._registration
                            )
                        except TnlError:
                            # close retries cleanup if the native publisher is unavailable.
                            pass
                        else:
                            self._registered = False
                    self._fail(
                        TnlError("sdk.listener_failed", "ASGI listener stopped during publication")
                    )
                    return
                self._observe(status)
                if self._closed or self._finished.done():
                    return
                await asyncio.sleep(0.25)
                if asyncio.get_running_loop().time() - last_renew >= 5:
                    await self._native.request(self._socket, "renew", self._registration)
                    last_renew = asyncio.get_running_loop().time()
                status = parse_status(
                    await self._native.request(self._socket, "status", self._registration), self._id
                )
            except asyncio.CancelledError:
                return
            except (NativeUnavailable, RegistrationLost):
                if strict:
                    self._fail(RegistrationLost())
                    return
                try:
                    self._socket = await self._native.start(self._directory)
                    status = parse_status(
                        await self._native.request(self._socket, "register", self._payload),
                        self._id,
                    )
                except TnlError as restart_error:
                    self._fail(restart_error)
                    return
            except TnlError as cause:
                self._fail(cause)
                return

    def _fail(self, error: TnlError) -> None:
        if not self._ready.done():
            self._ready.set_exception(error)
        if not self._finished.done():
            self._finished.set_exception(error)

    async def wait(self) -> None:
        await self._finished

    async def close(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            if self._monitor is not None:
                self._monitor.cancel()
                try:
                    await self._monitor
                except asyncio.CancelledError:
                    pass
            cleanup: list[Exception] = []
            if self._registered:
                try:
                    await self._native.request(self._socket, "unregister", self._registration)
                except TnlError as cause:
                    if not isinstance(cause, RegistrationLost):
                        cleanup.append(cause)
            self._server.should_exit = True
            try:
                await asyncio.wait_for(self._serve_task, 15)
            except (Exception, asyncio.CancelledError) as cause:
                if isinstance(cause, Exception):
                    cleanup.append(cause)
                self._server.force_exit = True
                self._serve_task.cancel()
            finally:
                self._listener.close()
            if not self._finished.done():
                if cleanup:
                    self._finished.set_exception(cleanup[0])
                else:
                    self._finished.set_result(None)
            if not self._ready.done():
                self._ready.set_exception(RegistrationLost())
                self._ready.add_done_callback(
                    lambda future: future.exception() if not future.cancelled() else None
                )
            if len(cleanup) == 1:
                raise cleanup[0]
            if cleanup:
                raise ExceptionGroup("ad-hoc publisher and ASGI cleanup failed", cleanup)


async def _start_asgi(app: ASGIApp) -> tuple[uvicorn.Server, asyncio.Task[None], socket.socket]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        configuration = uvicorn.Config(
            app,
            lifespan="on",
            ws="websockets-sansio",
            log_level="critical",
            access_log=False,
            timeout_graceful_shutdown=10,
        )
        server = uvicorn.Server(configuration)
        task = asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:
            if task.done():
                await task
                raise TnlError("sdk.listener_failed", "ASGI lifespan did not start")
            await asyncio.sleep(0.01)
        return server, task, listener
    except BaseException:
        listener.close()
        raise


@asynccontextmanager
async def open(
    app: ASGIApp,
    *,
    credential: str | None = None,
    server: str | None = None,
    directory: str | Path | None = None,
    allow_ip: Sequence[str] | None = None,
    allow_all_ips: bool = False,
    limits: Limits | None = None,
) -> AsyncIterator[Tunnel]:
    """open an ASGI app after lifespan startup and close its URL on exit."""
    if not callable(app):
        raise TnlError("sdk.configuration_invalid", "an ASGI application is required")
    selected = credential if credential is not None else os.environ.get("TNL_CREDENTIAL")
    if selected is None or selected == "":
        raise CredentialRequired()
    if _credential.fullmatch(selected) is None:
        raise TnlError("sdk.credential_rejected", "invalid ad-hoc credential")
    if allow_all_ips and allow_ip is not None:
        raise TnlError("sdk.configuration_invalid", "choose allow_ip or allow_all_ips")
    _limit_payload(limits)
    root = str(Path(directory or os.getcwd()).resolve())
    asgi_server, task, listener = await _start_asgi(app)
    tunnel = Tunnel(
        _native,
        asgi_server,
        task,
        listener,
        root,
        selected,
        server,
        allow_ip,
        allow_all_ips,
        limits,
    )
    try:
        await tunnel.start()
    except BaseException as setup_error:
        try:
            await asyncio.shield(tunnel.close())
        except BaseException as cleanup_error:
            raise BaseExceptionGroup(
                "ASGI setup and cleanup failed", [setup_error, cleanup_error]
            ) from None
        raise
    try:
        yield tunnel
    except BaseException as body_error:
        try:
            await asyncio.shield(tunnel.close())
        except BaseException as cleanup_error:
            raise BaseExceptionGroup(
                "ASGI operation and cleanup failed", [body_error, cleanup_error]
            ) from None
        raise
    else:
        await asyncio.shield(tunnel.close())
