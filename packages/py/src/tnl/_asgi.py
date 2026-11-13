"""temporary ASGI listeners with invocation-scoped native publication."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import socket
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import uvicorn
from starlette.types import ASGIApp

from ._native import NativeRuntime
from ._protocol import (
    Endpoint,
    InvalidResponse,
    NativeUnavailable,
    RegistrationLost,
    Status,
    TnlError,
    parse_assignment,
    parse_registration,
    parse_status,
    service_name,
)

_native = NativeRuntime()
_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_duration = re.compile(r"(?:(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:ns|us|µs|ms|s|m|h))+")


async def _join_cleanup[T](task: asyncio.Task[T]) -> T:
    """defer caller cancellation until the owned cleanup task has finished."""
    canceled: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cause:
            canceled = cause
        except BaseException:
            break
    try:
        result = task.result()
    except BaseException as cause:
        if canceled is not None and not isinstance(cause, asyncio.CancelledError):
            raise BaseExceptionGroup("cleanup and cancellation failed", [canceled, cause]) from None
        raise
    if canceled is not None:
        raise canceled
    return result


class _OwnedServer(uvicorn.Server):
    tunnel: Publication | None = None

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        if self.tunnel is not None:
            await self.tunnel.unregister()
        await super().shutdown(sockets)


@dataclass(frozen=True, slots=True)
class RateLimit:
    requests: int
    per: str


@dataclass(frozen=True, slots=True)
class Limits:
    requests: int | None = None
    rate: RateLimit | None = None
    concurrency: int | None = None


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    """a visitor access mode with an optional additional network restriction."""

    mode: Literal["restricted", "anonymous"] = "restricted"
    ip: tuple[str, ...] = ()


def _access_payload(
    access: Literal["restricted", "anonymous"] | AccessPolicy | None,
) -> tuple[str | None, list[str] | None]:
    if access is None:
        return None, None
    if isinstance(access, str):
        if access not in ("restricted", "anonymous"):
            raise TnlError("sdk.configuration_invalid", "access must be restricted or anonymous")
        return access, None
    if (
        not isinstance(access, AccessPolicy)
        or access.mode not in ("restricted", "anonymous")
        or len(access.ip) > 32
    ):
        raise TnlError("sdk.configuration_invalid", "invalid visitor access policy")
    if any(not isinstance(value, str) or not value for value in access.ip) or len(
        set(access.ip)
    ) != len(access.ip):
        raise TnlError(
            "sdk.configuration_invalid", "visitor IP list contains invalid or duplicate entries"
        )
    return access.mode, list(access.ip) if access.ip else None


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


class Publication:
    """one public URL publication and its owned ASGI adapter listener."""

    def __init__(
        self,
        native: NativeRuntime,
        server: _OwnedServer,
        serve_task: asyncio.Task[None],
        listener: socket.socket,
        directory: str,
        publisher_credential_file: str | None,
        publisher_identity_id: str | None,
        server_url: str | None,
        state_dir: str | None,
        access_mode: str | None,
        ip: list[str] | None,
        limits: Limits | None,
        require_post_quantum: bool = False,
        telemetry: bool = True,
        deployment: dict[str, str] | None = None,
        service: str | None = None,
        on_close: Callable[[Publication], None] | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._native = native
        self._deployment = None if deployment is None else dict(deployment)
        self._service = service
        self._on_close = on_close
        self._environment = None if environment is None else dict(environment)
        self._assigned_url: str | None = None
        self._server = server
        self._serve_task = serve_task
        self._listener = listener
        self._directory = directory
        self._state_dir = state_dir
        self._endpoint: Endpoint | None = None
        self._id = "ivk_" + "".join(secrets.choice(_alphabet) for _ in range(22))
        self._owner = secrets.token_hex(16)
        self._target = f"http://127.0.0.1:{listener.getsockname()[1]}"
        self._payload: dict[str, object] = {
            "version": 1,
            "invocation_id": self._id,
            "owner": self._owner,
            "pid": os.getpid(),
            "target": self._target,
            "telemetry_disabled": not telemetry
            or (os.environ if self._environment is None else self._environment)
            .get("TNL_NO_TELEMETRY", "")
            .lower()
            in {"1", "true"},
        }
        if self._deployment is not None:
            self._payload["deployment"] = self._deployment
        if publisher_credential_file is not None:
            self._payload["publisher_credential_file"] = publisher_credential_file
        if publisher_identity_id is not None:
            self._payload["publisher_identity_id"] = publisher_identity_id
        if server_url is not None:
            self._payload["server_url"] = server_url
        self._registration: dict[str, object] | None = None
        self._registration_uncertain = False
        self._initial_registration: asyncio.Task[None] | None = None
        if access_mode is not None:
            self._payload["access_mode"] = access_mode
        if require_post_quantum:
            self._payload["require_post_quantum"] = True
        if ip is not None:
            self._payload["ip"] = ip
        if limits is not None:
            self._payload["limits"] = _limit_payload(limits)
        self._closed = False
        self._closing_event = asyncio.Event()
        self._close_lock = asyncio.Lock()
        self._cleanup_task: asyncio.Task[None] | None = None
        self._close_complete = False
        self._registration_lock = asyncio.Lock()
        self._monitor: asyncio.Task[None] | None = None
        self._url: str | None = None
        self._run = 0
        loop = asyncio.get_running_loop()
        self._ready: asyncio.Future[None] = loop.create_future()
        self._finished: asyncio.Future[None] = loop.create_future()
        for future in (self._ready, self._finished):
            future.add_done_callback(
                lambda value: value.exception() if not value.cancelled() else None
            )
        server.tunnel = self

    @property
    def url(self) -> str:
        if self._url is None or not self._ready.done() or self._ready.exception() is not None:
            raise InvalidResponse()
        return self._url

    async def _register(self) -> None:
        async with self._registration_lock:
            if self._closed:
                return
            if self._deployment is not None:
                self._endpoint = await self._native.start(
                    self._directory,
                    invocation_id=self._id,
                    state_dir=self._state_dir,
                    publications=True,
                    environment=self._environment,
                )
            elif self._service is not None:
                self._endpoint = await self._native.start(
                    self._directory,
                    service=self._service,
                    state_dir=self._state_dir,
                    environment=self._environment,
                )
            else:
                self._endpoint = await self._native.start(
                    self._directory,
                    invocation_id=self._id,
                    state_dir=self._state_dir,
                    environment=self._environment,
                )
            await self._acknowledge_registration()

    async def _acknowledge_registration(self) -> None:
        assert self._endpoint is not None
        # native may commit before the reply is lost. keep the exact invocation,
        # owner, PID, target, and policy until its idempotent reply is reconciled.
        self._registration_uncertain = True
        try:
            if self._service is not None:
                assignment = parse_assignment(
                    await self._native.request(
                        self._endpoint,
                        "prepare",
                        {
                            "version": 1,
                            "directory": self._directory,
                            "service": self._service,
                            "framework": "python",
                            "owner": self._owner,
                            "pid": os.getpid(),
                            "telemetry_disabled": self._payload["telemetry_disabled"],
                        },
                    ),
                    self._endpoint,
                )
                if (
                    not assignment.public_url
                    or self._assigned_url is not None
                    and self._assigned_url != assignment.public_url
                ):
                    raise InvalidResponse()
                self._assigned_url = assignment.public_url
                self._registration = {
                    "version": 1,
                    "registration_id": assignment.registration_id,
                    "owner": self._owner,
                    "target": self._target,
                }
                await self._native.request(self._endpoint, "register", self._registration)
                self._registration_uncertain = False
                return
            self._registration = parse_registration(
                await self._native.request(self._endpoint, "ad-hoc/register", self._payload),
                self._owner,
                self._target,
            )
        except (NativeUnavailable, InvalidResponse, asyncio.CancelledError):
            raise
        except TnlError:
            self._registration_uncertain = False
            raise
        self._registration_uncertain = False

    async def start(self) -> None:
        self._initial_registration = asyncio.create_task(self._register())
        await asyncio.shield(self._initial_registration)
        self._monitor = asyncio.create_task(self._follow())
        await asyncio.shield(self._ready)

    async def unregister(self) -> None:
        await _join_cleanup(asyncio.create_task(self._unregister()))

    async def _unregister(self) -> None:
        if not self._closed:
            self._fail(TnlError("sdk.listener_failed", "ASGI listener stopped during publication"))
        if self._initial_registration is not None:
            try:
                await self._initial_registration
            except TnlError:
                pass
        async with self._registration_lock:
            for attempt in range(3):
                try:
                    if self._registration_uncertain:
                        await self._acknowledge_registration()
                    break
                except NativeUnavailable:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(0.1)
            if self._registration is not None and self._endpoint is not None:
                for attempt in range(3):
                    try:
                        await self._native.request(self._endpoint, "unregister", self._registration)
                        break
                    except RegistrationLost:
                        break
                    except NativeUnavailable:
                        if attempt == 2:
                            raise
                        await asyncio.sleep(0.1)
                self._registration = None

    def _observe(self, status: Status) -> None:
        if status.public_url is not None:
            if (
                self._url is not None
                and status.public_url != self._url
                or self._assigned_url is not None
                and status.public_url != self._assigned_url
            ):
                raise InvalidResponse()
            self._url = status.public_url
        if status.publish_run_number is not None:
            if status.publish_run_number < self._run:
                raise InvalidResponse()
            self._run = status.publish_run_number
        if status.routable and not self._ready.done():
            self._ready.set_result(None)
        elif status.failure:
            self._fail(TnlError("sdk.publication_failed", "the public URL could not be published"))

    async def _follow(self) -> None:
        last_renew = asyncio.get_running_loop().time()
        while not self._closed and not self._finished.done():
            try:
                if self._serve_task.done():
                    self._fail(
                        TnlError("sdk.listener_failed", "ASGI listener stopped during publication")
                    )
                    return
                assert self._endpoint is not None and self._registration is not None
                status = parse_status(
                    await self._native.request(self._endpoint, "status"),
                    self._service or self._id,
                    str(self._registration["registration_id"]),
                    self._target,
                )
                if status is not None:
                    self._observe(status)
                await self._pause(0.25)
                if self._closed or self._finished.done():
                    return
                if asyncio.get_running_loop().time() - last_renew >= 5:
                    await self._native.request(self._endpoint, "renew", self._registration)
                    last_renew = asyncio.get_running_loop().time()
            except asyncio.CancelledError:
                return
            except (NativeUnavailable, RegistrationLost):
                try:
                    await self._register()
                except (NativeUnavailable, RegistrationLost):
                    await self._pause(1)
                except TnlError as cause:
                    self._fail(cause)
                    return
            except TnlError as cause:
                self._fail(cause)
                return

    def _fail(self, error: TnlError) -> None:
        if not self._ready.done():
            self._ready.set_exception(error)
        if not self._finished.done():
            self._finished.set_exception(error)

    async def _pause(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._closing_event.wait(), seconds)
        except TimeoutError:
            pass

    async def wait(self) -> None:
        await asyncio.shield(self._finished)

    async def aclose(self) -> None:
        if self._cleanup_task is None or (self._cleanup_task.done() and not self._close_complete):
            self._cleanup_task = asyncio.create_task(self._close())
        await _join_cleanup(self._cleanup_task)

    async def _close(self) -> None:
        async with self._close_lock:
            if self._close_complete:
                return
            self._closed = True
            self._closing_event.set()
            if self._monitor is not None:
                await self._monitor
            # an error retains the listener and registration for a later close
            # retry. only a joined native cleanup may stop the application's ASGI.
            await self.unregister()
            cleanup: list[Exception] = []
            self._server.tunnel = None
            self._server.should_exit = True
            try:
                await asyncio.wait_for(self._serve_task, 15)
            except (Exception, asyncio.CancelledError) as cause:
                if isinstance(cause, Exception):
                    cleanup.append(cause)
                self._server.force_exit = True
                self._serve_task.cancel()
                try:
                    await self._serve_task
                except asyncio.CancelledError:
                    pass
            finally:
                self._listener.close()
            self._close_complete = True
            if self._on_close is not None:
                self._on_close(self)
            if not self._finished.done():
                if cleanup:
                    self._finished.set_exception(cleanup[0])
                else:
                    self._finished.set_result(None)
            if not self._ready.done():
                self._ready.set_exception(RegistrationLost())
            if len(cleanup) == 1:
                raise cleanup[0]
            if cleanup:
                raise ExceptionGroup("publisher and ASGI cleanup failed", cleanup)

    async def __aenter__(self) -> Publication:
        if self._closed:
            raise RegistrationLost()
        return self

    async def __aexit__(self, _type: object, primary: object, _traceback: object) -> None:
        try:
            await self.aclose()
        except BaseException as cleanup:
            if isinstance(primary, BaseException):
                raise BaseExceptionGroup(
                    "publication operation and cleanup failed", [primary, cleanup]
                ) from None
            raise


async def _start_asgi(app: ASGIApp) -> tuple[_OwnedServer, asyncio.Task[None], socket.socket]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    task: asyncio.Task[None] | None = None
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        server = _OwnedServer(
            uvicorn.Config(
                app,
                lifespan="on",
                ws="websockets-sansio",
                log_level="critical",
                access_log=False,
                timeout_graceful_shutdown=10,
            )
        )
        task = asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:
            if task.done():
                await task
                raise TnlError("sdk.listener_failed", "ASGI lifespan did not start")
            await asyncio.sleep(0.01)
        return server, task, listener
    except BaseException:
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        listener.close()
        raise


async def start_publication(
    app: ASGIApp,
    *,
    publisher_credential_file: str | Path | None = None,
    publisher_identity_id: str | None = None,
    server: str | None = None,
    directory: str | Path | None = None,
    state_dir: str | Path | None = None,
    access: Literal["restricted", "anonymous"] | AccessPolicy | None = None,
    limits: Limits | None = None,
    require_post_quantum: bool = False,
    telemetry: bool = True,
    deployment: dict[str, str] | None = None,
    service: str | None = None,
    on_close: Callable[[Publication], None] | None = None,
    on_start: Callable[[Publication], None] | None = None,
    environment: Mapping[str, str] | None = None,
) -> Publication:
    """start ASGI, register its bound listener, and wait for native routability."""
    if service is not None:
        service_name(service)
    if deployment is not None and (
        service is not None
        or server is not None
        or publisher_identity_id is not None
        or publisher_credential_file is not None
    ):
        raise TnlError("sdk.configuration_invalid", "select one captured publication owner")
    if (service is not None or deployment is not None and "service" in deployment) and (
        access is not None or limits is not None or require_post_quantum
    ):
        raise TnlError(
            "sdk.configuration_invalid",
            "named publication uses its saved visitor policy and limits",
        )
    if not callable(app):
        raise TnlError("sdk.configuration_invalid", "pass an ASGI app")
    if not isinstance(require_post_quantum, bool):
        raise TnlError("sdk.configuration_invalid", "require_post_quantum must be a boolean")
    if type(telemetry) is not bool:
        raise TnlError("sdk.configuration_invalid", "telemetry must be a boolean")
    if publisher_credential_file is not None and publisher_identity_id is not None:
        raise TnlError("sdk.configuration_invalid", "select a publisher file or publisher ID")
    # a running connector owner does not inherit later changes to the app's env.
    # send the path, never the credential contents, with this invocation.
    if (
        publisher_credential_file is None
        and publisher_identity_id is None
        and deployment is None
        and service is None
    ):
        publisher_credential_file = (os.environ if environment is None else environment).get(
            "TNL_PUBLISHER_CREDENTIAL_FILE"
        )
    if publisher_credential_file is not None and (
        not isinstance(publisher_credential_file, str | Path)
        or not Path(publisher_credential_file).is_absolute()
        or not 0 < len(str(publisher_credential_file)) <= 4096
        or "\0" in str(publisher_credential_file)
    ):
        raise TnlError(
            "sdk.configuration_invalid", "publisher_credential_file must be an absolute path"
        )
    if publisher_identity_id is not None and (
        not isinstance(publisher_identity_id, str)
        or re.fullmatch(r"pub_[A-Za-z0-9]{22}", publisher_identity_id) is None
    ):
        raise TnlError("sdk.configuration_invalid", "pass a stored publisher ID")
    if server is not None:
        origin = urlsplit(server)
        if (
            len(server) > 4096
            or origin.scheme != "https"
            or not origin.hostname
            or origin.username
            or origin.password
            or origin.path
            or origin.query
            or origin.fragment
        ):
            raise TnlError("sdk.configuration_invalid", "server must be an HTTPS origin")
    access_mode, ip = _access_payload(access)
    _limit_payload(limits)
    root = str(Path(directory or os.getcwd()).resolve())
    asgi_server, task, listener = await _start_asgi(app)
    tunnel = Publication(
        _native,
        asgi_server,
        task,
        listener,
        root,
        None if publisher_credential_file is None else str(publisher_credential_file),
        publisher_identity_id,
        server,
        None if state_dir is None else str(state_dir),
        access_mode,
        ip,
        limits,
        require_post_quantum,
        telemetry,
        deployment,
        service,
        on_close,
        environment,
    )
    try:
        if on_start is not None:
            on_start(tunnel)
        await tunnel.start()
        return tunnel
    except BaseException as primary:
        try:
            await tunnel.aclose()
        except BaseException as cleanup:
            if isinstance(primary, asyncio.CancelledError) and isinstance(
                cleanup, asyncio.CancelledError
            ):
                raise primary from None
            raise BaseExceptionGroup(
                "ASGI operation and cleanup failed", [primary, cleanup]
            ) from None
        raise


@asynccontextmanager
async def open(
    app: ASGIApp,
    *,
    publisher_credential_file: str | Path | None = None,
    publisher_identity_id: str | None = None,
    server: str | None = None,
    directory: str | Path | None = None,
    state_dir: str | Path | None = None,
    access: Literal["restricted", "anonymous"] | AccessPolicy | None = None,
    limits: Limits | None = None,
    require_post_quantum: bool = False,
    telemetry: bool = True,
) -> AsyncIterator[Publication]:
    publication = await start_publication(
        app,
        publisher_credential_file=publisher_credential_file,
        publisher_identity_id=publisher_identity_id,
        server=server,
        directory=directory,
        state_dir=state_dir,
        access=access,
        limits=limits,
        require_post_quantum=require_post_quantum,
        telemetry=telemetry,
    )
    try:
        yield publication
    except BaseException as primary:
        try:
            await publication.aclose()
        except BaseException as cleanup:
            if isinstance(primary, asyncio.CancelledError) and isinstance(
                cleanup, asyncio.CancelledError
            ):
                raise primary from None
            raise BaseExceptionGroup(
                "ASGI operation and cleanup failed", [primary, cleanup]
            ) from None
        raise
    else:
        await publication.aclose()
