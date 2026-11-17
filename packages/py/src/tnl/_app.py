"""configured Uvicorn registration belongs to the serving worker after bind."""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from starlette.types import ASGIApp
from uvicorn.supervisors import ChangeReload

from ._asgi import _OwnedServer
from ._native import NativeRuntime, _join_cleanup, _shutdown_deadline, _shutdown_timestamp
from ._protocol import (
    Endpoint,
    InvalidResponse,
    NativeUnavailable,
    RegistrationLost,
    TnlError,
    parse_assignment,
    service_name,
)


@dataclass(frozen=True, slots=True)
class _Preparing:
    pass


@dataclass(frozen=True, slots=True)
class _Prepared:
    endpoint: Endpoint
    registration_id: str


@dataclass(frozen=True, slots=True)
class _Closed:
    registration: _Prepared | None


type _RegistrationPhase = _Preparing | _Prepared | _Closed


class PreparedService:
    def __init__(
        self,
        directory: str,
        service: str | None,
        state_dir: str | None,
        native: NativeRuntime,
        telemetry: bool = True,
    ) -> None:
        self._directory = directory
        self._service = service
        self._state_dir = state_dir
        self._native = native
        if type(telemetry) is not bool:
            raise TnlError("sdk.configuration_invalid", "telemetry must be a boolean")
        self._telemetry_disabled = not telemetry or os.getenv("TNL_NO_TELEMETRY", "").lower() in {
            "1",
            "true",
        }
        self._owner = secrets.token_hex(16)
        self._phase: _RegistrationPhase = _Preparing()
        self._target: str | None = None
        self._lock = asyncio.Lock()
        self._renewal: asyncio.Task[None] | None = None
        self._requests: set[asyncio.Task[object]] = set()
        self._preparations: set[asyncio.Task[None]] = set()
        self._closed_error = RegistrationLost()
        self._cleanup: asyncio.Task[None] | None = None
        self._shutdown_until: float | None = None
        self._preparation_uncertain = False
        self._prepared_cleanup: _Prepared | None = None
        self.service = ""
        self.hostname = ""
        self.public_url = ""

    async def _request(
        self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
    ) -> object:
        task = asyncio.create_task(self._native.request(endpoint, operation, payload))
        self._requests.add(task)
        try:
            return await task
        finally:
            self._requests.discard(task)

    async def _prepare(self) -> None:
        if isinstance(self._phase, _Closed):
            raise self._closed_error
        task = asyncio.create_task(self._prepare_work())
        self._preparations.add(task)
        task.add_done_callback(self._preparation_finished)
        # track native discovery and reservation together so close joins the
        # complete acquisition before collecting registrations to unregister.
        await task
        if isinstance(self._phase, _Closed):
            raise self._closed_error

    def _preparation_finished(self, task: asyncio.Task[None]) -> None:
        self._preparations.discard(task)
        if not task.cancelled():
            task.exception()

    async def _prepare_work(self) -> None:
        if isinstance(self._phase, _Closed):
            raise self._closed_error
        endpoint = await self._native.start(
            self._directory, service=self._service, state_dir=self._state_dir
        )
        if isinstance(self._phase, _Closed):
            raise self._closed_error
        payload: dict[str, object] = {
            "version": 1,
            "directory": self._directory,
            "framework": "python",
            "owner": self._owner,
            "pid": os.getpid(),
            "telemetry_disabled": self._telemetry_disabled,
        }
        if self._service is not None:
            payload["service"] = self._service
        self._preparation_uncertain = True
        assignment = parse_assignment(await self._request(endpoint, "prepare", payload), endpoint)
        self._prepared_cleanup = _Prepared(endpoint, assignment.registration_id)
        self._preparation_uncertain = False
        # acquisition may precede endpoint allocation; prepared apps may not.
        if not assignment.hostname:
            raise InvalidResponse()
        ident, name, host, url = (
            assignment.registration_id,
            assignment.service,
            assignment.hostname,
            assignment.public_url,
        )
        if self.service and (url != self.public_url or name != self.service):
            # compensate this rejected registration without stopping its owner.
            until = self._shutdown_until or _shutdown_deadline()
            if asyncio.get_running_loop().time() >= until:
                raise TimeoutError("registration cleanup timed out; remote cleanup is unconfirmed")
            async with asyncio.timeout_at(until):
                await self._native.request(
                    endpoint,
                    "unregister",
                    {
                        "version": 1,
                        "registration_id": ident,
                        "owner": self._owner,
                        "shutdown_deadline": _shutdown_timestamp(until),
                    },
                )
            self._preparation_uncertain = False
            self._prepared_cleanup = None
            raise InvalidResponse()
        if isinstance(self._phase, _Closed):
            raise self._closed_error
        self._phase = _Prepared(endpoint, ident)
        self._preparation_uncertain = False
        self.service, self.hostname, self.public_url = name, host, url

    def _registration(self, prepared: _Prepared | None = None) -> dict[str, object]:
        if prepared is None:
            if not isinstance(self._phase, _Prepared):
                raise RegistrationLost()
            prepared = self._phase
        value: dict[str, object] = {
            "version": 1,
            "registration_id": prepared.registration_id,
            "owner": self._owner,
        }
        if self._target is not None:
            value["target"] = self._target
        return value

    async def start(self) -> None:
        await self._prepare()
        if isinstance(self._phase, _Closed):
            raise self._closed_error
        self._renewal = asyncio.create_task(self._renew())

    async def register(self, target: str) -> None:
        async with self._lock:
            if isinstance(self._phase, _Closed):
                raise RegistrationLost()
            self._target = target
            prepared = self._phase
            assert isinstance(prepared, _Prepared)
            try:
                await self._request(prepared.endpoint, "register", self._registration(prepared))
            except (NativeUnavailable, RegistrationLost):
                await self._prepare()
                prepared = self._phase
                assert isinstance(prepared, _Prepared)
                await self._request(prepared.endpoint, "register", self._registration(prepared))

    async def _renew(self) -> None:
        while not isinstance(self._phase, _Closed):
            await asyncio.sleep(5)
            async with self._lock:
                prepared = self._phase
                if isinstance(prepared, _Closed):
                    return
                assert isinstance(prepared, _Prepared)
                try:
                    await self._request(prepared.endpoint, "renew", self._registration(prepared))
                except (NativeUnavailable, RegistrationLost):
                    try:
                        await self._prepare()
                        prepared = self._phase
                        assert isinstance(prepared, _Prepared)
                        if self._target is not None:
                            await self._request(
                                prepared.endpoint, "register", self._registration(prepared)
                            )
                    except TnlError:
                        pass
                except TnlError:
                    pass

    async def close(self, until: float | None = None) -> None:
        if self._cleanup is None:
            deadline = self._shutdown_until or _shutdown_deadline()
            if until is not None:
                deadline = min(deadline, until)
            self._shutdown_until = deadline
            self._cleanup = asyncio.create_task(self._close(deadline))
        await _join_cleanup(self._cleanup)

    async def _close(self, until: float) -> None:
        prepared = self._phase if isinstance(self._phase, _Prepared) else self._prepared_cleanup
        self._phase = _Closed(prepared)
        workers: set[asyncio.Task[object] | asyncio.Task[None]] = set(self._requests)
        workers.update(self._preparations)
        if self._renewal is not None:
            workers.add(self._renewal)
        for worker in workers:
            worker.cancel()
        failures: list[BaseException] = []
        if workers:
            done, pending = await asyncio.wait(
                workers, timeout=max(0, until - asyncio.get_running_loop().time())
            )
            for worker in done:
                if not worker.cancelled():
                    cause = worker.exception()
                    if (
                        cause is not None
                        and cause is not self._closed_error
                        and all(cause is not failure for failure in failures)
                    ):
                        failures.append(cause)
            if pending:
                failures.append(
                    TimeoutError("publication shutdown timed out; remote cleanup is unconfirmed")
                )
                for worker in pending:
                    worker.add_done_callback(
                        lambda task: None if task.cancelled() else task.exception()
                    )
        if self._preparation_uncertain:
            failures.append(
                TnlError(
                    "sdk.dev_unavailable", "native registration cleanup could not be confirmed"
                )
            )
        registrations: list[_Prepared] = []
        for candidate in (prepared, self._prepared_cleanup):
            if candidate is not None and candidate not in registrations:
                registrations.append(candidate)
        for registration in registrations:
            try:
                if asyncio.get_running_loop().time() >= until:
                    raise TimeoutError(
                        "publication shutdown timed out; remote cleanup is unconfirmed"
                    )
                async with asyncio.timeout_at(until):
                    await self._native.request(
                        registration.endpoint,
                        "unregister",
                        {
                            **self._registration(registration),
                            "shutdown_deadline": _shutdown_timestamp(until),
                        },
                    )
            except BaseException as cause:
                failures.append(cause)
        if not failures:
            self._phase = _Closed(None)
            self._prepared_cleanup = None
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("app registration operation and cleanup failed", failures)


async def prepare(
    *,
    directory: str | Path | None = None,
    service: str | None = None,
    state_dir: str | Path | None = None,
    telemetry: bool = True,
) -> PreparedService:
    if service is not None:
        service_name(service)
    root = str(Path(directory or os.getcwd()).resolve())
    result = PreparedService(
        root, service, None if state_dir is None else str(state_dir), NativeRuntime(), telemetry
    )
    try:
        await result.start()
    except BaseException as primary:
        try:
            await result.close()
        except BaseException as cleanup:
            raise BaseExceptionGroup(
                "app preparation and cleanup failed", [primary, cleanup]
            ) from None
        raise
    return result


class Server(_OwnedServer):
    """register a configured service in the serving worker, never its supervisor."""

    def __init__(
        self,
        config: uvicorn.Config,
        *,
        directory: str | Path | None = None,
        service: str | None = None,
        state_dir: str | Path | None = None,
        telemetry: bool = True,
    ) -> None:
        # uvicorn pickles this configuration for reloader workers. install the
        # worker-local tracking wrapper only after the worker loads the app.
        super().__init__(config, None)
        self._directory = directory
        self._service = service
        self._state_dir = state_dir
        self._telemetry = telemetry
        self._publication: PreparedService | None = None

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        self._own_app(self.config.loaded_app)
        await super().startup(sockets)
        if not self.started or self.should_exit:
            return
        try:
            bound = [sock for listener in self.servers for sock in listener.sockets or ()]
            if not bound:
                raise TnlError("sdk.listener_failed", "Uvicorn has no bound TCP listener")
            host, port = bound[0].getsockname()[:2]
            if host in {"0.0.0.0", "::"}:
                host = "127.0.0.1" if host == "0.0.0.0" else "::1"
            authority = f"[{host}]" if ":" in host else host
            protocol = "https" if self.config.is_ssl else "http"
            self._publication = await prepare(
                directory=self._directory,
                service=self._service,
                state_dir=self._state_dir,
                telemetry=self._telemetry,
            )
            await self._publication.register(f"{protocol}://{authority}:{port}")
        except BaseException:
            await self.shutdown(sockets)
            raise

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        if self._shutdown_until is None:
            self._shutdown_until = _shutdown_deadline()
        until = self._shutdown_until
        failures: list[BaseException] = []
        try:
            async with asyncio.timeout_at(until):
                if self._publication is not None:
                    await self._publication.close(until)
                    self._publication = None
        except BaseException as cause:
            failures.append(cause)
        try:
            async with asyncio.timeout_at(until):
                await super().shutdown(sockets)
                await self.join_workers()
        except BaseException as cause:
            failures.append(cause)
            failures.extend(await self.force_shutdown(None))
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("native registration and ASGI shutdown failed", failures)


def run(
    app: ASGIApp | str,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
    directory: str | Path | None = None,
    service: str | None = None,
    state_dir: str | Path | None = None,
    telemetry: bool = True,
    reload_dirs: list[str] | None = None,
) -> None:
    """run a configured service; reload uses a separate Uvicorn supervisor."""
    if reload and not isinstance(app, str):
        raise TnlError("sdk.configuration_invalid", "reload requires an ASGI import string")
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        reload=reload,
        reload_dirs=reload_dirs if reload else None,
        lifespan="on",
        ws="websockets-sansio",
    )
    server = Server(
        config, directory=directory, service=service, state_dir=state_dir, telemetry=telemetry
    )
    if config.should_reload:
        listener = config.bind_socket()
        try:
            ChangeReload(config, target=server.run, sockets=[listener]).run()
        finally:
            listener.close()
    else:
        server.run()
