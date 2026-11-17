"""configured Uvicorn registration belongs to the serving worker after bind."""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
from pathlib import Path

import uvicorn
from starlette.types import ASGIApp
from uvicorn.supervisors import ChangeReload

from ._asgi import _OwnedServer
from ._native import NativeRuntime, _join_cleanup, _shutdown_deadline
from ._protocol import (
    InvalidResponse,
    NativeUnavailable,
    RegistrationLost,
    TnlError,
    service_name,
)
from ._registration import NativeRegistration


class PreparedService:
    def __init__(
        self,
        directory: str,
        service: str | None,
        state_dir: str | None,
        native: NativeRuntime,
        telemetry: bool = True,
    ) -> None:
        if type(telemetry) is not bool:
            raise TnlError("sdk.configuration_invalid", "telemetry must be a boolean")
        self._registration = NativeRegistration(
            native,
            directory,
            state_dir,
            {
                "version": 1,
                "directory": directory,
                "framework": "python",
                "owner": secrets.token_hex(16),
                "pid": os.getpid(),
                "telemetry_disabled": not telemetry
                or os.getenv("TNL_NO_TELEMETRY", "").lower() in {"1", "true"},
                **({} if service is None else {"service": service}),
            },
            service=service,
        )
        self._renewal: asyncio.Task[None] | None = None
        self._preparations: set[asyncio.Task[None]] = set()
        self._closed_error = RegistrationLost()
        self._cleanup: asyncio.Task[None] | None = None
        self._shutdown_until: float | None = None
        self.service = ""
        self.hostname = ""
        self.public_url = ""

    async def _prepare(self) -> None:
        if self._registration.closed:
            raise self._closed_error
        task = asyncio.create_task(self._prepare_work())
        self._preparations.add(task)
        task.add_done_callback(self._preparation_finished)
        await task
        if self._registration.closed:
            raise self._closed_error

    def _preparation_finished(self, task: asyncio.Task[None]) -> None:
        self._preparations.discard(task)
        if not task.cancelled():
            task.exception()

    async def _prepare_work(self) -> None:
        try:
            await self._registration.discover()
        except RegistrationLost:
            if self._registration.closed:
                raise self._closed_error from None
            raise
        assignment = await self._registration.prepare()
        if self._registration.closed:
            raise self._closed_error
        # acquisition may precede endpoint allocation; prepared apps may not.
        if not assignment.hostname:
            raise InvalidResponse()
        name, host, url = assignment.service, assignment.hostname, assignment.public_url
        if self.service and (url != self.public_url or name != self.service):
            # compensate this rejected registration without stopping its owner.
            until = self._shutdown_until or _shutdown_deadline()
            await self._registration.discard_candidate(until)
            raise InvalidResponse()
        self._registration.accept()
        self.service, self.hostname, self.public_url = name, host, url

    async def start(self) -> None:
        await self._prepare()
        if self._registration.closed:
            raise self._closed_error
        self._renewal = asyncio.create_task(self._renew())

    async def register(self, target: str) -> None:
        async with self._registration.lock:
            try:
                await self._registration.bind(target)
            except (NativeUnavailable, RegistrationLost):
                if self._registration.closed:
                    raise
                await self._prepare()
                await self._registration.bind(target)

    async def _renew(self) -> None:
        while not self._registration.closed:
            await asyncio.sleep(5)
            async with self._registration.lock:
                if self._registration.closed:
                    return
                try:
                    await self._registration.renew()
                except (NativeUnavailable, RegistrationLost):
                    try:
                        await self._prepare()
                        if self._registration.target is not None:
                            await self._registration.bind(self._registration.target)
                    except TnlError:
                        pass
                except TnlError:
                    pass

    async def close(self, until: float | None = None) -> None:
        if self._cleanup is None:
            deadline = self._shutdown_until or _shutdown_deadline()
            if until is not None:
                deadline = min(deadline, until)
            self._shutdown_until = self._registration.begin_shutdown(deadline)
            self._cleanup = asyncio.create_task(self._close(deadline))
        await _join_cleanup(self._cleanup)

    async def _close(self, until: float) -> None:
        joining = self._registration.stop()
        workers = set(self._preparations)
        if self._renewal is not None:
            workers.add(self._renewal)
        for worker in workers:
            if not worker.done():
                worker.cancel()
        pending_work: set[asyncio.Task[None] | asyncio.Task[list[BaseException]]] = {
            joining,
            *workers,
        }
        done, pending = await asyncio.wait(
            pending_work, timeout=max(0, until - asyncio.get_running_loop().time())
        )
        failures: list[BaseException] = []
        for completed in done:
            if completed.cancelled():
                continue
            cause = completed.exception()
            if cause is not None and cause is not self._closed_error:
                failures.append(cause)
        if joining in done and not joining.cancelled() and joining.exception() is None:
            for cause in joining.result():
                if all(cause is not failure for failure in failures):
                    failures.append(cause)
        if pending:
            failures.append(
                TimeoutError("publication shutdown timed out; remote cleanup is unconfirmed")
            )
            for unfinished in pending:
                unfinished.add_done_callback(
                    lambda task: None if task.cancelled() else task.exception()
                )
        try:
            if not pending:
                await self._registration.unregister(until)
        except BaseException as cause:
            failures.append(cause)
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
