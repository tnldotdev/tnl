"""configured Uvicorn registration belongs to the serving worker after bind."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import socket
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from starlette.types import ASGIApp
from uvicorn.supervisors import ChangeReload

from ._native import NativeRuntime
from ._protocol import (
    Endpoint,
    InvalidResponse,
    NativeUnavailable,
    RegistrationLost,
    TnlError,
    hostname,
    object_value,
    service_name,
    text,
)
from ._publication import Publication, Selection, join_cleanup


def _service_metadata(name: str, value: object) -> dict[str, object]:
    item = object_value(
        value, {"protocol", "namespace", "hostname", "port", "public", "url", "paths"}
    )
    hostname(item.get("namespace"))
    host = hostname(item.get("hostname"))
    protocol, port = item.get("protocol"), item.get("port")
    if (
        protocol not in ("http", "tcp", "postgres", "mysql", "kubernetes")
        or type(port) is not int
        or not 1 <= port <= 65535
        or type(item.get("public")) is not bool
    ):
        raise InvalidResponse()
    url = item.get("url", "")
    if protocol in ("http", "kubernetes"):
        if url != f"https://{host}:{port}" and not (port == 443 and url == f"https://{host}"):
            raise InvalidResponse()
    elif url != "":
        raise InvalidResponse()
    paths = item.get("paths", {})
    if not isinstance(paths, dict) or len(paths) > 32 or protocol != "http" and paths:
        raise InvalidResponse()
    for prefix, raw in paths.items():
        prefix = text(prefix, 256)
        mount = object_value(raw, {"service", "url", "stripPrefix"})
        if (
            re.fullmatch(r"/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]+", prefix) is None
            or any(segment in (".", "..") for segment in prefix.split("/"))
            or prefix == "/__tnl"
            or prefix.startswith("/__tnl/")
            or service_name(mount.get("service")) == name
            or mount.get("url") != f"{url}{prefix}"
            or type(mount.get("stripPrefix")) is not bool
        ):
            raise InvalidResponse()
    return item


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


@dataclass(slots=True)
class _PublicationRun:
    stopped: asyncio.Event
    done: asyncio.Future[None]


class PreparedService:
    def __init__(
        self, directory: str, service: str | None, state_dir: str | None, native: NativeRuntime
    ) -> None:
        self._directory = directory
        self._service = service
        self._state_dir = state_dir
        self._native = native
        self._owner = secrets.token_hex(16)
        self._phase: _RegistrationPhase = _Preparing()
        self._target: str | None = None
        self._lock = asyncio.Lock()
        self._renewal: asyncio.Task[None] | None = None
        self._active: _PublicationRun | None = None
        self._released = False
        self._cleanup: asyncio.Task[None] | None = None
        self._close_complete = False
        self._closing_requested = False
        self.service = ""
        self.hostname = ""
        self.public_url = ""

    async def _prepare(self) -> None:
        endpoint = await self._native.start(
            self._directory, service=self._service, state_dir=self._state_dir
        )
        payload: dict[str, object] = {
            "version": 1,
            "directory": self._directory,
            "framework": "python",
            "owner": self._owner,
            "pid": os.getpid(),
        }
        if self._service is not None:
            payload["service"] = self._service
        assignment = object_value(
            await self._native.request(endpoint, "prepare", payload),
            {"version", "registration_id", "service", "hostname", "public_url", "project"},
        )
        ident = text(assignment.get("registration_id"), 128)
        if (
            type(assignment.get("version")) is not int
            or assignment["version"] != 1
            or re.fullmatch(r"reg_[a-f0-9]{32}", ident) is None
        ):
            raise InvalidResponse()
        name = service_name(assignment.get("service"))
        without_endpoint = assignment.get("hostname") == "" and assignment.get("public_url") == ""
        host = "" if without_endpoint else hostname(assignment.get("hostname"))
        url = "" if without_endpoint else text(assignment.get("public_url"))
        project = object_value(
            assignment.get("project"),
            {"namespace", "dev", "services", "oauth", "webhooks", "aliases", "worktree"},
        )
        services = project.get("services")
        if not isinstance(services, dict) or len(services) > 32 or project.get("dev") is not True:
            raise InvalidResponse()
        if (
            project.get("namespace") != ""
            or services
            or any(key in project for key in ("oauth", "webhooks", "aliases"))
        ):
            hostname(project.get("namespace"))
        validated = {}
        for key, raw in services.items():
            key = service_name(key)
            validated[key] = _service_metadata(key, raw)
        own = validated.get(name)
        if (
            name != endpoint.service
            or endpoint.scope != "app"
            or (without_endpoint and own is not None)
            or (
                not without_endpoint
                and (
                    own is None
                    or own.get("protocol") != "http"
                    or own.get("hostname") != host
                    or own.get("url") != url
                )
            )
        ):
            raise InvalidResponse()
        if self.service and (url != self.public_url or name != self.service):
            await self._native.request(
                endpoint,
                "unregister",
                {"version": 1, "registration_id": ident, "owner": self._owner},
            )
            raise InvalidResponse()
        if isinstance(self._phase, _Closed):
            raise RegistrationLost()
        self._phase = _Prepared(endpoint, ident)
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
        self._renewal = asyncio.create_task(self._renew())

    async def register(self, target: str) -> Publication:
        async with self._lock:
            if self._closing_requested or isinstance(self._phase, _Closed):
                raise RegistrationLost()
            if self._released:
                await self._prepare()
                self._released = False
            self._target = target
            prepared = self._phase
            assert isinstance(prepared, _Prepared)
            try:
                await self._native.request(
                    prepared.endpoint, "register", self._registration(prepared)
                )
            except (NativeUnavailable, RegistrationLost):
                await self._prepare()
                prepared = self._phase
                assert isinstance(prepared, _Prepared)
                await self._native.request(
                    prepared.endpoint, "register", self._registration(prepared)
                )

            self._finish_active()
            if self._closing_requested:
                raise RegistrationLost()
            active = _PublicationRun(asyncio.Event(), asyncio.get_running_loop().create_future())
            self._active = active

            def current() -> Selection:
                if (
                    self._active is not active
                    or not isinstance(self._phase, _Prepared)
                    or self._target is None
                ):
                    raise RegistrationLost()
                return Selection(
                    self._phase.endpoint, self.service, self._phase.registration_id, self._target
                )

            async def close() -> None:
                active.stopped.set()
                await join_cleanup(asyncio.create_task(self._release(active)))

            async def finished() -> None:
                await asyncio.shield(active.done)

            return Publication(
                native=self._native,
                current=current,
                url=lambda: self.public_url or None,
                stopped=active.stopped,
                close=close,
                finished=finished,
            )

    def _finish_active(self) -> None:
        if self._active is not None:
            self._active.stopped.set()
            if not self._active.done.done():
                self._active.done.set_result(None)
            self._active = None

    async def _release(self, active: _PublicationRun) -> None:
        async with self._lock:
            if self._active is not active:
                return
            prepared = self._phase.registration if isinstance(self._phase, _Closed) else self._phase
            if isinstance(prepared, _Prepared):
                try:
                    await self._native.request(
                        prepared.endpoint, "unregister", self._registration(prepared)
                    )
                except RegistrationLost:
                    pass
            self._released = True
            self._target = None
            self._finish_active()

    async def _renew(self) -> None:
        while not isinstance(self._phase, _Closed):
            await asyncio.sleep(5)
            async with self._lock:
                prepared = self._phase
                if isinstance(prepared, _Closed):
                    return
                if self._released:
                    continue
                assert isinstance(prepared, _Prepared)
                try:
                    await self._native.request(
                        prepared.endpoint, "renew", self._registration(prepared)
                    )
                except (NativeUnavailable, RegistrationLost):
                    try:
                        await self._prepare()
                        prepared = self._phase
                        assert isinstance(prepared, _Prepared)
                        if self._target is not None:
                            await self._native.request(
                                prepared.endpoint, "register", self._registration(prepared)
                            )
                    except TnlError:
                        pass
                except TnlError:
                    pass

    async def close(self) -> None:
        self._closing_requested = True
        if self._active is not None:
            self._active.stopped.set()
        if self._cleanup is None or self._cleanup.done() and not self._close_complete:
            self._cleanup = asyncio.create_task(self._close())
        await join_cleanup(self._cleanup)

    async def _close(self) -> None:
        async with self._lock:
            if self._close_complete:
                return
            prepared = (
                self._phase.registration
                if isinstance(self._phase, _Closed)
                else self._phase
                if isinstance(self._phase, _Prepared) and not self._released
                else None
            )
            self._phase = _Closed(prepared)
            if self._renewal is not None:
                self._renewal.cancel()
                try:
                    await self._renewal
                except asyncio.CancelledError:
                    pass
            if prepared is not None:
                try:
                    await self._native.request(
                        prepared.endpoint, "unregister", self._registration(prepared)
                    )
                except RegistrationLost:
                    pass
            self._finish_active()
            self._close_complete = True


async def prepare(
    *,
    directory: str | Path | None = None,
    service: str | None = None,
    state_dir: str | Path | None = None,
) -> PreparedService:
    if service is not None:
        service_name(service)
    root = str(Path(directory or os.getcwd()).resolve())
    result = PreparedService(
        root, service, None if state_dir is None else str(state_dir), NativeRuntime()
    )
    await result.start()
    return result


class Server(uvicorn.Server):
    """register a configured service in the serving worker, never its supervisor."""

    def __init__(
        self,
        config: uvicorn.Config,
        *,
        directory: str | Path | None = None,
        service: str | None = None,
        state_dir: str | Path | None = None,
    ) -> None:
        super().__init__(config)
        self._directory = directory
        self._service = service
        self._state_dir = state_dir
        self._publication: PreparedService | None = None

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
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
                directory=self._directory, service=self._service, state_dir=self._state_dir
            )
            await self._publication.register(f"{protocol}://{authority}:{port}")
        except BaseException:
            await self.shutdown(sockets)
            raise

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        try:
            if self._publication is not None:
                await self._publication.close()
                self._publication = None
        finally:
            await super().shutdown(sockets)


def run(
    app: ASGIApp | str,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
    directory: str | Path | None = None,
    service: str | None = None,
    state_dir: str | Path | None = None,
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
    server = Server(config, directory=directory, service=service, state_dir=state_dir)
    if config.should_reload:
        listener = config.bind_socket()
        try:
            ChangeReload(config, target=server.run, sockets=[listener]).run()
        finally:
            listener.close()
    else:
        server.run()
