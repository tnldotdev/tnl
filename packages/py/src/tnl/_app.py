"""configured Uvicorn registration belongs to the serving worker after bind."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import socket
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


def _read_telemetry_disabled(value: str | None) -> bool:
    """match the native cli's pinned kong boolean environment grammar, without trimming."""
    if value is None:
        return False
    normalized = value.lower()
    if normalized in ("true", "yes", "1"):
        return True
    if normalized in ("false", "no", "0"):
        return False
    raise TnlError("sdk.configuration_invalid", "TNL_NO_TELEMETRY must be a boolean")


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


class PreparedService:
    def __init__(
        self, directory: str, service: str | None, state_dir: str | None, native: NativeRuntime
    ) -> None:
        self._directory = directory
        self._service = service
        self._state_dir = state_dir
        self._native = native
        self._telemetry_disabled = _read_telemetry_disabled(os.environ.get("TNL_NO_TELEMETRY"))
        self._owner = secrets.token_hex(16)
        self._endpoint: Endpoint | None = None
        self._registration_id = ""
        self._target: str | None = None
        self._closed = False
        self._lock = asyncio.Lock()
        self._renewal: asyncio.Task[None] | None = None
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
            "telemetry_disabled": self._telemetry_disabled,
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
        self._endpoint = endpoint
        self._registration_id = ident
        self.service, self.hostname, self.public_url = name, host, url

    def _registration(self) -> dict[str, object]:
        value: dict[str, object] = {
            "version": 1,
            "registration_id": self._registration_id,
            "owner": self._owner,
        }
        if self._target is not None:
            value["target"] = self._target
        return value

    async def start(self) -> None:
        await self._prepare()
        self._renewal = asyncio.create_task(self._renew())

    async def register(self, target: str) -> None:
        async with self._lock:
            if self._closed:
                raise RegistrationLost()
            self._target = target
            assert self._endpoint is not None
            try:
                await self._native.request(self._endpoint, "register", self._registration())
            except (NativeUnavailable, RegistrationLost):
                await self._prepare()
                assert self._endpoint is not None
                await self._native.request(self._endpoint, "register", self._registration())

    async def _renew(self) -> None:
        while not self._closed:
            await asyncio.sleep(5)
            async with self._lock:
                if self._closed:
                    return
                assert self._endpoint is not None
                try:
                    await self._native.request(self._endpoint, "renew", self._registration())
                except (NativeUnavailable, RegistrationLost):
                    try:
                        await self._prepare()
                        assert self._endpoint is not None
                        if self._target is not None:
                            await self._native.request(
                                self._endpoint, "register", self._registration()
                            )
                    except TnlError:
                        pass
                except TnlError:
                    pass

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._renewal is not None:
                self._renewal.cancel()
                try:
                    await self._renewal
                except asyncio.CancelledError:
                    pass
            if self._endpoint is not None:
                try:
                    await self._native.request(self._endpoint, "unregister", self._registration())
                except (RegistrationLost, NativeUnavailable):
                    pass


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
