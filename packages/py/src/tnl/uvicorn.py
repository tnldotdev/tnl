"""register the socket owned by a development Uvicorn worker."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import socket
import sys
from pathlib import Path

import uvicorn as _uvicorn
from uvicorn.supervisors import ChangeReload

from ._native import NativeRuntime
from ._protocol import InvalidResponse, NativeUnavailable, RegistrationLost, TnlError

_native = NativeRuntime()
_registration = re.compile(r"reg_[a-f0-9]{32}")
_service = re.compile(r"[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?")


class Server(_uvicorn.Server):
    """prepare before ASGI startup and register only the serving worker's socket."""

    def __init__(self, config: _uvicorn.Config, service: str, directory: str) -> None:
        super().__init__(config)
        self.service = service
        self.directory = directory
        self.owner = secrets.token_hex(16)
        self.endpoint = ""
        self.registration_id = ""
        self.public_url = ""
        self._renewal: asyncio.Task[None] | None = None

    def _registration(self, target: str | None = None) -> dict[str, object]:
        result: dict[str, object] = {
            "version": 1,
            "registration_id": self.registration_id,
            "owner": self.owner,
        }
        if target is not None:
            result["target"] = target
        return result

    async def _prepare(self) -> None:
        self.endpoint = await _native.start(self.directory)
        value = await _native.app_request(
            self.endpoint,
            "prepare",
            {
                "version": 1,
                "directory": self.directory,
                "service": self.service,
                "framework": "python",
                "owner": self.owner,
                "pid": os.getpid(),
            },
        )
        if not isinstance(value, dict) or set(value) != {
            "version",
            "registration_id",
            "service",
            "hostname",
            "public_url",
            "project",
        }:
            raise InvalidResponse()
        registration_id = value["registration_id"]
        hostname = value["hostname"]
        public_url = value["public_url"]
        if (
            value["version"] != 1
            or not isinstance(registration_id, str)
            or _registration.fullmatch(registration_id) is None
            or value["service"] != self.service
            or not isinstance(hostname, str)
            or not isinstance(public_url, str)
            or public_url != "https://" + hostname
            or not isinstance(value["project"], dict)
            or self.public_url != ""
            and self.public_url != public_url
        ):
            raise InvalidResponse()
        self.registration_id = registration_id
        self.public_url = public_url

    def _target(self) -> str:
        if len(self.servers) != 1 or not self.servers[0].sockets:
            raise TnlError("sdk.listener_failed", "Uvicorn has no bound listener")
        host, port = self.servers[0].sockets[0].getsockname()[:2]
        if host != "127.0.0.1" or not isinstance(port, int) or port <= 0:
            raise TnlError("sdk.listener_failed", "Uvicorn must bind a loopback listener")
        return f"http://127.0.0.1:{port}"

    async def startup(self, sockets: list[socket.socket] | None = None) -> None:
        await self._prepare()
        try:
            await super().startup(sockets=sockets)
            if self.started:
                await _native.app_request(
                    self.endpoint, "register", self._registration(self._target())
                )
                self._renewal = asyncio.create_task(self._renew())
        except BaseException:
            await self._unregister()
            if self.started:
                await super().shutdown(sockets=sockets)
            raise

    async def _renew(self) -> None:
        while True:
            await asyncio.sleep(5)
            try:
                await _native.app_request(self.endpoint, "renew", self._registration())
            except (NativeUnavailable, RegistrationLost):
                try:
                    await self._prepare()
                    await _native.app_request(
                        self.endpoint, "register", self._registration(self._target())
                    )
                except TnlError:
                    # keep the local listener running while the publisher recovers.
                    pass
            except TnlError:
                # the next renewal retries transient control or local failures.
                pass

    async def _unregister(self) -> None:
        if self._renewal is not None:
            self._renewal.cancel()
            try:
                await self._renewal
            except asyncio.CancelledError:
                pass
            self._renewal = None
        if self.registration_id and self.endpoint:
            try:
                await _native.app_request(self.endpoint, "unregister", self._registration())
            except (NativeUnavailable, RegistrationLost):
                pass
            self.registration_id = ""

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        try:
            await self._unregister()
        finally:
            await super().shutdown(sockets=sockets)


def run(
    app: str,
    *,
    service: str,
    host: str = "127.0.0.1",
    port: int = 0,
    reload: bool = False,
    directory: str | Path | None = None,
    reload_dirs: list[str] | None = None,
    log_level: str = "info",
) -> None:
    """serve a configured app from any worktree with a bound-port registration."""
    # spawn re-executes dev.py as __mp_main__; only its original process starts
    # the reload supervisor. the Uvicorn worker continues through Server.run.
    if reload and sys._getframe(1).f_globals.get("__name__") == "__mp_main__":
        return
    if (
        not isinstance(app, str)
        or not app
        or not isinstance(service, str)
        or len(service) > 32
        or _service.fullmatch(service) is None
        or host != "127.0.0.1"
        or type(port) is not int
        or not 0 <= port <= 65535
        or type(reload) is not bool
    ):
        raise TnlError("sdk.configuration_invalid", "select an app, service, and loopback listener")
    root = str(Path(directory or os.getcwd()).resolve())
    config = _uvicorn.Config(
        app,
        host=host,
        port=port,
        reload=reload,
        reload_dirs=reload_dirs,
        workers=1,
        log_level=log_level,
        ws="websockets-sansio",
    )
    server = Server(config, service, root)
    if config.should_reload:
        listener = config.bind_socket()
        try:
            ChangeReload(config, target=server.run, sockets=[listener]).run()
        finally:
            listener.close()
    else:
        server.run()
