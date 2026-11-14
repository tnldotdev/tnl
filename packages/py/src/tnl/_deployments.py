"""project-bound deployment selections over the existing native connector owner."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import ssl
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ._client import ClientFactory, _Factory
from ._connections import Connection, _command, _error, _object, _Scope, _text, _TLSConnection
from ._management_client import Deployments, Management, Publishers
from ._protocol import TnlError, hostname, service_name

type Protocol = Literal["http", "postgres", "mysql", "tcp", "kubernetes"]


@dataclass(frozen=True, slots=True, repr=False)
class LocalPostgresConnection:
    host: str
    port: int
    ssl: ssl.SSLContext | Literal[False]
    server_hostname: str | None = None

    def __repr__(self) -> str:
        return "<tnl local PostgreSQL connection>"


type DeploymentConnection = Connection | LocalPostgresConnection


class Deployment:
    def __init__(
        self, project: str, name: str, token: str | None, services: Mapping[str, Protocol]
    ) -> None:
        if re.fullmatch(r"dpl_[A-Za-z0-9]{22}", name) is None:
            service_name(name)
        self._local = name == "local"
        if not self._local and token is None:
            raise TnlError("sdk.configuration_invalid", "supply an approved deployment credential")
        self._services = dict(services)
        self._scope = _Scope(
            str(Path.cwd().resolve()),
            None,
            deployment={
                "project": project,
                "name": name,
                "token": token,
                "services": list(services),
            },
        )
        self._pid = os.getpid()
        self._closed = False
        self._pending: set[asyncio.Task[tuple[object, DeploymentConnection]]] = set()
        self._factories: set[ClientFactory[object]] = set()
        self._closing: asyncio.Task[None] | None = None

    def __repr__(self) -> str:
        return "<tnl deployment (private)>"

    def _validate(self, name: str) -> None:
        if self._pid != os.getpid() or self._closed:
            raise _error("closed")
        if name not in self._services:
            raise TnlError("sdk.configuration_invalid", "select a declared service")

    async def _acquire(self, name: str) -> tuple[object, DeploymentConnection]:
        self._validate(name)
        if len(self._pending) >= 64:
            raise _error("unavailable")

        async def prepare() -> tuple[object, DeploymentConnection]:
            if self._local:
                value = await asyncio.to_thread(self._local_connection, name)
                if self._closed:
                    raise _error("closed")
                return value
            connection, owner = await asyncio.to_thread(self._scope.prepare, name, None)
            if self._closed:
                raise _error("closed")
            if connection.protocol != self._services[name]:
                raise _error("invalid")
            binding: tuple[object, ...] = (
                owner.handle,
                connection._transport_id,
                connection.protocol,
                connection.host,
                connection.port,
            )
            if isinstance(connection, _TLSConnection):
                binding += (connection.server_hostname, connection.ca)
            return binding, connection

        work = asyncio.create_task(prepare())
        self._pending.add(work)
        work.add_done_callback(self._pending.discard)
        # cancellation releases this waiter, not the thread or its cleanup owner.
        return await asyncio.shield(work)

    def _local_connection(self, name: str) -> tuple[object, LocalPostgresConnection]:
        if self._services[name] != "postgres":
            raise TnlError(
                "sdk.configuration_invalid", "local access requires a PostgreSQL service"
            )
        raw = _command(
            self._scope.binary(),
            "local",
            "--directory",
            self._scope.directory,
            "--service",
            name,
            "--protocol",
            "postgres",
        )
        value = _object(raw, {"schema", "protocol", "host", "port", "ssl", "binding"})
        host, port, binding = value.get("host"), value.get("port"), value.get("binding")
        if (
            value.get("schema") != 1
            or value.get("protocol") != "postgres"
            or not isinstance(host, str)
            or type(port) is not int
            or not 1 <= port <= 65535
            or not isinstance(binding, str)
            or re.fullmatch(r"[0-9a-f]{64}", binding) is None
        ):
            raise _error("invalid")
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise _error("invalid")
        except ValueError:
            raise _error("invalid") from None
        trust: ssl.SSLContext | Literal[False] = False
        name_tls = None
        if "ssl" in value:
            tls = _object(value["ssl"], {"servername", "rejectUnauthorized", "ca"})
            if tls.get("rejectUnauthorized") is not True:
                raise _error("invalid")
            name_tls = hostname(tls.get("servername"))
            try:
                trust = ssl.create_default_context(cadata=_text(tls["ca"]) if "ca" in tls else None)
            except (ValueError, ssl.SSLError):
                raise _error("invalid") from None
        return binding, LocalPostgresConnection(host, port, trust, name_tls)

    async def connect(self, name: str) -> DeploymentConnection:
        return (await self._acquire(name))[1]

    def client[T](
        self,
        name: str,
        *,
        create: Callable[[DeploymentConnection], T | Awaitable[T]],
        close: Callable[[T], None | Awaitable[None]],
    ) -> ClientFactory[T]:
        self._validate(name)
        if len(self._factories) >= 64:
            raise TnlError("sdk.client_capacity", "close an unused client factory")

        async def retired() -> list[BaseException]:
            self._factories.discard(factory)
            return []

        factory = _Factory(
            lambda: self._acquire(name), create=create, close=close, finalize=retired
        )
        self._factories.add(factory)
        return factory

    async def aclose(self) -> None:
        if self._pid != os.getpid():
            return
        self._closed = True

        async def cleanup() -> None:
            failures: list[BaseException] = []
            pending = await asyncio.gather(*tuple(self._pending), return_exceptions=True)
            failures.extend(
                value
                for value in pending
                if isinstance(value, BaseException)
                and not (isinstance(value, TnlError) and value.code == "sdk.connection_closed")
            )
            for factory in tuple(self._factories):
                try:
                    await factory.aclose()
                except BaseException as error:
                    failures.append(error)
                else:
                    self._factories.discard(factory)
            try:
                await asyncio.to_thread(self._scope.stop)
            except BaseException as error:
                failures.append(error)
            if failures:
                raise BaseExceptionGroup("deployment cleanup failed", failures)

        if self._closing is None:
            self._closing = asyncio.create_task(cleanup())
        try:
            await asyncio.shield(self._closing)
        finally:
            if self._closing.done():
                self._closing = None

    async def __aenter__(self) -> Deployment:
        if self._pid != os.getpid() or self._closed:
            raise _error("closed")
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()


class Client:
    def __init__(
        self,
        *,
        project: str,
        services: Mapping[str, Mapping[str, Protocol]] | None = None,
        token: str | None = None,
    ) -> None:
        if len(project.split("/")) != 2 or any(not part for part in project.split("/")):
            raise TnlError("sdk.configuration_invalid", "select TEAM/PROJECT")
        self._project = project
        self._token = token if token is not None else os.environ.get("TNL_TOKEN")
        management = Management(project, self._token)
        self.deployments = Deployments(management)
        self.publishers = Publishers(management)
        self._services: dict[str, Protocol] = {}
        for name, facts in (services or {}).items():
            service_name(name)
            if set(facts) != {"protocol"} or facts["protocol"] not in {
                "http",
                "postgres",
                "mysql",
                "tcp",
                "kubernetes",
            }:
                raise TnlError(
                    "sdk.configuration_invalid", "service facts contain only a supported protocol"
                )
            self._services[name] = facts["protocol"]
        if len(self._services) > 32:
            raise TnlError("sdk.configuration_invalid", "select at most 32 services")

    def __repr__(self) -> str:
        return "<tnl client (private)>"

    def deployment(self, name: str) -> Deployment:
        return Deployment(self._project, name, self._token, self._services)


def create_client(
    *,
    project: str,
    services: Mapping[str, Mapping[str, Protocol]] | None = None,
    token: str | None = None,
) -> Client:
    return Client(project=project, services=services, token=token)
