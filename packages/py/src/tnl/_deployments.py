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
from typing import ClassVar, Literal
from urllib.parse import urlsplit

from starlette.types import ASGIApp

from ._asgi import AccessPolicy, Limits, Publication, _join_cleanup, start_publication
from ._client import ClientFactory, _Factory
from ._connections import (
    Connection,
    ConnectionAcquisition,
    HTTPConnection,
    KubernetesConnection,
    _command,
    _error,
    _object,
    _Scope,
    _text,
    _TLSConnection,
)
from ._management_client import Deployments, Management, Publishers
from ._protocol import TnlError, hostname, service_name
from ._workload import capture_workload, uses_workload

type Protocol = Literal["http", "postgres", "mysql", "tcp", "kubernetes"]


@dataclass(frozen=True, slots=True, repr=False)
class LocalPostgresConnection:
    host: str
    port: int
    ssl: ssl.SSLContext | Literal[False]
    server_hostname: str | None = None

    def __repr__(self) -> str:
        return "<tnl local PostgreSQL connection>"


@dataclass(frozen=True, slots=True, repr=False)
class LocalMySQLConnection:
    host: str
    port: int
    ssl: ssl.SSLContext | Literal[False]
    server_hostname: str | None = None
    protocol: ClassVar[Literal["mysql"]] = "mysql"

    def __repr__(self) -> str:
        return "<tnl local MySQL connection>"


@dataclass(frozen=True, slots=True, repr=False)
class LocalTCPConnection:
    host: str
    port: int
    ssl: ssl.SSLContext | Literal[False]
    server_hostname: str | None = None
    protocol: ClassVar[Literal["tcp"]] = "tcp"

    def __repr__(self) -> str:
        return "<tnl local TCP connection>"


@dataclass(frozen=True, slots=True, repr=False)
class LocalHTTPConnection:
    host: str
    port: int
    url: str
    ssl: ssl.SSLContext | Literal[False]
    server_hostname: str | None = None
    protocol: ClassVar[Literal["http"]] = "http"

    def __repr__(self) -> str:
        return "<tnl local HTTP connection>"


@dataclass(frozen=True, slots=True, repr=False)
class LocalKubernetesConnection:
    server: str
    kubeconfig: str
    context: str
    protocol: ClassVar[Literal["kubernetes"]] = "kubernetes"

    def __repr__(self) -> str:
        return "<tnl local Kubernetes connection>"


type LocalConnection = (
    LocalPostgresConnection
    | LocalMySQLConnection
    | LocalTCPConnection
    | LocalHTTPConnection
    | LocalKubernetesConnection
)
type DeploymentConnection = Connection | LocalConnection


class Deployment:
    def __init__(
        self, project: str, name: str, token: str | None, services: Mapping[str, Protocol]
    ) -> None:
        if re.fullmatch(r"dpl_[A-Za-z0-9]{22}", name) is None:
            service_name(name)
        self._local = name == "local"
        self._project, self._name, self._token = project, name, token
        self._environment = dict(os.environ)
        mounted = (
            self._environment.get("TNL_CONNECTION_HANDLE")
            if token is None and not self._local
            else None
        )
        source = capture_workload()
        self._workload = (
            source
            if not self._local and token is None and mounted is None and uses_workload(source)
            else None
        )
        if not self._local and token is None and mounted is None and self._workload is None:
            raise TnlError("sdk.configuration_invalid", "supply an approved deployment credential")
        self._services = dict(services)
        self._scope = _Scope(
            str(Path.cwd().resolve()),
            mounted,
            deployment=None
            if token is None
            else {
                "project": project,
                "name": name,
                "token": token,
                "services": list(services),
            },
            selection={"project": project, "name": name},
        )
        self._pid = os.getpid()
        self._acquisitions: dict[str, ConnectionAcquisition] = {}
        self._closed = False
        self._pending: set[asyncio.Task[tuple[object, DeploymentConnection]]] = set()
        self._factories: set[ClientFactory[object]] = set()
        self._closing: asyncio.Task[None] | None = None
        self._publications: set[Publication] = set()
        self._publication_tasks: set[asyncio.Task[Publication]] = set()

    def __repr__(self) -> str:
        return "<tnl deployment (private)>"

    def _validate(self, name: str) -> None:
        if self._closed or self._pid != os.getpid():
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
            acquisition = self._acquisitions.get(name)
            if acquisition is None:
                acquisition = ConnectionAcquisition(self._scope, name, self._workload)
                self._acquisitions[name] = acquisition
            connection = await acquisition.prepare()
            owner = acquisition._session
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
            if isinstance(connection, (HTTPConnection, KubernetesConnection)):
                binding += (connection.url,)
            if isinstance(connection, KubernetesConnection):
                binding += (connection.kubeconfig, connection.context)
            return binding, connection

        work = asyncio.create_task(prepare())
        self._pending.add(work)
        work.add_done_callback(self._pending.discard)
        # cancellation releases this waiter, not the thread or its cleanup owner.
        return await asyncio.shield(work)

    def _local_connection(self, name: str) -> tuple[object, LocalConnection]:
        protocol = self._services[name]
        raw = _command(
            self._scope.binary(),
            "local",
            "--directory",
            self._scope.directory,
            "--service",
            name,
            "--protocol",
            protocol,
        )
        value = _object(
            raw,
            {
                "schema",
                "protocol",
                "host",
                "port",
                "ssl",
                "binding",
                "url",
                "server",
                "kubeconfig",
                "context",
            },
        )
        host, port, binding = value.get("host"), value.get("port"), value.get("binding")
        if (
            value.get("schema") != 1
            or value.get("protocol") != protocol
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
        name_tls: str | None = None
        if "ssl" in value:
            tls = _object(value["ssl"], {"servername", "rejectUnauthorized", "ca"})
            if tls.get("rejectUnauthorized") is not True:
                raise _error("invalid")
            name_tls = hostname(tls.get("servername"))
            try:
                trust = ssl.create_default_context(cadata=_text(tls["ca"]) if "ca" in tls else None)
            except (ValueError, ssl.SSLError):
                raise _error("invalid") from None
        connection: LocalConnection
        if protocol in {"postgres", "mysql", "tcp"}:
            if any(key in value for key in ("url", "server", "kubeconfig", "context")):
                raise _error("invalid")
            if protocol == "postgres":
                connection = LocalPostgresConnection(host, port, trust, name_tls)
            elif protocol == "mysql":
                connection = LocalMySQLConnection(host, port, trust, name_tls)
            else:
                connection = LocalTCPConnection(host, port, trust, name_tls)
        elif protocol == "http":
            if any(key in value for key in ("server", "kubeconfig", "context")):
                raise _error("invalid")
            url = _text(value.get("url"))
            try:
                parsed = urlsplit(url)
                if (
                    parsed.scheme != ("https" if name_tls else "http")
                    or parsed.hostname != (name_tls or host)
                    or parsed.port != port
                    or parsed.path
                    or parsed.query
                    or parsed.fragment
                    or parsed.username
                    or parsed.password
                ):
                    raise _error("invalid")
            except ValueError:
                raise _error("invalid") from None
            connection = LocalHTTPConnection(host, port, url, trust, name_tls)
        else:
            if trust is False or any(key in value for key in ("url",)):
                raise _error("invalid")
            server = _text(value.get("server"))
            kubeconfig, context = _text(value.get("kubeconfig")), _text(value.get("context"))
            server_host = f"[{host}]" if ":" in host else host
            if server != f"https://{server_host}:{port}":
                raise _error("invalid")
            connection = LocalKubernetesConnection(server, kubeconfig, context)
        return binding, connection

    async def connect(self, name: str) -> DeploymentConnection:
        return (await self._acquire(name))[1]

    async def publish(
        self,
        first: str | ASGIApp,
        app: ASGIApp | None = None,
        *,
        access: Literal["restricted", "anonymous"] | AccessPolicy | None = None,
        limits: Limits | None = None,
        require_post_quantum: bool | None = None,
        telemetry: bool = True,
    ) -> Publication:
        if self._closed or self._pid != os.getpid():
            raise _error("closed")
        if not self._local and self._token is None:
            raise TnlError(
                "sdk.configuration_invalid", "publication requires a registered credential"
            )
        if len(self._publications) + len(self._publication_tasks) >= 64:
            raise TnlError("sdk.client_capacity", "close an unused publication")
        service = first if isinstance(first, str) else None
        application = first if service is None else app
        if not callable(application) or service is None and app is not None:
            raise TnlError(
                "sdk.configuration_invalid", "pass an ASGI app, optionally after a service name"
            )
        if require_post_quantum is not None and type(require_post_quantum) is not bool:
            raise TnlError("sdk.configuration_invalid", "require_post_quantum must be a boolean")
        if service is not None:
            service_name(service)
            if (
                self._services
                and self._services.get(service) != "http"
                or access is not None
                or limits is not None
                or require_post_quantum is not None
            ):
                raise TnlError(
                    "sdk.configuration_invalid",
                    "named HTTP publication uses saved policy and limits",
                )
        selection = (
            None
            if self._local
            else {"project": self._project, "name": self._name, "credential": self._token or ""}
        )
        if selection is not None and service is not None:
            selection["service"] = service

        async def create() -> Publication:
            publication = await start_publication(
                application,
                directory=self._scope.directory,
                state_dir=self._environment.get("TNL_STATE_DIR"),
                access=access,
                limits=limits,
                require_post_quantum=require_post_quantum or False,
                telemetry=telemetry,
                deployment=selection,
                service=service if self._local else None,
                on_close=self._publications.discard,
                on_start=self._publications.add,
                environment=self._environment,
            )
            if self._closed:
                await publication.aclose()
                raise _error("closed")
            self._publications.add(publication)
            return publication

        work = asyncio.create_task(create())
        self._publication_tasks.add(work)
        work.add_done_callback(self._publication_tasks.discard)
        try:
            return await asyncio.shield(work)
        except asyncio.CancelledError as primary:
            work.cancel()
            try:
                publication = await _join_cleanup(work)
                await _join_cleanup(asyncio.create_task(publication.aclose()))
            except asyncio.CancelledError:
                raise primary from None
            except BaseException as cleanup:
                raise BaseExceptionGroup(
                    "publication cancellation and cleanup failed", [primary, cleanup]
                ) from None
            raise

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
            publication_tasks = tuple(self._publication_tasks)
            for work in publication_tasks:
                work.cancel()
            publication_results = await asyncio.gather(*publication_tasks, return_exceptions=True)
            failures.extend(
                value
                for value in publication_results
                if isinstance(value, BaseException)
                and not isinstance(value, asyncio.CancelledError)
                and not (isinstance(value, TnlError) and value.code == "sdk.connection_closed")
            )
            for publication in tuple(self._publications):
                try:
                    await publication.aclose()
                except BaseException as error:
                    failures.append(error)
                else:
                    try:
                        await publication.wait()
                    except BaseException as error:
                        failures.append(error)
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
            for acquisition in self._acquisitions.values():
                try:
                    await acquisition.aclose()
                except BaseException as error:
                    failures.append(error)
            try:
                await asyncio.to_thread(self._scope.stop)
            except BaseException as error:
                failures.append(error)
            if failures:
                raise BaseExceptionGroup("deployment cleanup failed", failures)

        if self._closing is None:
            self._closing = asyncio.create_task(cleanup())
        closing = self._closing
        try:
            await asyncio.shield(closing)
        finally:
            if closing.done() and self._closing is closing:
                self._closing = None

    async def __aenter__(self) -> Deployment:
        if self._closed:
            raise _error("closed")
        return self

    async def __aexit__(self, _type: object, primary: object, _traceback: object) -> None:
        try:
            await self.aclose()
        except BaseException as cleanup:
            if isinstance(primary, BaseException):
                raise BaseExceptionGroup(
                    "deployment operation and cleanup failed", [primary, cleanup]
                ) from None
            raise


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
