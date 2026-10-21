"""typed snapshots over the native connection owner's bounded CLI contract."""

from __future__ import annotations

import asyncio
import atexit
import json
import os
import selectors
import ssl
import subprocess
import threading
import time
from collections.abc import Generator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Literal, cast
from urllib.parse import urlsplit

from ._native import native_binary
from ._protocol import TnlError, hostname, service_name

_MAX_BYTES = 128 << 10
_TIMEOUT = 65.0


def _error(code: str) -> TnlError:
    messages = {
        "invalid": "the native connection response is invalid; update the tnl wheel",
        "input": "select a declared service name and an existing project directory",
        "not_prepared": "prepare connections first or await tnl.connect(service)",
        "unavailable": "native connection failed; check the prepared handle and tnl sign-in",
        "expired": "the connection snapshot expired; read it again before opening a connection",
        "closed": "the connection handle is closed; create a new handle",
    }
    return TnlError("sdk.connection_" + code, messages[code])


@dataclass(frozen=True, slots=True, repr=False)
class _ConnectionSettings:
    host: str
    port: int
    expires_at: datetime

    def __repr__(self) -> str:
        return "<tnl connection (private)>"


@dataclass(frozen=True, slots=True, repr=False)
class _TLSConnection(_ConnectionSettings):
    ssl: ssl.SSLContext
    server_hostname: str
    ca: str | None


@dataclass(frozen=True, slots=True, repr=False)
class PostgresConnection(_TLSConnection):
    protocol: ClassVar[Literal["postgres"]] = "postgres"


@dataclass(frozen=True, slots=True, repr=False)
class MySQLConnection(_TLSConnection):
    protocol: ClassVar[Literal["mysql"]] = "mysql"


@dataclass(frozen=True, slots=True, repr=False)
class TCPConnection(_ConnectionSettings):
    protocol: ClassVar[Literal["tcp"]] = "tcp"


@dataclass(frozen=True, slots=True, repr=False)
class HTTPConnection(_TLSConnection):
    url: str
    protocol: ClassVar[Literal["http"]] = "http"


@dataclass(frozen=True, slots=True, repr=False)
class KubernetesConnection(_TLSConnection):
    url: str
    kubeconfig: str
    context: str
    protocol: ClassVar[Literal["kubernetes"]] = "kubernetes"


type Connection = (
    PostgresConnection | MySQLConnection | TCPConnection | HTTPConnection | KubernetesConnection
)
type _TLSConnections = PostgresConnection | MySQLConnection | HTTPConnection | KubernetesConnection


def _object(value: object, allowed: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) - allowed:
        raise _error("invalid")
    return cast(dict[str, object], value)


def _text(value: object) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        raise _error("invalid")
    return value


def _expiry(value: object) -> datetime:
    try:
        result = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise _error("invalid")
        if result <= datetime.now(UTC):
            raise _error("expired")
        return result
    except ValueError:
        raise _error("invalid") from None


def _snapshot(value: object) -> Connection:
    obj = _object(
        value,
        {"schema", "protocol", "host", "port", "ssl", "url", "kubeconfig", "context", "expires_at"},
    )
    if type(obj.get("schema")) is not int or obj["schema"] != 1:
        raise _error("invalid")
    port = obj.get("port")
    if obj.get("host") != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
        raise _error("invalid")
    protocol = obj.get("protocol")
    if not isinstance(protocol, str):
        raise _error("invalid")
    plain = ("127.0.0.1", port, _expiry(obj.get("expires_at")))
    if protocol == "tcp":
        if any(key in obj for key in ("ssl", "url", "kubeconfig", "context")):
            raise _error("invalid")
        return TCPConnection(*plain)
    tls = _object(obj.get("ssl"), {"servername", "rejectUnauthorized", "ca"})
    if tls.get("rejectUnauthorized") is not True:
        raise _error("invalid")
    try:
        name = hostname(tls.get("servername"))
        ca = _text(tls["ca"]) if "ca" in tls else None
        context = ssl.create_default_context(cadata=ca)
    except (TnlError, ValueError, ssl.SSLError):
        raise _error("invalid") from None
    # the Python API deliberately exposes no client certificate or key. native
    # connection admission and renewal remain in the native owner.
    fields = (*plain, context, name, ca)
    if protocol in {"postgres", "mysql"}:
        if any(key in obj for key in ("url", "kubeconfig", "context")):
            raise _error("invalid")
        if protocol == "postgres":
            return PostgresConnection(*fields)
        return MySQLConnection(*fields)
    url = _text(obj.get("url"))
    try:
        parsed = urlsplit(url)
        if (
            parsed.hostname != name
            or parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or url != f"https://{name}" + (f":{parsed.port}" if parsed.port is not None else "")
        ):
            raise _error("invalid")
    except ValueError:
        raise _error("invalid") from None
    if protocol == "http" and not any(key in obj for key in ("kubeconfig", "context")):
        return HTTPConnection(*fields, url)
    if protocol == "kubernetes":
        return KubernetesConnection(
            *fields, url, _text(obj.get("kubeconfig")), _text(obj.get("context"))
        )
    raise _error("invalid")


def _prepared(value: object, service: str) -> Connection:
    obj = _object(value, {"schema", "public_runtime", "connection"})
    if type(obj.get("schema")) is not int or obj["schema"] != 1:
        raise _error("invalid")
    project = _object(
        obj.get("public_runtime"),
        {"dev", "namespace", "services", "worktree", "oauth", "webhooks", "aliases"},
    )
    services = project.get("services")
    if type(project.get("dev")) is not bool or not isinstance(services, dict) or len(services) > 32:
        raise _error("invalid")
    try:
        hostname(project.get("namespace"))
        metadata = _object(
            services.get(service),
            {"protocol", "namespace", "hostname", "port", "public", "url", "paths"},
        )
        hostname(metadata.get("namespace"))
        name = hostname(metadata.get("hostname"))
    except TnlError as cause:
        raise _error("invalid") from cause
    port = metadata.get("port")
    if type(port) is not int or not 1 <= port <= 65535 or type(metadata.get("public")) is not bool:
        raise _error("invalid")
    connection = _snapshot(obj.get("connection"))
    if (
        metadata.get("protocol") != connection.protocol
        or isinstance(connection, _TLSConnection)
        and name != connection.server_hostname
        or isinstance(connection, (HTTPConnection, KubernetesConnection))
        and metadata.get("url") != connection.url
    ):
        raise _error("invalid")
    return connection


def _command(binary: Path, *arguments: str) -> object:
    """bound stdout in memory and time; never print native stderr or responses."""
    try:
        with subprocess.Popen(
            [str(binary), "--no-telemetry", "runtime", "connections", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ) as child:
            assert child.stdout is not None
            try:
                deadline = time.monotonic() + _TIMEOUT
                data = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not selector.select(remaining):
                            raise _error("unavailable")
                        chunk = os.read(child.stdout.fileno(), 8192)
                        if not chunk:
                            break
                        data.extend(chunk)
                        if len(data) > _MAX_BYTES:
                            raise _error("invalid")
                child.wait(timeout=max(0.001, deadline - time.monotonic()))
                if child.returncode:
                    raise _error("unavailable")
                result: object = json.loads(data)
                return result
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
    except (OSError, subprocess.TimeoutExpired):
        raise _error("unavailable") from None
    except (ValueError, UnicodeDecodeError):
        raise _error("invalid") from None


class _Session:
    def __init__(self, directory: str, service: str, mounted: str | None) -> None:
        self.directory = directory
        self.service = service
        self.mounted = mounted
        self.handle = mounted
        self.binary: Path | None = None
        self.owned = False
        self.closed = False
        self.failure: TnlError | None = None
        self.lock = threading.RLock()

    def read(self, prepare: bool = False) -> Connection:
        with self.lock:
            started = False
            if self.closed:
                raise _error("closed")
            if self.failure is not None:
                raise self.failure
            if self.handle is None and not prepare:
                raise _error("not_prepared")
            if self.binary is None:
                self.binary = native_binary().resolve(strict=True)
            if self.handle is None:
                try:
                    status = _object(
                        _command(
                            self.binary,
                            "start",
                            "--directory",
                            self.directory,
                            "--parent-pid",
                            str(os.getpid()),
                            "--service",
                            self.service,
                        ),
                        {
                            "schema",
                            "state",
                            "pid",
                            "expires_at",
                            "public_runtime",
                            "private_handle",
                            "executable",
                            "kubeconfig",
                            "reason",
                        },
                    )
                    handle = _text(status.get("private_handle"))
                    if (
                        type(status.get("schema")) is not int
                        or status["schema"] != 1
                        or status.get("state") != "ready"
                        or type(status.get("pid")) is not int
                        or cast(int, status["pid"]) <= 0
                        or not Path(handle).is_absolute()
                        or status.get("executable") != str(self.binary)
                        or not isinstance(status.get("public_runtime"), dict)
                    ):
                        raise _error("invalid")
                    _expiry(status.get("expires_at"))
                    self.handle, self.owned = handle, True
                    started = True
                    atexit.register(self._cleanup)
                except TnlError as error:
                    self.failure = error
                    raise
            try:
                return _prepared(
                    _command(
                        self.binary, "read", "--handle", self.handle, "--service", self.service
                    ),
                    self.service,
                )
            except TnlError as error:
                if started:
                    self.failure = error
                    try:
                        self.close()
                    except TnlError as cleanup:
                        raise error from cleanup
                raise

    def close(self) -> None:
        with self.lock:
            if self.closed:
                return
            if self.owned:
                assert self.binary is not None and self.handle is not None
                _command(self.binary, "stop", "--handle", self.handle)
            with _sessions_lock:
                self.closed = True
                key = (self.directory, self.service, self.mounted)
                if _sessions.get(key) is self:
                    del _sessions[key]
            atexit.unregister(self._cleanup)

    def _cleanup(self) -> None:
        try:
            self.close()
        except TnlError:
            # the native owner also monitors the exact Python parent process.
            pass


_sessions: dict[tuple[str, str, str | None], _Session] = {}
_sessions_lock = threading.Lock()


class ConnectionHandle[C: Connection]:
    """a lazy native handle; await for one coherent, non-awaitable snapshot."""

    def __init__(self, session: _Session, protocol: str | None = None) -> None:
        self._session = session
        self._protocol = protocol

    def __repr__(self) -> str:
        return "<tnl connection handle (private)>"

    def snapshot(self) -> C:
        """read a prepared owner's current snapshot, without startup or sign-in."""
        return self._check(self._session.read())

    def _check(self, connection: Connection) -> C:
        if self._protocol is not None and connection.protocol != self._protocol:
            raise _error("invalid")
        return cast(C, connection)

    async def _prepare(self) -> C:
        return self._check(await asyncio.to_thread(self._session.read, True))

    def __await__(self) -> Generator[object, None, C]:
        return self._prepare().__await__()

    @property
    def protocol(self) -> str:
        return self.snapshot().protocol

    @property
    def host(self) -> str:
        return self.snapshot().host

    @property
    def port(self) -> int:
        return self.snapshot().port

    @property
    def ssl(self: ConnectionHandle[_TLSConnections]) -> ssl.SSLContext:
        return self._tls().ssl

    @property
    def server_hostname(self: ConnectionHandle[_TLSConnections]) -> str:
        return self._tls().server_hostname

    @property
    def ca(self: ConnectionHandle[_TLSConnections]) -> str | None:
        return self._tls().ca

    def _tls(self) -> _TLSConnection:
        connection = self.snapshot()
        if not isinstance(connection, _TLSConnection):
            raise _error("invalid")
        return connection

    @property
    def expires_at(self) -> datetime:
        return self.snapshot().expires_at

    def close(self) -> None:
        """close the shared SDK-owned session; mounted owners stay running."""
        self._session.close()

    async def aclose(self) -> None:
        await asyncio.to_thread(self.close)


class PostgresConnectionHandle(ConnectionHandle[PostgresConnection]):
    @property
    def protocol(self) -> Literal["postgres"]:
        return self.snapshot().protocol


class MySQLConnectionHandle(ConnectionHandle[MySQLConnection]):
    @property
    def protocol(self) -> Literal["mysql"]:
        return self.snapshot().protocol


class TCPConnectionHandle(ConnectionHandle[TCPConnection]):
    @property
    def protocol(self) -> Literal["tcp"]:
        return self.snapshot().protocol


class HTTPConnectionHandle(ConnectionHandle[HTTPConnection]):
    @property
    def protocol(self) -> Literal["http"]:
        return self.snapshot().protocol

    @property
    def url(self) -> str:
        return self.snapshot().url


class KubernetesConnectionHandle(ConnectionHandle[KubernetesConnection]):
    @property
    def protocol(self) -> Literal["kubernetes"]:
        return self.snapshot().protocol

    @property
    def url(self) -> str:
        return self.snapshot().url

    @property
    def kubeconfig(self) -> str:
        return self.snapshot().kubeconfig

    @property
    def context(self) -> str:
        return self.snapshot().context


def connect(
    service: str, *, directory: str | os.PathLike[str] | None = None
) -> ConnectionHandle[Connection]:
    """select a service without starting native or reading credentials."""
    try:
        name = service_name(service)
        root = Path(directory if directory is not None else os.getcwd()).resolve(strict=True)
        mounted = os.environ.get("TNL_CONNECTION_HANDLE")
        if not root.is_dir() or mounted is not None and not Path(mounted).is_absolute():
            raise _error("input")
    except (TnlError, OSError, ValueError, TypeError):
        raise _error("input") from None
    key = (str(root), name, mounted)
    with _sessions_lock:
        session = _sessions.get(key)
        if session is None:
            session = _Session(*key)
            _sessions[key] = session
    return ConnectionHandle(session)


class Project:
    """runtime name/protocol validation for the generated project-local facade."""

    def __init__(self, services: Mapping[str, str] | None = None) -> None:
        self._services = None if services is None else dict(services)

    def connect(
        self, service: str, *, directory: str | os.PathLike[str] | None = None
    ) -> ConnectionHandle[Connection]:
        handle = connect(service, directory=directory)
        if self._services is not None and service not in self._services:
            raise _error("input")
        if self._services is not None:
            protocol = self._services[service]
            handles: dict[str, type[ConnectionHandle[Connection]]] = {
                "postgres": PostgresConnectionHandle,
                "mysql": MySQLConnectionHandle,
                "tcp": TCPConnectionHandle,
                "http": HTTPConnectionHandle,
                "kubernetes": KubernetesConnectionHandle,
            }
            if protocol not in handles:
                raise _error("input")
            handle = handles[protocol](handle._session, protocol)
        return handle
