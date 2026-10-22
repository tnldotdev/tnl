"""typed snapshots over the native connection owner's bounded CLI contract."""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import json
import os
import selectors
import ssl
import subprocess
import threading
import time
from collections.abc import Generator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Literal, cast
from urllib.parse import urlsplit

from ._connection_ipc import OwnerIPC
from ._native import native_binary
from ._protocol import TnlError, hostname, service_name
from ._workload import Selection, select_workload, uses_workload

_MAX_BYTES = 128 << 10
_TIMEOUT = 65.0


def _error(code: str) -> TnlError:
    messages = {
        "invalid": "the native connection response is invalid; update the tnl wheel",
        "input": "select a declared service name and an existing project directory",
        "not_prepared": "prepare connections first or await tnl.connect(service)",
        "unavailable": "native connection failed; check the prepared handle and tnl sign-in",
        "expired": "the connection snapshot or owner expired; await the handle for fresh settings",
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
        {
            "schema",
            "protocol",
            "host",
            "port",
            "ssl",
            "url",
            "kubeconfig",
            "context",
            "expires_at",
            "transport_id",
        },
    )
    if type(obj.get("schema")) is not int or obj["schema"] != 1:
        raise _error("invalid")
    if "transport_id" in obj:
        transport = _text(obj["transport_id"])
        if (
            not transport.startswith("ctg_")
            or len(transport) != 26
            or not transport[4:].isascii()
            or not transport[4:].isalnum()
        ):
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
    obj = _object(value, {"schema", "project_runtime", "connection", "verification"})
    if type(obj.get("schema")) is not int or obj["schema"] != 1:
        raise _error("invalid")
    project = _object(
        obj.get("project_runtime"),
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


def _command(binary: Path, *arguments: str, input_value: object = None) -> object:
    """bound both pipes and exit by one deadline; never expose native output."""
    try:
        deadline = time.monotonic() + _TIMEOUT
        encoded = b"" if input_value is None else json.dumps(input_value).encode()
        if len(encoded) > _MAX_BYTES:
            raise _error("invalid")
        with subprocess.Popen(
            [str(binary), "--no-telemetry", "runtime", "connections", *arguments],
            stdin=subprocess.PIPE if input_value is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        ) as child:
            try:
                assert child.stdout is not None
                data = bytearray()
                with selectors.DefaultSelector() as selector:
                    os.set_blocking(child.stdout.fileno(), False)
                    selector.register(child.stdout, selectors.EVENT_READ)
                    pending = memoryview(encoded)
                    if child.stdin is not None:
                        os.set_blocking(child.stdin.fileno(), False)
                        selector.register(child.stdin, selectors.EVENT_WRITE)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise _error("unavailable")
                        for key, _ in selector.select(remaining):
                            try:
                                if key.fileobj is child.stdin:
                                    assert child.stdin is not None
                                    try:
                                        written = os.write(key.fd, pending[:4096])
                                        pending = pending[written:]
                                    except BrokenPipeError:
                                        pending = pending[len(pending) :]
                                    if not pending:
                                        selector.unregister(child.stdin)
                                        child.stdin.close()
                                else:
                                    chunk = os.read(key.fd, 8192)
                                    if not chunk:
                                        selector.unregister(child.stdout)
                                    data.extend(chunk)
                                    if len(data) > _MAX_BYTES:
                                        raise _error("invalid")
                            except BlockingIOError:
                                continue
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
        self.creator_pid = os.getpid()
        self.service = service
        self.mounted = mounted
        self.handle = mounted
        self.binary: Path | None = None
        self.owned = False
        self.expires_at: datetime | None = None
        self.closed = False
        self.failure: TnlError | None = None
        self.lock = threading.RLock()
        self.ipc: OwnerIPC | None = None
        self.context: object = None
        self.policies: set[tuple[str, str, str]] = set()

    def read(
        self,
        prepare: bool = False,
        *,
        service: str | None = None,
        selection: Selection | None = None,
    ) -> Connection:
        if self.creator_pid != os.getpid():
            raise _error("closed")
        with self.lock:
            name = service or self.service
            started = False
            if self.closed:
                raise _error("closed")
            if self.failure is not None:
                raise self.failure
            if self.owned and self.expires_at is not None and self.expires_at <= datetime.now(UTC):
                if not prepare:
                    raise _error("expired")
                # join the old owner before reusing its port. a new start uses
                # current native identity and authorization, not old credentials.
                self._stop_owner()
            if self.handle is None and not prepare:
                raise _error("not_prepared")
            if self.binary is None:
                self.binary = native_binary().resolve(strict=True)
            if self.handle is None:
                try:
                    arguments = [
                        "start",
                        "--directory",
                        self.directory,
                        "--parent-pid",
                        str(os.getpid()),
                    ]
                    private_input: object = None
                    if selection is not None:
                        arguments.extend(
                            [
                                "--workload",
                                selection.name,
                                "--workload-manifest",
                                selection.manifest,
                            ]
                        )
                        context = (
                            self.context
                            if self.context is not None
                            else _command(
                                self.binary,
                                "context",
                                "--directory",
                                self.directory,
                                "--workload",
                                selection.name,
                                "--workload-manifest",
                                selection.manifest,
                            )
                        )
                        private_input = {
                            "schema": 1,
                            "context": context,
                            "assertion": selection.assertion,
                        }
                    status = _object(
                        _command(
                            self.binary,
                            *arguments,
                            **({"input_value": private_input} if private_input is not None else {}),
                        ),
                        {
                            "schema",
                            "state",
                            "pid",
                            "expires_at",
                            "project_runtime",
                            "connection_handle",
                            "executable",
                            "kubeconfig",
                            "reason",
                        },
                    )
                    handle = _text(status.get("connection_handle"))
                    if (
                        type(status.get("schema")) is not int
                        or status["schema"] != 1
                        or status.get("state") != "ready"
                        or type(status.get("pid")) is not int
                        or cast(int, status["pid"]) <= 0
                        or not Path(handle).is_absolute()
                        or status.get("executable") != str(self.binary)
                        or not isinstance(status.get("project_runtime"), dict)
                    ):
                        raise _error("invalid")
                    self.expires_at = _expiry(status.get("expires_at"))
                    self.handle, self.owned = handle, True
                    started = True
                    atexit.register(self._cleanup)
                except TnlError as error:
                    self.failure = error
                    raise
            try:
                if prepare:
                    if self.ipc is None:
                        self.ipc = OwnerIPC(self.handle)
                    raw = self.ipc.prepare(
                        name, selection.assertion if selection is not None else None
                    )
                else:
                    raw = _command(self.binary, "read", "--handle", self.handle, "--service", name)
                return _prepared(raw, name)
            except TnlError as error:
                if prepare and self.owned and not started:
                    try:
                        recovered = _object(
                            _command(self.binary, "recover", "--handle", self.handle),
                            {"schema", "state"},
                        )
                        if recovered.get("schema") != 1 or recovered.get("state") != "stopped":
                            raise _error("invalid")
                    except TnlError:
                        raise error from None
                    self.handle, self.owned, self.expires_at = None, False, None
                    if self.ipc is not None:
                        self.ipc.close()
                        self.ipc = None
                    atexit.unregister(self._cleanup)
                    return self.read(True, service=name, selection=selection)
                raise

    def _stop_owner(self) -> None:
        if self.creator_pid != os.getpid():
            raise _error("closed")
        assert self.binary is not None and self.handle is not None
        stopped = _object(
            _command(self.binary, "stop", "--handle", self.handle), {"schema", "state"}
        )
        if (
            type(stopped.get("schema")) is not int
            or stopped["schema"] != 1
            or stopped.get("state") != "stopped"
        ):
            raise _error("invalid")
        self.handle, self.owned, self.expires_at = None, False, None
        if self.ipc is not None:
            self.ipc.close()
            self.ipc = None
        atexit.unregister(self._cleanup)

    def close(self) -> None:
        # check before acquiring a lock possibly held by a vanished parent thread.
        if self.creator_pid != os.getpid():
            return
        with self.lock:
            if self.closed:
                return
            if self.owned:
                self._stop_owner()
            if self.ipc is not None:
                self.ipc.close()
                self.ipc = None
            with _sessions_lock:
                self.closed = True
                key = (self.directory, self.service, self.mounted)
                if _sessions.get(key) is self:
                    del _sessions[key]
                for token, (scope, _) in list(_identities.items()):
                    if token[0] == self.directory and scope == self.service:
                        del _identities[token]
                _prune_policies()
            atexit.unregister(self._cleanup)

    def _cleanup(self) -> None:
        try:
            self.close()
        except TnlError:
            # the native owner also monitors the exact Python parent process.
            pass


_sessions: dict[tuple[str, str, str | None], _Session] = {}
_sessions_lock = threading.Lock()
_contexts: dict[tuple[str, str, str], object] = {}
_identities: dict[tuple[str, str, str, str], tuple[str, datetime]] = {}


@dataclass
class _PolicyLock:
    lock: threading.Lock = field(default_factory=threading.Lock)
    users: int = 0


_policy_locks: dict[tuple[str, str, str], _PolicyLock] = {}


def _after_fork() -> None:
    global _sessions_lock
    # close only this process's duplicate socket descriptors, without IPC or any
    # inherited locks. existing handle/atexit references are fenced by creator PID.
    for session in _sessions.values():
        if session.ipc is not None:
            session.ipc.discard_inherited()
    _sessions.clear()
    _contexts.clear()
    _identities.clear()
    _policy_locks.clear()
    _sessions_lock = threading.Lock()


os.register_at_fork(after_in_child=_after_fork)


def _prune_policies() -> None:
    # callers hold _sessions_lock. users includes threads waiting on a policy,
    # so removing an inactive policy cannot create two concurrent identity locks.
    active = {policy for session in _sessions.values() for policy in session.policies}
    for policy, entry in list(_policy_locks.items()):
        if not entry.users and policy not in active:
            del _policy_locks[policy]
            _contexts.pop(policy, None)
            for token in list(_identities):
                if token[:3] == policy:
                    del _identities[token]


def _workload_session(directory: str, selection: Selection) -> _Session:
    policy = (directory, selection.name, selection.policy)
    identity_key = (*policy, hashlib.sha256(selection.assertion.encode()).hexdigest())
    with _sessions_lock:
        approved = _identities.get(identity_key) if selection.assertion else None
        if approved is not None and approved[1] > datetime.now(UTC):
            cached = _sessions.get((directory, approved[0], None))
            if cached is not None and not cached.closed:
                return cached
        if policy not in _policy_locks:
            if len(_policy_locks) >= 32:
                raise _error("unavailable")
            _policy_locks[policy] = _PolicyLock()
        entry = _policy_locks[policy]
        entry.users += 1
    try:
        with entry.lock:
            return _identify_workload_session(directory, selection, policy, identity_key)
    finally:
        with _sessions_lock:
            entry.users -= 1
            _prune_policies()


def _identify_workload_session(
    directory: str,
    selection: Selection,
    policy: tuple[str, str, str],
    identity_key: tuple[str, str, str, str],
) -> _Session:
    with _sessions_lock:
        approved = _identities.get(identity_key) if selection.assertion else None
        if approved is not None and approved[1] > datetime.now(UTC):
            cached = _sessions.get((directory, approved[0], None))
            if cached is not None and not cached.closed:
                return cached
    binary = native_binary().resolve(strict=True)
    arguments = [
        "--directory",
        directory,
        "--workload",
        selection.name,
        "--workload-manifest",
        selection.manifest,
    ]
    with _sessions_lock:
        context = _contexts.get(policy)
    if context is None:
        context = _command(binary, "context", *arguments)
        with _sessions_lock:
            _contexts[policy] = context
    identity = _object(
        _command(
            binary,
            "identity",
            *arguments,
            input_value={"schema": 1, "context": context, "assertion": selection.assertion},
        ),
        {"schema", "binding", "assertion_expires_at"},
    )
    binding = _text(identity.get("binding"))
    if (
        type(identity.get("schema")) is not int
        or identity["schema"] != 1
        or len(binding) != 64
        or any(c not in "0123456789abcdef" for c in binding)
    ):
        raise _error("invalid")
    expiry = (
        _expiry(identity["assertion_expires_at"])
        if selection.assertion and "assertion_expires_at" in identity
        else None
    )
    scope = json.dumps([binding, context], sort_keys=True)
    key = (directory, scope, None)
    with _sessions_lock:
        session = _sessions.get(key)
        if session is None:
            if len(_sessions) >= 32:
                raise _error("unavailable")
            session = _Session(*key)
            session.context = context
            _sessions[key] = session
        session.policies.add(policy)
        if expiry is not None:
            for token, (_, until) in list(_identities.items()):
                if until <= datetime.now(UTC):
                    del _identities[token]
            if len(_identities) >= 256:
                del _identities[next(iter(_identities))]
            _identities[identity_key] = (scope, expiry)
        return session


class ConnectionHandle[C: Connection]:
    """a lazy native handle; await for one coherent, non-awaitable snapshot."""

    def __init__(
        self, session: _Session, protocol: str | None = None, service: str | None = None
    ) -> None:
        self._session = session
        self._protocol = protocol
        self._service = service or session.service
        self._verified_workload = False

    def __repr__(self) -> str:
        return "<tnl connection handle (private)>"

    def snapshot(self) -> C:
        """read a prepared owner's current snapshot, without startup or sign-in."""
        if uses_workload() and not self._verified_workload:
            raise _error("not_prepared")
        return self._check(self._session.read(service=self._service))

    def _check(self, connection: Connection) -> C:
        if self._protocol is not None and connection.protocol != self._protocol:
            raise _error("invalid")
        return cast(C, connection)

    async def _prepare(self) -> C:
        if self._session.creator_pid != os.getpid() or self._session.closed:
            raise _error("closed")
        selection = None
        if uses_workload():
            selection = await select_workload(self._session.directory, self._service)
            self._session = await asyncio.to_thread(
                _workload_session, self._session.directory, selection
            )
            self._verified_workload = True
        return self._check(
            await asyncio.to_thread(
                self._session.read, True, service=self._service, selection=selection
            )
        )

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
    key = (str(root), "", mounted)
    with _sessions_lock:
        session = _sessions.get(key)
        if session is None:
            session = _Session(*key)
            _sessions[key] = session
    return ConnectionHandle(session, service=name)


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
            handle = handles[protocol](handle._session, protocol, service)
        return handle
