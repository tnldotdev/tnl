"""typed snapshots over the connector owner's bounded CLI contract."""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import json
import os
import selectors
import ssl
import subprocess
import tempfile
import threading
import time
import weakref
from collections.abc import Generator, Mapping
from concurrent.futures import Future
from dataclasses import dataclass
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
        "invalid": "the connector connection response is invalid; update the tnl wheel",
        "input": "select a declared service name and an existing project directory",
        "not_prepared": "prepare connections first or await tnl.connect(service)",
        "unavailable": "connector connection failed; check the prepared handle and tnl sign-in",
        "expired": "the connection snapshot or owner expired; await the handle for fresh settings",
        "closed": "the connection handle is closed; create a new handle",
    }
    return TnlError("sdk.connection_" + code, messages[code])


class _RetainedStartFailure(TnlError):
    def __init__(self, reason: str, handle: str) -> None:
        value = _native_error(reason)
        super().__init__(value.code, str(value))
        self.reason = {
            "sdk.connection_invalid": "TNL_SERVER_RESPONSE_INVALID",
            "sdk.connection_expired": "TNL_CLIENT_CONNECTION_EXPIRED",
        }.get(value.code, "TNL_CLIENT_CONNECTION_UNAVAILABLE")
        self.handle = handle


def _native_error(reason: object, retained: bool = False, handle: object = None) -> TnlError:
    if retained and isinstance(reason, str):
        if (
            not isinstance(handle, str)
            or len(handle) != 81
            or handle[64] != "."
            or any(char not in "0123456789abcdef" for char in handle[:64] + handle[65:])
        ):
            return _error("invalid")
        return _RetainedStartFailure(reason, handle)
    if reason in ("TNL_SERVER_RESPONSE_INVALID", "TNL_CLIENT_CONNECTION_REQUEST_INVALID"):
        return _error("invalid")
    if reason == "TNL_CLIENT_CONNECTION_EXPIRED":
        return _error("expired")
    return _error("unavailable")


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
    transport = _text(obj.get("transport_id"))
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
    # connection admission and renewal remain in the connector owner.
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
            stderr=subprocess.PIPE,
            bufsize=0,
        ) as child:
            try:
                assert child.stdout is not None
                assert child.stderr is not None
                data = bytearray()
                diagnostic = bytearray()
                with selectors.DefaultSelector() as selector:
                    os.set_blocking(child.stdout.fileno(), False)
                    selector.register(child.stdout, selectors.EVENT_READ)
                    os.set_blocking(child.stderr.fileno(), False)
                    selector.register(child.stderr, selectors.EVENT_READ)
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
                                        selector.unregister(key.fileobj)
                                    target = data if key.fileobj is child.stdout else diagnostic
                                    target.extend(chunk)
                                    if len(target) > _MAX_BYTES:
                                        raise _error("invalid")
                            except BlockingIOError:
                                continue
                child.wait(timeout=max(0.001, deadline - time.monotonic()))
                if child.returncode:
                    reason = None
                    retained = False
                    failure_handle = None
                    try:
                        problem: object = json.loads(diagnostic)
                        if isinstance(problem, dict):
                            reason = problem.get("reason")
                            retained = problem.get("sdk_retained_start_failure") is True
                            failure_handle = problem.get("sdk_failure_handle")
                    except (ValueError, UnicodeDecodeError):
                        pass
                    raise _native_error(reason, retained, failure_handle)
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
    """hold one native-selected capability; never select or replace its owner."""

    def __init__(self, scope: _Scope, handle: str | None = None) -> None:
        self.scope = scope
        self.directory = scope.directory
        self.creator_pid = os.getpid()
        self.handle = handle
        self.expires_at: datetime | None = None
        self.closed = False
        self.joined = False
        self.lock = threading.RLock()
        self.cleanup_lock = threading.Lock()
        self.changed = threading.Condition(self.lock)
        self.pending = 0
        self.attached: _Session | None = None
        self.failed: set[_Session] = set()
        self.ipc: OwnerIPC | None = None
        self.failure_handle: str | None = None

    def prepare(self, service: str, selection: Selection | None) -> tuple[Connection, _Session]:
        # the SDK joins its worker threads; native still decides which capability
        # a request selects and whether that owner can be reused or replaced.
        with self.scope.lock, self.changed:
            if self.closed:
                raise _error("closed")
            self.pending += 1
            self.scope.pending += 1
        try:
            result = self.scope.prepare(service, selection, self)
            with self.changed:
                if self.handle is None:
                    self.attached = result[1]
            return result
        finally:
            with self.scope.lock, self.changed:
                self.pending -= 1
                self.scope.pending -= 1
                self.changed.notify_all()

    def read(self, *, service: str) -> Connection:
        if self.creator_pid != os.getpid() or self.closed:
            raise _error("closed")
        selected = self
        if selected.handle is None:
            raise _error("not_prepared")
        if selected.closed:
            raise _error("closed")
        if selected.expires_at is not None and selected.expires_at <= datetime.now(UTC):
            raise _error("expired")
        return _prepared(
            _command(
                self.scope.binary(), "read", "--handle", selected.handle, "--service", service
            ),
            service,
        )

    def close(self) -> None:
        # forked children must not acquire inherited locks or stop a parent owner.
        if self.creator_pid != os.getpid():
            return
        if not self.cleanup_lock.acquire(timeout=_TIMEOUT):
            raise _error("unavailable")
        try:
            self._close()
        finally:
            self.cleanup_lock.release()

    def _close(self) -> None:
        deadline = time.monotonic() + _TIMEOUT
        with self.scope.lock, self.changed:
            if self.joined:
                return
            self.closed = True
            stop_scope = (
                self.scope.mounted is None
                and self.handle is None
                and self.failure_handle is None
                and self.attached is None
                and not self.failed
                and not self.scope.failure_handles
                and not self.scope.handles
                and self.scope.pending == self.pending
            )
        if stop_scope:
            self.scope.stop()
        with self.changed:
            while self.pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _error("unavailable")
                self.changed.wait(remaining)
            selected = self.attached or self
            failed = tuple(self.failed)
        for session in failed:
            session.close()
        if selected is not self:
            selected.close()
        elif not stop_scope:
            if self.failure_handle is not None:
                assert self.scope.registry is not None
                stopped = _command(
                    self.scope.binary(),
                    "sdk-close-failure",
                    "--registry",
                    self.scope.registry,
                    "--parent-pid",
                    str(os.getpid()),
                    "--failure-handle",
                    self.failure_handle,
                )
                self.scope.check_stopped(stopped)
                with self.scope.lock:
                    self.scope.failures = {
                        key: failure
                        for key, failure in self.scope.failures.items()
                        if failure.session is not self
                    }
            elif self.scope.mounted is None and self.handle is not None:
                stopped = _object(
                    _command(self.scope.binary(), "stop", "--handle", self.handle),
                    {"schema", "state"},
                )
                if (
                    type(stopped.get("schema")) is not int
                    or stopped["schema"] != 1
                    or stopped.get("state") != "stopped"
                ):
                    raise _error("invalid")
        with self.changed:
            if self.ipc is not None:
                self.ipc.close()
                self.ipc = None
            self.joined = True
        self.scope.prune()


class _FailureObservation:
    def __init__(self, scope: _Scope, error: _RetainedStartFailure) -> None:
        self.reason, self.handle = error.reason, error.handle
        self.reference = weakref.ref(error)
        self.session = _Session(scope)
        self.session.failure_handle = error.handle

    def error(self) -> _RetainedStartFailure:
        error = self.reference()
        if error is None:
            error = _RetainedStartFailure(self.reason, self.handle)
            self.reference = weakref.ref(error)
        return error


class _Scope:
    def __init__(self, directory: str, mounted: str | None) -> None:
        self.directory, self.mounted = directory, mounted
        self.creator_pid = os.getpid()
        self.registry: str | None = None
        self._binary: Path | None = None
        self.entry: tuple[str, OwnerIPC] | None = None
        self.pending = 0
        self.requests: dict[tuple[str, str], Future[object]] = {}
        self.failures: dict[str, _FailureObservation] = {}
        self.failure_handles: dict[str, _FailureObservation] = {}
        self.lock = threading.Lock()
        self.handles: dict[str, _Session] = {}
        self.selected = _Session(self, mounted)
        if mounted is not None:
            self.handles[mounted] = self.selected

    def binary(self) -> Path:
        with self.lock:
            if self._binary is None:
                self._binary = native_binary().resolve(strict=True)
            return self._binary

    def prepare(
        self, service: str, selection: Selection | None, requester: _Session | None = None
    ) -> tuple[Connection, _Session]:
        requested_at = datetime.now(UTC).isoformat()
        binary = self.binary()
        if self.mounted is not None:
            assert self.selected is not None
            with self.selected.lock:
                if self.selected.closed:
                    raise _error("closed")
                if self.selected.ipc is None:
                    self.selected.ipc = OwnerIPC(self.mounted)
            return _prepared(self.selected.ipc.prepare(service), service), self.selected
        with self.lock:
            if self.registry is None:
                self.registry = str(Path(tempfile.mkdtemp(prefix="tnl-sdk-")).resolve())
                atexit.register(self._cleanup)
            registry = self.registry
        if requester is not None and requester.closed:
            raise _error("closed")
        arguments = [
            "sdk-prepare",
            "--directory",
            self.directory,
            "--registry",
            registry,
            "--parent-pid",
            str(os.getpid()),
            "--selected-service",
            service,
            "--requested-at",
            requested_at,
            "--retain-start-failure",
        ]
        if selection is not None:
            arguments.extend(
                ["--workload", selection.name, "--workload-manifest", selection.manifest]
            )
        private_input = {
            "schema": 1,
            **({"assertion": selection.assertion} if selection is not None else {}),
        }
        selector = (
            "human"
            if selection is None
            else hashlib.sha256(
                json.dumps([selection.name, selection.policy, selection.assertion]).encode()
            ).hexdigest()
        )
        key = (selector, service)
        with self.lock:
            retained = self.failures.get(selector)
            if retained is not None:
                if requester is not None:
                    with requester.changed:
                        requester.failed.add(retained.session)
                raise retained.error()
            future = self.requests.get(key)
            leading = future is None
            if future is None:
                if len(self.requests) >= 64:
                    raise _error("unavailable")
                future = Future()
                self.requests[key] = future
        if leading:
            try:
                raw = self._request(
                    binary, arguments, private_input, service, selection, requested_at
                )
            except BaseException as error:
                with self.lock:
                    if isinstance(error, _RetainedStartFailure):
                        observation = self.failure_handles.get(error.handle)
                        if observation is None:
                            observation = _FailureObservation(self, error)
                            self.failure_handles[error.handle] = observation
                        if len(self.failures) >= 32:
                            self.failures.pop(next(iter(self.failures)))
                        self.failures[selector] = observation
                        error = observation.error()
                    self.requests.pop(key, None)
                future.set_exception(error)
            else:
                with self.lock:
                    self.requests.pop(key, None)
                future.set_result(raw)
        try:
            raw = future.result(timeout=_TIMEOUT)
        except TimeoutError:
            raise _error("unavailable") from None
        except _RetainedStartFailure as error:
            with self.lock:
                if requester is not None:
                    with requester.changed:
                        requester.failed.add(self.failure_handles[error.handle].session)
            raise
        value = _object(raw, {"schema", "owner", "prepared"})
        owner = _object(
            value.get("owner"),
            {
                "schema",
                "state",
                "pid",
                "expires_at",
                "project_runtime",
                "connection_handle",
                "executable",
                "kubeconfig",
            },
        )
        file = _text(owner.get("connection_handle"))
        if (
            type(value.get("schema")) is not int
            or value["schema"] != 1
            or type(owner.get("schema")) is not int
            or owner["schema"] != 1
            or owner.get("state") != "ready"
            or not Path(file).is_absolute()
            or owner.get("executable") != str(binary)
        ):
            raise _error("invalid")
        expiry = _expiry(owner.get("expires_at"))
        connection = _prepared(value.get("prepared"), service)
        with self.lock:
            session = self.selected if selection is None else self.handles.get(file)
            if session is None:
                session = _Session(self, file)
            session.handle = file
            session.expires_at = expiry
            self.handles = {
                old: held
                for old, held in self.handles.items()
                if held is not session or old == file
            }
            self.handles[file] = session
            if self.entry is None:
                self.entry = (file, OwnerIPC(file))
        if session.closed:
            raise _error("closed")
        return connection, session

    def _request(
        self,
        binary: Path,
        arguments: list[str],
        private_input: object,
        service: str,
        selection: Selection | None,
        requested_at: str,
    ) -> object:
        entry = self.entry
        if entry is None:
            raw = _command(binary, *arguments, input_value=private_input)
        else:
            try:
                raw = entry[1].prepare(
                    service,
                    selection.assertion if selection else None,
                    sdk=True,
                    workload=selection.name if selection else None,
                    manifest=selection.manifest if selection else None,
                    requested_at=requested_at,
                )
            except TnlError as original:
                try:
                    raw = _command(
                        binary, *arguments, "--recover-handle", entry[0], input_value=private_input
                    )
                except TnlError:
                    raise original from None
                with self.lock:
                    if self.entry is entry:
                        self.entry = None
                        entry[1].close()
        if isinstance(raw, dict) and "reason" in raw:
            _object(raw, {"schema", "reason", "sdk_retained_start_failure", "sdk_failure_handle"})
            if (
                type(raw.get("schema")) is not int
                or raw["schema"] != 1
                or not isinstance(raw.get("reason"), str)
            ):
                raise _error("invalid")
            raise _native_error(
                raw["reason"],
                raw.get("sdk_retained_start_failure") is True,
                raw.get("sdk_failure_handle"),
            )
        return raw

    @staticmethod
    def check_stopped(raw: object) -> None:
        stopped = _object(raw, {"schema", "state"})
        if (
            type(stopped.get("schema")) is not int
            or stopped["schema"] != 1
            or stopped.get("state") != "stopped"
        ):
            raise _error("invalid")

    def prune(self) -> None:
        # keep one scope per application boundary; joined capabilities and exit
        # hooks must not accumulate across repeated close/reopen cycles.
        with self.lock:
            self.handles = {
                file: session for file, session in self.handles.items() if not session.joined
            }
            if self.entry is not None and self.entry[0] not in self.handles:
                self.entry[1].close()
                self.entry = None
            if not self.pending:
                self.failure_handles = {
                    handle: failure
                    for handle, failure in self.failure_handles.items()
                    if not failure.session.joined
                }
            if not self.pending and not self.handles and not self.failure_handles:
                self.failures.clear()
                atexit.unregister(self._cleanup)
                self.registry = None

    def stop(self) -> None:
        if self.registry is not None:
            stopped = _object(
                _command(
                    self.binary(),
                    "sdk-stop",
                    "--registry",
                    self.registry,
                    "--parent-pid",
                    str(os.getpid()),
                ),
                {"schema", "state"},
            )
            if (
                type(stopped.get("schema")) is not int
                or stopped["schema"] != 1
                or stopped.get("state") != "stopped"
            ):
                raise _error("invalid")
            if self.entry is not None:
                self.entry[1].close()
                self.entry = None
            with self.lock:
                self.failures.clear()
                self.failure_handles.clear()

    def _cleanup(self) -> None:
        if self.creator_pid != os.getpid():
            return
        try:
            self.stop()
        except TnlError:
            # native also monitors the Python parent process.
            pass


_sessions: dict[tuple[str, str | None, str | None, str | None], _Scope] = {}
_sessions_lock = threading.Lock()


def _after_fork() -> None:
    global _sessions_lock
    # close only this process's duplicate socket descriptors, without IPC or any
    # inherited locks. existing handle/atexit references are fenced by creator PID.
    for scope in _sessions.values():
        if scope.entry is not None:
            scope.entry[1].discard_inherited()
        for session in scope.handles.values():
            if session.ipc is not None:
                session.ipc.discard_inherited()
    _sessions.clear()
    _sessions_lock = threading.Lock()


os.register_at_fork(after_in_child=_after_fork)


class ConnectionHandle[C: Connection]:
    """a lazy native handle; await for one coherent, non-awaitable snapshot."""

    def __init__(
        self, session: _Session, protocol: str | None = None, service: str | None = None
    ) -> None:
        self._session = session
        self._protocol = protocol
        assert service is not None
        self._service = service
        self._verified_workload = False

    def __repr__(self) -> str:
        return "<tnl connection handle (private)>"

    def snapshot(self) -> C:
        """read a prepared owner's current snapshot, without startup or sign-in."""
        if uses_workload() and (not self._verified_workload or self._session.handle is None):
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
        connection, session = await asyncio.to_thread(
            self._session.prepare, self._service, selection
        )
        if self._session.closed:
            raise _error("closed")
        self._session = session
        self._verified_workload = selection is not None
        return self._check(connection)

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
    key = (str(root), os.environ.get("TNL_STATE_DIR"), os.environ.get("TNL_SERVER"), mounted)
    with _sessions_lock:
        scope = _sessions.get(key)
        if scope is None:
            scope = _Scope(str(root), mounted)
            _sessions[key] = scope
        if uses_workload():
            session = _Session(scope)
        else:
            if scope.selected.closed:
                scope.selected = _Session(scope, mounted)
            session = scope.selected
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
