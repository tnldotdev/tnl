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
import uuid
import weakref
from concurrent.futures import Future
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, Literal, cast
from urllib.parse import urlsplit

from ._connection_ipc import OwnerIPC, _InterruptedError
from ._native import native_binary
from ._protocol import TnlError, _service_metadata, hostname, service_name
from ._workload import Selection, Source, select_workload

_MAX_BYTES = 128 << 10
_TIMEOUT = 65.0


def _error(code: str) -> TnlError:
    messages = {
        "invalid": "the connector connection response is invalid; update the tnl wheel",
        "unavailable": "connection failed; check the credential, workload, or job connector",
        "expired": "the connection expired; prepare the deployment connection again",
        "closed": "the deployment connection is closed; create a new deployment handle",
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


class _OwnerPreparationFailure(TnlError):
    def __init__(self, error: TnlError, handle: str) -> None:
        super().__init__(error.code, str(error))
        self.handle = handle


def _native_error(
    reason: object, retained: bool = False, handle: object = None, owner: object = None
) -> TnlError:
    if owner is not None:
        if not isinstance(owner, str) or not Path(owner).is_absolute() or "\0" in owner:
            return _error("invalid")
        return _OwnerPreparationFailure(_native_error(reason), owner)
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
    workload_errors = {
        "TNL_CLIENT_WORKLOAD_REQUIRED": "sdk.workload_required",
        "TNL_CLIENT_WORKLOAD_MANIFEST_INVALID": "sdk.workload_manifest_invalid",
        "TNL_CLIENT_WORKLOAD_SERVICE_DENIED": "sdk.workload_denied",
        "TNL_CLIENT_WORKLOAD_ASSERTION_UNAVAILABLE": "sdk.workload_assertion_unavailable",
    }
    if isinstance(reason, str) and reason in workload_errors:
        return TnlError(workload_errors[reason], "native workload selection or acquisition failed")
    return _error("unavailable")


@dataclass(frozen=True, slots=True, repr=False)
class _ConnectionSettings:
    host: str
    port: int
    expires_at: datetime
    _transport_id: str = field(default="", kw_only=True, repr=False, compare=False)

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
        return TCPConnection(*plain, _transport_id=transport)
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
            return PostgresConnection(*fields, _transport_id=transport)
        return MySQLConnection(*fields, _transport_id=transport)
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
        return HTTPConnection(*fields, url, _transport_id=transport)
    if protocol == "kubernetes":
        return KubernetesConnection(
            *fields,
            url,
            _text(obj.get("kubeconfig")),
            _text(obj.get("context")),
            _transport_id=transport,
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
        metadata = _service_metadata(service, services.get(service))
        name = hostname(metadata.get("hostname"))
    except TnlError as cause:
        raise _error("invalid") from cause
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
    acknowledged = False
    try:
        deadline = time.monotonic() + _TIMEOUT
        encoded = b"" if input_value is None else json.dumps(input_value).encode()
        if len(encoded) > _MAX_BYTES:
            raise _error("invalid")
        with subprocess.Popen(
            [str(binary), "runtime", "connections", *arguments],
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
                    owner_handle = None
                    try:
                        problem: object = json.loads(diagnostic)
                        if isinstance(problem, dict):
                            reason = problem.get("reason")
                            retained = problem.get("sdk_retained_start_failure") is True
                            failure_handle = problem.get("sdk_failure_handle")
                            owner_handle = problem.get("sdk_owner_handle")
                    except (ValueError, UnicodeDecodeError):
                        pass
                    acknowledged = isinstance(reason, str)
                    raise _native_error(reason, retained, failure_handle, owner_handle)
                result: object = json.loads(data)
                return result
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeDecodeError, TnlError) as cause:
        error = (
            cause
            if isinstance(cause, TnlError)
            else _error(
                "unavailable"
                if isinstance(cause, (OSError, subprocess.TimeoutExpired))
                else "invalid"
            )
        )
        if (
            arguments
            and arguments[0] == "sdk-prepare"
            and (
                not acknowledged
                or error.code == "sdk.connection_invalid"
                and not isinstance(error, (_OwnerPreparationFailure, _RetainedStartFailure))
            )
        ):
            error = _InterruptedError(error.code, str(error))
        raise error from None


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
        self.preparations: set[_Session] = set()
        self.initial_session: _Session | None = None
        self.ipc: OwnerIPC | None = None
        self.failure_handle: str | None = None
        self.request_handle: str | None = None
        self.interrupted = False

    def resolve_request(self, target: _Session | None) -> None:
        with self.changed:
            reference = self.request_handle
            if reference is None:
                return
            self.request_handle = None
            self.attached = target
            if target is None:
                self.joined = True
        receipt = Path(reference)
        for file in (
            receipt,
            Path(reference + ".lock"),
            *receipt.parent.glob(receipt.name + ".write-*"),
        ):
            file.unlink(missing_ok=True)
        with self.scope.lock:
            self.scope.request_handles.pop(reference, None)

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

    def cleanup_targets(self) -> set[_Session]:
        with self.changed:
            if self.joined:
                return set()
            if self.pending or any((self.handle, self.failure_handle, self.request_handle)):
                return {self}
            children = self.failed | self.preparations
            if self.attached is not None:
                children = children | {self.attached}
        return {target for child in children for target in child.cleanup_targets()}

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
        with self.changed:
            while self.pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _error("unavailable")
                self.changed.wait(remaining)
            if self.joined:
                return
            selected = self.attached or self
            failed = tuple(self.failed)
            preparations = tuple(self.preparations)
        for preparation in preparations:
            preparation.close()
        for session in failed:
            session.close()
        if selected is not self:
            selected.close()
        elif self.scope.mounted is None:
            reference = (
                ["--request-handle", self.request_handle]
                if self.request_handle is not None
                else ["--failure-handle", self.failure_handle]
                if self.failure_handle is not None
                else ["--handle", self.handle]
                if self.handle is not None
                else []
            )
            if reference:
                assert self.scope.registry is not None
                self.scope.check_stopped(
                    _command(
                        self.scope.binary(),
                        "sdk-close",
                        "--registry",
                        self.scope.registry,
                        "--parent-pid",
                        str(os.getpid()),
                        *reference,
                    )
                )
                if self.request_handle is not None:
                    self.resolve_request(None)
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
    def __init__(
        self,
        directory: str,
        mounted: str | None,
        *,
        deployment: dict[str, object] | None = None,
        selection: dict[str, str] | None = None,
    ) -> None:
        self.directory, self.mounted = directory, mounted
        self.deployment = deployment
        self.selection = None if selection is None else dict(selection)
        self.creator_pid = os.getpid()
        self.registry: str | None = None
        self._binary: Path | None = None
        self.entry: tuple[str, OwnerIPC] | None = None
        self.pending = 0
        self.requests: dict[
            tuple[str, str], tuple[Future[tuple[Connection, _Session]], _Session]
        ] = {}
        self.request_handles: dict[str, _Session] = {}
        self.failure_handles: dict[str, _FailureObservation] = {}
        self.lock = threading.Lock()
        self.handles: dict[str, _Session] = {}
        self.selected = _Session(self, mounted)
        if mounted is not None:
            self.handles[mounted] = self.selected
        _scopes.add(self)

    def binary(self) -> Path:
        with self.lock:
            if self._binary is None:
                self._binary = native_binary().resolve(strict=True)
            return self._binary

    def prepare(
        self, service: str, selection: Selection | None, requester: _Session | None = None
    ) -> tuple[Connection, _Session]:
        requested_at = datetime.now(UTC).isoformat()
        if self.mounted is not None:
            assert self.selected is not None
            with self.selected.lock:
                if self.selected.closed:
                    raise _error("closed")
                if self.selected.ipc is None:
                    self.selected.ipc = OwnerIPC(self.mounted)
            expected: dict[str, object] | None = (
                None if self.selection is None else {"selection": self.selection}
            )
            return _prepared(
                self.selected.ipc.prepare(service, selection=expected), service
            ), self.selected
        binary = self.binary()
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
        private_input = {
            "schema": 1,
            **(selection.private_input() if selection is not None else {}),
            **({"deployment": self.deployment} if self.deployment is not None else {}),
        }
        selector = (
            "human"
            if selection is None
            else hashlib.sha256(
                json.dumps([selection.name, selection.policy, selection.assertion]).encode()
            ).hexdigest()
        )
        key = (selector, service)
        if selection is not None and selection.assertion is None:
            # native must acquire this request's current token before coalescing
            # owner startup by verified identity. no SDK assertion cache applies.
            selector = uuid.uuid4().hex
            key = (selector, service)
        with self.lock:
            entry = self.requests.get(key)
            leading = entry is None
            if entry is None:
                self.request_handles = {
                    path: held
                    for path, held in self.request_handles.items()
                    if held.request_handle is not None and not held.joined
                }
                if len(self.requests) >= 64 or len(self.request_handles) >= 64:
                    raise _error("unavailable")
                request = _Session(self)
                reference = str(Path(registry) / ("request-" + uuid.uuid4().hex + ".json"))
                try:
                    with open(
                        reference, "x", opener=lambda path, flags: os.open(path, flags, 0o600)
                    ) as file:
                        json.dump({"schema": 1, "parent_pid": os.getpid()}, file)
                except OSError:
                    raise _error("unavailable") from None
                request.request_handle = reference
                request.pending = 1
                entry = (Future(), request)
                self.requests[key] = entry
                self.request_handles[reference] = request
            future, request = entry
            if requester is not None:
                with requester.changed:
                    requester.failed.add(request)
        if leading:
            received = False
            try:
                raw = self._request(
                    binary,
                    arguments,
                    private_input,
                    service,
                    selection,
                    requested_at,
                    request,
                )
                received = True
                result = self._selected(raw, binary, service, selection, request)
            except BaseException as error:
                with self.lock:
                    target = None
                    if isinstance(error, _RetainedStartFailure):
                        observation = self.failure_handles.get(error.handle)
                        if observation is None:
                            observation = _FailureObservation(self, error)
                            self.failure_handles[error.handle] = observation
                        error = observation.error()
                        target = observation.session
                    elif isinstance(error, _OwnerPreparationFailure):
                        target = self.handles.setdefault(error.handle, _Session(self, error.handle))
                    self.requests.pop(key, None)
                if target is not None or (
                    not received
                    and not request.interrupted
                    and not isinstance(error, _InterruptedError)
                ):
                    request.resolve_request(target)
                future.set_exception(error)
            else:
                with self.lock:
                    self.requests.pop(key, None)
                future.set_result(result)
            finally:
                with request.changed:
                    request.pending = 0
                    request.changed.notify_all()
        try:
            connection, session = future.result(timeout=_TIMEOUT)
        except TimeoutError:
            raise _error("unavailable") from None
        except _RetainedStartFailure as error:
            with self.lock:
                if requester is not None:
                    with requester.changed:
                        requester.failed.add(self.failure_handles[error.handle].session)
            raise
        except _OwnerPreparationFailure as error:
            with self.lock:
                failed_owner = self.handles.setdefault(error.handle, _Session(self, error.handle))
                if requester is not None and failed_owner is not requester:
                    with requester.changed:
                        requester.failed.add(failed_owner)
            raise
        if requester is not None and requester is not session and requester.handle is None:
            with requester.changed:
                requester.attached = session
        if session.closed:
            raise _error("closed")
        return connection, session

    def _selected(
        self,
        raw: object,
        binary: Path,
        service: str,
        selection: Selection | None,
        request: _Session,
    ) -> tuple[Connection, _Session]:
        value = _object(raw, {"schema", "owner", "prepared"})
        owner = _object(
            value.get("owner"),
            {
                "expires_at",
                "connection_handle",
                "executable",
            },
        )
        file = _text(owner.get("connection_handle"))
        if (
            type(value.get("schema")) is not int
            or value["schema"] != 1
            or not Path(file).is_absolute()
            or owner.get("executable") != str(binary)
        ):
            raise _error("invalid")
        expiry = _expiry(owner.get("expires_at"))
        with self.lock:
            session = self.handles.get(file)
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
            if selection is None:
                self.selected = session
        request.resolve_request(session)
        with self.lock:
            if self.entry is None:
                self.entry = (file, OwnerIPC(file))
        if session.closed:
            raise _error("closed")
        connection = _prepared(value.get("prepared"), service)
        return connection, session

    def _request(
        self,
        binary: Path,
        arguments: list[str],
        private_input: object,
        service: str,
        selection: Selection | None,
        requested_at: str,
        request: _Session,
    ) -> object:
        request_handle = request.request_handle
        assert request_handle is not None
        arguments = [*arguments, "--sdk-request-handle", request_handle]
        entry = self.entry
        if entry is None:
            raw = _command(binary, *arguments, input_value=private_input)
        else:
            try:
                raw = entry[1].prepare(
                    service,
                    selection.assertion if selection else None,
                    sdk=True,
                    selection=(
                        {"deployment": self.deployment}
                        if self.deployment is not None
                        else selection.private_input()
                        if selection
                        else None
                    ),
                    requested_at=requested_at,
                    request_handle=request_handle,
                )
            except TnlError as original:
                try:
                    raw = _command(
                        binary, *arguments, "--recover-handle", entry[0], input_value=private_input
                    )
                except (_OwnerPreparationFailure, _RetainedStartFailure):
                    # the requester must retain the replacement's cleanup reference.
                    raise
                except TnlError as recovery:
                    # preserve the original IPC error object without losing the
                    # recovery command's still-unacknowledged native admission.
                    request.interrupted = isinstance(recovery, _InterruptedError)
                    raise original from None
                with self.lock:
                    if self.entry is entry:
                        self.entry = None
                        entry[1].close()
        if isinstance(raw, dict) and "reason" in raw:
            _object(
                raw,
                {
                    "schema",
                    "reason",
                    "sdk_retained_start_failure",
                    "sdk_failure_handle",
                    "sdk_owner_handle",
                },
            )
            if (
                type(raw.get("schema")) is not int
                or raw["schema"] != 1
                or not isinstance(raw.get("reason"), str)
            ):
                raise _error("invalid")
            error = _native_error(
                raw["reason"],
                raw.get("sdk_retained_start_failure") is True,
                raw.get("sdk_failure_handle"),
                raw.get("sdk_owner_handle"),
            )
            if error.code == "sdk.connection_invalid" and not isinstance(
                error, (_OwnerPreparationFailure, _RetainedStartFailure)
            ):
                request.interrupted = True
            raise error
        return raw

    def workload(self, service: str, request: dict[str, object]) -> object:
        entry = self.entry
        raw: object
        try:
            if entry is None:
                raise _error("unavailable")
            raw = entry[1].prepare(
                service, sdk=True, preview=True, selection={"sdk_workload": request}
            )
        except TnlError:
            raw = _command(
                self.binary(),
                "sdk-workload",
                "--directory",
                self.directory,
                "--service",
                service,
                input_value={"schema": 1, "sdk_workload": request},
            )
        if isinstance(raw, dict) and "reason" in raw:
            raise _native_error(raw["reason"])
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
            self.request_handles = {
                path: held
                for path, held in self.request_handles.items()
                if held.request_handle is not None and not held.joined
            }
            if (
                not self.pending
                and not self.handles
                and not self.failure_handles
                and not self.request_handles
            ):
                atexit.unregister(self._cleanup)
                self.registry = None

    def stop(self) -> None:
        if self.creator_pid != os.getpid():
            return
        if self.mounted is not None and self.selected.ipc is not None:
            self.selected.ipc.close()
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
                self.failure_handles.clear()
            atexit.unregister(self._cleanup)

    def _cleanup(self) -> None:
        if self.creator_pid != os.getpid():
            return
        try:
            self.stop()
        except TnlError:
            # native also monitors the Python parent process.
            pass


_scopes: weakref.WeakSet[_Scope] = weakref.WeakSet()


def _after_fork() -> None:
    # close only this process's duplicate socket descriptors, without IPC or any
    # inherited locks. existing handle/atexit references are fenced by creator PID.
    for scope in _scopes:
        if scope.entry is not None:
            scope.entry[1].discard_inherited()
        for session in scope.handles.values():
            if session.ipc is not None:
                session.ipc.discard_inherited()


os.register_at_fork(after_in_child=_after_fork)


class ConnectionAcquisition:
    """join selections for one service inside an explicitly owned native scope."""

    def __init__(self, scope: _Scope, service: str, workload: Source | None = None) -> None:
        service_name(service)
        session = scope.selected
        self._workload = workload
        self._session = session
        # retain every pending selection until its worker and cleanup have joined.
        self._lifetime = _Session(session.scope)
        self._lifetime.attached = session
        self._service = service

    def __repr__(self) -> str:
        return "<tnl connection acquisition (private)>"

    async def prepare(self) -> Connection:
        if (
            self._session.creator_pid != os.getpid()
            or self._lifetime.closed
            or self._session.closed
        ):
            raise _error("closed")
        unprepared = self._session if self._session.handle is None else None
        selection = None
        if self._workload is not None:
            selection = await select_workload(
                self._service,
                self._session.scope.workload,
                self._workload,
                self._session.scope.selection,
            )
        with self._lifetime.changed:
            if self._lifetime.closed:
                raise _error("closed")
            preparation = _Session(self._session.scope)
            preparation.initial_session = unprepared
            self._lifetime.preparations.add(preparation)
        try:
            connection, session = await asyncio.to_thread(
                preparation.prepare, self._service, selection
            )
        except asyncio.CancelledError:
            # cancelling the await does not join its worker. keep that exact
            # preparation for close, including a selection not returned yet.
            raise
        except BaseException:
            # the worker has finished. retain its exact capabilities once, not
            # another wrapper for every observation of the same native failure.
            targets = preparation.cleanup_targets()
            with self._lifetime.changed:
                self._lifetime.failed.update(targets)
                self._lifetime.preparations.discard(preparation)
            raise
        with self._lifetime.changed:
            if self._lifetime.closed or (
                preparation.initial_session is not None and preparation.initial_session.closed
            ):
                # retain this preparation's late owner for joined close. only
                # the initial shared session fences an alias's pending selection.
                raise _error("closed")
            self._session = session
            self._lifetime.attached = session
            self._lifetime.preparations.remove(preparation)
        return connection

    def close(self) -> None:
        """join this acquisition's selected work; leave borrowed owners running."""
        self._lifetime.close()

    async def aclose(self) -> None:
        await asyncio.to_thread(self.close)
