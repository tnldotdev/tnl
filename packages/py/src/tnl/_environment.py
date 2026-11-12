"""native environment selection; wire shapes are owned by connector/runtime/contract.go."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from ._connection_ipc import OwnerIPC
from ._connections import _error, _expiry, _object, _prepared, _ResolvedService, _text
from ._native import native_binary
from ._protocol import TnlError, hostname
from ._service_facts import ServiceFacts
from ._identity import IdentitySource, OIDCAssertion
from ._identity_models import IdentitySourceChallenge, IdentitySourceReply
from ._identity_validation import is_challenge

_START_TIMEOUT = 40.0


@dataclass(frozen=True, slots=True)
class EnvironmentReference:
    server: str
    project_key: str
    environment_id: str

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.server)
            host = parsed.hostname
            if host is None or "%" in host:
                raise ValueError("missing server")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                host = hostname(host)
            else:
                host = f"[{address.compressed}]" if address.version == 6 else address.compressed
            port = parsed.port
            canonical = "https://" + host + (f":{port}" if port is not None and port != 443 else "")
            if parsed.username is not None or parsed.password is not None or self.server != canonical or port is not None and not 1 <= port <= 65535:
                raise ValueError("noncanonical server")
        except (TypeError, ValueError, TnlError):
            raise _error("input") from None
        if not isinstance(self.project_key, str) or not isinstance(self.environment_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", self.project_key) or not re.fullmatch(r"env_[A-Za-z0-9]{22}", self.environment_id):
            raise _error("input")

    def _wire(self) -> dict[str, str]:
        return {
            "server": self.server,
            "project_key": self.project_key,
            "environment_id": self.environment_id,
        }


@dataclass(slots=True)
class _NativeOwner:
    process: asyncio.subprocess.Process
    service: str
    protocol: str
    ipc: OwnerIPC | None = None
    binding: dict[str, object] | None = None
    stopped: bool = False
    public_key: str | None = None
    session_id: str | None = None
    initial: bool = True
    gate: asyncio.Lock = field(default_factory=asyncio.Lock)
    cleanup_confirmed: bool = False


class _NativeSelection:
    def __init__(
        self, services: ServiceFacts, environment: EnvironmentReference, identity: IdentitySource
    ) -> None:
        self._facts = ServiceFacts(services)
        if not isinstance(environment, EnvironmentReference) or not isinstance(
            identity, IdentitySource
        ):
            raise _error("input")
        self.environment = environment
        self.identity = identity
        if identity.permission_id is None:
            raise _error("input")
        self._startup = identity._startup()
        self._callback = identity.assertion
        self._owners: list[_NativeOwner] = []
        self._starts: dict[str, asyncio.Task[_ResolvedService]] = {}
        self._workers: set[asyncio.Task[object]] = set()
        self._abandoned: set[asyncio.Task[object]] = set()
        self._terminal: list[BaseException] = []
        self._sources: set[asyncio.Task[str]] = set()
        self._abandoned_sources: set[asyncio.Task[str]] = set()
        self._source_failures: dict[asyncio.Task[str], BaseException] = {}
        self._closed = False
        self._observed_start_failures: set[BaseException] = set()

    def _selection(self, service: str, protocol: str) -> dict[str, object]:
        return {
            "environment": self.environment._wire(),
            "permission_id": self.identity.permission_id,
            "services": {service: protocol},
        }

    async def _proof(
        self, raw: object, owner: _NativeOwner, operation: Literal["visitor_prepare", "visitor_attach"]
    ) -> IdentitySourceReply:
        if not is_challenge(raw):
            raise _error("invalid")
        obj = raw
        audience = obj["audience"]
        prepare_audience = (
            f"{self.environment.server}/v1/projects/{self.environment.project_key}"
            f"/environments/{self.environment.environment_id}/visitors/prepare"
        )
        attach_prefix = self.environment.server + "/v1/environment-visitor-sessions/"
        if (
            obj.get("schema") != 1
            or type(obj.get("schema")) is not int
            or obj.get("operation") != operation
            or obj["server"] != self.environment.server
            or obj["source"] != self.identity._selector()
            or (_expiry(obj["expires_at"]) - datetime.now(UTC)).total_seconds() > 60
            or owner.public_key is not None and owner.public_key != obj["native_public_key"]
            or owner.session_id is not None and owner.session_id != obj.get("session_id")
            or obj.get("selection") != self._selection(owner.service, owner.protocol)
            or (
                audience != prepare_audience
                if operation == "visitor_prepare"
                else not audience.startswith(attach_prefix)
                or not re.fullmatch(
                    r"wls_[A-Za-z0-9]{22}/assertions", audience[len(attach_prefix) :]
                )
            )
        ):
            raise _error("invalid")
        owner.public_key = obj["native_public_key"]
        if "session_id" in obj:
            owner.session_id = obj["session_id"]
        value = await self._acquire(obj)
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 32768
            or re.search(r"\s|\0", value)
        ):
            raise _error("input")
        return {"schema": 1, "challenge_id": obj["id"], "assertion": value}

    async def _acquire(self, challenge: IdentitySourceChallenge) -> str:
        if len(self._sources) >= 64 or len(self._source_failures) >= 64:
            raise _error("unavailable")

        async def invoke() -> str:
            if self._callback is None:
                raise _error("input")
            proof = await self._callback()
            if not isinstance(proof, OIDCAssertion):
                raise _error("input")
            return proof.token

        call = asyncio.create_task(invoke())
        self._sources.add(call)

        def finished(done: asyncio.Task[str]) -> None:
            self._sources.discard(done)
            if not done.cancelled():
                error = done.exception()
                if done in self._abandoned_sources and error is not None:
                    self._source_failures[done] = error
            self._abandoned_sources.discard(done)

        def abandon() -> None:
            if call.done():
                if not call.cancelled():
                    error = call.exception()
                    if error is not None:
                        self._source_failures[call] = error
            else:
                self._abandoned_sources.add(call)
                call.cancel()

        call.add_done_callback(finished)
        try:
            done, _ = await asyncio.wait({call}, timeout=max(0, min(10, (_expiry(challenge["expires_at"]) - datetime.now(UTC)).total_seconds())))
            if not done:
                abandon()
                raise TimeoutError("identity source deadline exceeded")
            return call.result()
        except asyncio.CancelledError:
            abandon()
            raise

    async def _line(self, stream: asyncio.StreamReader) -> object:
        line = await stream.readline()
        if not line or len(line) > 128 << 10:
            raise _error("invalid")
        try:
            result: object = json.loads(line)
        except (ValueError, UnicodeError):
            raise _error("invalid") from None
        return result

    async def _join(self, process: asyncio.subprocess.Process) -> int:
        waiting = asyncio.create_task(process.wait())
        done, _ = await asyncio.wait({waiting}, timeout=20)
        if not done:
            process.kill()
            await waiting
            raise TimeoutError("native environment owner did not join cleanup")
        return waiting.result()

    async def _start(self, service: str) -> _ResolvedService:
        self._owners = [owner for owner in self._owners if not owner.stopped]
        if self._closed or len(self._owners) >= 32 or service not in self._facts:
            raise _error("input")
        protocol = self._facts[service]["protocol"]
        binary = native_binary().resolve(strict=True)
        child_environment = dict(os.environ)
        for key in ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "VERCEL_OIDC_TOKEN", "VERCEL_OIDC_TOKEN_FILE", "VERCEL_TOKEN"):
            child_environment.pop(key, None)
        if self.identity.acquisition is not None and self.identity.acquisition.method == "token-env":
            child_environment.pop(self.identity.acquisition.token_env, None)
        process = await asyncio.create_subprocess_exec(
            str(binary),
            "--no-telemetry",
            "runtime",
            "connections",
            "environment-serve",
            "--parent-pid",
            str(os.getpid()),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=(128 << 10) + 1,
            env=child_environment,
        )
        owner = _NativeOwner(process, service, protocol)
        self._owners.append(owner)
        assert process.stdin is not None and process.stdout is not None
        try:
            async with asyncio.timeout(_START_TIMEOUT):
                startup = {**self._startup}
                if self.identity.acquisition is not None:
                    _, startup["source_environment"] = self.identity.acquisition._capture()
                process.stdin.write(
                    json.dumps(
                        {"schema": 1, "selection": self._selection(service, protocol), **startup}
                    ).encode()
                    + b"\n"
                )
                await process.stdin.drain()
                if self._callback is not None:
                    reply = await self._proof(await self._line(process.stdout), owner, "visitor_prepare")
                    process.stdin.write(json.dumps(reply).encode() + b"\n")
                    await process.stdin.drain()
                process.stdin.close()
                raw_status = await self._line(process.stdout)
                failed = _object(raw_status, {"schema", "state", "pid", "expires_at", "project_runtime", "connection_handle", "executable", "environment", "kubeconfig", "reason", "cleanup_complete"})
                if failed.get("schema") == 1 and type(failed.get("schema")) is int and failed.get("state") == "failed" and failed.get("pid") == process.pid and failed.get("executable") == str(binary):
                    owner.cleanup_confirmed = failed.get("cleanup_complete") is True
                    raise _error("unavailable")
                status = _object(
                    raw_status,
                    {
                        "schema",
                        "state",
                        "pid",
                        "expires_at",
                        "project_runtime",
                        "connection_handle",
                        "executable",
                        "environment",
                        "kubeconfig",
                    },
                )
                if (
                    status.get("schema") != 1
                    or status.get("state") != "ready"
                    or status.get("pid") != process.pid
                    or status.get("executable") != str(binary)
                ):
                    raise _error("invalid")
                _expiry(status.get("expires_at"))
                binding = _object(
                    status.get("environment"),
                    {"environment", "applied_definition_revision", "mutation_revision", "services"},
                )
                if binding.get("environment") != self.environment._wire():
                    raise _error("invalid")
                for field in ("applied_definition_revision", "mutation_revision"):
                    revision = binding.get(field)
                    if type(revision) is not int or revision < 1:
                        raise _error("invalid")
                selected = _object(binding.get("services"), {service})
                fact = _object(
                    selected.get(service), {"service_id", "protocol", "endpoint", "kubernetes_auth"}
                )
                if fact.get("protocol") != protocol or not re.fullmatch(
                    r"svc_[A-Za-z0-9]{22}", _text(fact.get("service_id"))
                ):
                    raise _error("invalid")
                handle = _text(status.get("connection_handle"))
                if not Path(handle).is_absolute():
                    raise _error("invalid")
                owner.binding = binding
                owner.ipc = await asyncio.to_thread(OwnerIPC, handle)
                return _ResolvedService(service, protocol, owner)
        except BaseException as primary:
            if process.returncode is None:
                process.terminate()
            try:
                await self._join(process)
            except BaseException as cleanup:
                raise BaseExceptionGroup("environment startup and cleanup failed", [primary, cleanup]) from None
            if not owner.cleanup_confirmed and process.stdout is not None:
                # cancellation may win the wait just before native delivers its
                # failed-start cleanup receipt. inspect only joined, bounded EOF.
                remaining = await process.stdout.read((128 << 10) + 1)
                if len(remaining) <= 128 << 10:
                    try:
                        receipt: object = json.loads(remaining)
                        if isinstance(receipt, dict) and receipt.get("schema") == 1 and type(receipt.get("schema")) is int and receipt.get("state") == "failed" and receipt.get("pid") == process.pid and receipt.get("executable") == str(binary) and receipt.get("cleanup_complete") is True:
                            owner.cleanup_confirmed = True
                    except (ValueError, UnicodeError):
                        pass
            owner.stopped = process.returncode == 0 or owner.cleanup_confirmed
            if isinstance(primary, TimeoutError):
                raise _error("unavailable") from None
            raise

    async def resolve(self, service: str) -> _ResolvedService:
        pending = self._starts.get(service)
        if pending is None:
            pending = asyncio.create_task(self._start(service))
            self._starts[service] = pending
        try:
            return await asyncio.shield(pending)
        except BaseException as error:
            if pending.done() and not pending.cancelled() and pending.exception() is error:
                self._observed_start_failures.add(error)
            raise

    async def _request(self, work: Callable[[], object]) -> object:
        # cancellation of an await never abandons its bounded native IPC worker.
        task = asyncio.create_task(asyncio.to_thread(work))
        self._workers.add(task)

        def finished(done: asyncio.Task[object]) -> None:
            self._workers.discard(done)
            if not done.cancelled():
                error = done.exception()
                if done in self._abandoned and error is not None:
                    self._terminal.append(error)
            self._abandoned.discard(done)

        task.add_done_callback(finished)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done() and not task.cancelled():
                error = task.exception()
                if error is not None:
                    self._terminal.append(error)
            else:
                self._abandoned.add(task)
            raise

    async def prepare(self, resolution: _ResolvedService) -> object:
        owner = resolution.binding
        if (
            not isinstance(owner, _NativeOwner)
            or owner not in self._owners
            or owner.service != resolution.service
            or owner.protocol != resolution.protocol
            or owner.ipc is None
            or owner.binding is None
            or owner.stopped
        ):
            raise _error("invalid")
        async with owner.gate:
            return await self._prepare_owned(owner, resolution)

    async def _prepare_owned(self, owner: _NativeOwner, resolution: _ResolvedService) -> object:
        ipc = owner.ipc
        assert ipc is not None
        initial = owner.initial
        owner.initial = False
        reply = None
        if not initial and self._callback is not None:
            challenge = await self._request(lambda: ipc.prepare("", operation="identity-challenge"))
            reply = await self._proof(challenge, owner, "visitor_attach")
        environment = None
        if not initial and self.identity.acquisition is not None:
            _, environment = self.identity.acquisition._capture()
        raw = await self._request(lambda: ipc.prepare(resolution.service, identity_reply=reply, source_environment=environment))
        obj = _object(
            raw, {"schema", "project_runtime", "connection", "verification", "environment"}
        )
        if obj.get("environment") != owner.binding:
            raise _error("invalid")
        # the existing prepared decoder checks metadata/TLS/snapshot coherence.
        _prepared(
            {key: value for key, value in obj.items() if key != "environment"}, resolution.service
        )
        return obj.get("connection")

    async def aclose(self) -> None:
        self._closed = True
        for start in self._starts.values():
            if not start.done():
                start.cancel()
        starts = await asyncio.gather(*self._starts.values(), return_exceptions=True)
        await asyncio.gather(*tuple(self._workers), return_exceptions=True)
        failures = [
            *self._terminal,
            *(
                result
                for result in starts
                if isinstance(result, BaseException)
                and not isinstance(result, asyncio.CancelledError)
                and result not in self._observed_start_failures
            ),
        ]
        for source in self._sources:
            self._abandoned_sources.add(source)
            source.cancel()
        if self._sources:
            _, pending_sources = await asyncio.wait(tuple(self._sources), timeout=10)
            if pending_sources:
                failures.append(TimeoutError("identity source cleanup deadline exceeded"))
        failures.extend(self._source_failures.values())
        for owner in self._owners:
            if owner.stopped:
                continue
            try:
                if owner.process.returncode is None:
                    if owner.ipc is not None:
                        await self._request(partial(owner.ipc.prepare, "", operation="stop"))
                    else:
                        owner.process.terminate()
                await self._join(owner.process)
                if owner.process.returncode != 0:
                    raise _error("unavailable")
                if owner.ipc is not None:
                    owner.ipc.close()
                owner.stopped = True
            except BaseException as error:
                failures.append(error)
        if failures:
            raise BaseExceptionGroup("native environment cleanup failed", failures)
