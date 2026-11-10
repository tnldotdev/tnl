"""pin publication authority to the native visitor source owner and its signing key."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import re
import time
from dataclasses import dataclass

from ._connection_ipc import OwnerIPC
from ._connections import _Scope, _Session
from ._credential import ApplicationDocument, application_document, opaque_id, timestamp
from ._protocol import TnlError
from ._publication import join_cleanup


def _denied() -> TnlError:
    return TnlError(
        "sdk.workload_denied", "the native workload source does not authorize publication"
    )


@dataclass(frozen=True, slots=True, repr=False)
class _PreparedApplication:
    document: ApplicationDocument
    session: str
    lease: float
    assertion_expires: float
    digest: str
    binding: str


def _prepared(value: object) -> _PreparedApplication:
    try:
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema",
                "credential",
                "source_session_id",
                "lease_expires_at",
                "verification",
            }
            or type(value["schema"]) is not int
            or value["schema"] != 1
        ):
            raise ValueError("application")
        proof = value["verification"]
        if not isinstance(proof, dict) or set(proof) != {"digest", "binding", "expires_at"}:
            raise ValueError("verification")
        digest, binding = proof["digest"], proof["binding"]
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or (not isinstance(binding, str) or re.fullmatch(r"[0-9a-f]{64}", binding) is None)
        ):
            raise ValueError("binding")
        lease, expires, now = (
            timestamp(value["lease_expires_at"]),
            timestamp(proof["expires_at"]),
            time.time(),
        )
        if not now < lease <= now + 91 or not now < expires <= now + 12 * 3600 + 60:
            raise ValueError("expiry")
        return _PreparedApplication(
            application_document(value["credential"]),
            opaque_id(value["source_session_id"], "wls_"),
            lease,
            expires,
            digest,
            binding,
        )
    except (ValueError, TypeError, OverflowError, TnlError):
        pass
    raise _denied() from None


class WorkloadApplication:
    """one request's selected source; refresh may never select a replacement owner."""

    def __init__(self, scope: _Scope) -> None:
        self._scope = scope
        self._request = _Session(scope)
        self._starting: asyncio.Task[None] | None = None
        self._refreshes: set[asyncio.Task[None]] = set()
        self._refresh_lock = asyncio.Lock()
        self._current: _PreparedApplication | None = None
        self._initial: _PreparedApplication | None = None
        self._ipc: OwnerIPC | None = None
        self._closed = False
        self._closing: asyncio.Task[None] | None = None
        self._failure: TnlError | None = None

    def __repr__(self) -> str:
        return "<tnl workload application source (private)>"

    @property
    def document(self) -> ApplicationDocument:
        if self._initial is None:
            raise _denied()
        return self._initial.document

    async def start(self) -> None:
        if self._closed or self._scope.closed:
            raise _denied()
        if self._starting is None:
            self._starting = asyncio.create_task(self._acquire())
            self._starting.add_done_callback(
                lambda task: task.exception() if not task.cancelled() else None
            )
        await asyncio.shield(self._starting)

    async def _acquire(self) -> None:
        selection = await self._scope.select("")
        if selection is None:
            raise _denied()
        raw, session = await asyncio.to_thread(self._request.application, selection)
        prepared = _prepared(raw)
        if selection.assertion is not None and not hmac.compare_digest(
            prepared.digest,
            hashlib.sha256(selection.assertion.encode()).hexdigest(),
        ):
            raise _denied()
        server = (
            None if self._scope.environment is None else self._scope.environment.get("TNL_SERVER")
        )
        if server is not None and prepared.document.control_url != server:
            raise _denied()
        if session.handle is None:
            raise _denied()
        self._ipc = await asyncio.to_thread(OwnerIPC, session.handle)
        self._initial = self._current = prepared

    def check(self, resource: str) -> None:
        if self._failure is not None:
            raise self._failure
        current, initial = self._current, self._initial
        if self._closed or self._scope.closed or current is None or initial is None:
            raise _denied()
        if min(current.lease, current.assertion_expires) <= time.time():
            self._failure = _denied()
            raise self._failure
        original, grant = initial.document.publish(resource), current.document.publish(resource)
        if original.id != grant.id:
            raise _denied()

    async def authorize(self, resource: str) -> None:
        self.check(resource)
        task = asyncio.create_task(self._refresh(resource))
        self._refreshes.add(task)

        def done(work: asyncio.Task[None]) -> None:
            self._refreshes.discard(work)
            if not work.cancelled():
                work.exception()

        task.add_done_callback(done)
        await asyncio.shield(task)

    async def _refresh(self, resource: str) -> None:
        async with self._refresh_lock:
            self.check(resource)
            await self._refresh_current(resource)

    async def _refresh_current(self, resource: str) -> None:
        assert self._ipc is not None and self._initial is not None
        raw: object
        assertion: str | None = None
        try:
            try:
                selection = await self._scope.select("")
                if selection is None:
                    raise _denied()
                raw = await asyncio.to_thread(
                    self._ipc.prepare,
                    "",
                    selection.assertion,
                    selection=selection.private_input(),
                    application=True,
                )
                if isinstance(raw, dict) and "reason" in raw:
                    raise _denied()
                assertion = selection.assertion
            except TnlError:
                # a failed callback or changed request cannot select another
                # source. only the original owner's still-finite lease may remain.
                raw = await asyncio.to_thread(self._ipc.prepare, "", application=True)
            current, initial = _prepared(raw), self._initial
            if assertion is not None and not hmac.compare_digest(
                current.digest,
                hashlib.sha256(assertion.encode()).hexdigest(),
            ):
                raise _denied()
            left, right = initial.document, current.document
            if (
                current.session != initial.session
                or current.binding != initial.binding
                or (left.control_url, left.client_id, left.key_id, left.team_id)
                != (
                    right.control_url,
                    right.client_id,
                    right.key_id,
                    right.team_id,
                )
                or not hmac.compare_digest(
                    left.key.private_bytes_raw(), right.key.private_bytes_raw()
                )
            ):
                raise _denied()
            assert self._current is not None
            if (
                current.document.publish(resource).expires
                > self._current.document.publish(resource).expires
            ):
                raise _denied()
            self._current = current
            self.check(resource)
        except TnlError:
            self._failure = _denied()
        else:
            return
        raise self._failure from None

    async def close(self) -> None:
        self._closed = True
        if self._closing is None:
            self._closing = asyncio.create_task(self._close())
        try:
            await join_cleanup(self._closing)
        except BaseException:
            if self._closing.done():
                self._closing = None
            raise

    async def _close(self) -> None:
        if self._starting is not None:
            await asyncio.gather(self._starting, return_exceptions=True)
        await asyncio.gather(*tuple(self._refreshes), return_exceptions=True)
        if self._ipc is not None:
            await asyncio.to_thread(self._ipc.close)
            self._ipc = None
