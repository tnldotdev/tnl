"""observe one native publication without owning its listener or native process."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from ._native import NativeRuntime
from ._protocol import (
    Endpoint,
    NativeUnavailable,
    PublicationEvent,
    PublicationStatus,
    RegistrationLost,
    TnlError,
    parse_events,
    parse_status,
)


async def join_cleanup[T](task: asyncio.Task[T]) -> T:
    """defer caller cancellation until the owned cleanup task has finished."""
    canceled: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cause:
            canceled = cause
        except BaseException:
            break
    try:
        result = task.result()
    except BaseException as cause:
        if canceled is not None and not isinstance(cause, asyncio.CancelledError):
            raise BaseExceptionGroup("cleanup and cancellation failed", [canceled, cause]) from None
        raise
    if canceled is not None:
        raise canceled
    return result


@dataclass(frozen=True, slots=True)
class Selection:
    endpoint: Endpoint
    service: str
    registration_id: str
    target: str


class Publication:
    """status, fresh readiness, native events, termination, and joined cleanup."""

    def __init__(
        self,
        *,
        native: NativeRuntime,
        current: Callable[[], Selection],
        url: Callable[[], str | None],
        stopped: asyncio.Event,
        close: Callable[[], Awaitable[None]],
        finished: Callable[[], Awaitable[None]],
    ) -> None:
        self._observation_native = native
        self._current_selection = current
        self._publication_url = url
        self._stopped = stopped
        self._close_publication = close
        self._owner_finished = finished
        self._finishing: asyncio.Task[None] | None = None

    @property
    def url(self) -> str | None:
        return self._publication_url()

    async def _request(
        self, operation: str, payload: dict[str, object] | None = None
    ) -> tuple[object, Selection]:
        if self._stopped.is_set():
            raise RegistrationLost()
        selection = self._current_selection()
        work = asyncio.create_task(
            self._observation_native.request(selection.endpoint, operation, payload)
        )
        stopped = asyncio.create_task(self._stopped.wait())
        try:
            await asyncio.wait({work, stopped}, return_when=asyncio.FIRST_COMPLETED)
            if self._stopped.is_set() or self._current_selection() != selection:
                raise RegistrationLost()
            return work.result(), selection
        finally:
            for task in (work, stopped):
                task.cancel()
            await asyncio.gather(work, stopped, return_exceptions=True)

    async def _read(self, operation: str) -> tuple[PublicationStatus, object]:
        if self._stopped.is_set():
            raise RegistrationLost()
        current = self._current_selection()
        raw, selection = await self._request(
            operation, {"services": [current.service]} if operation == "check" else None
        )
        status = parse_status(raw, selection.service, selection.registration_id, selection.target)
        if status is None:
            raise RegistrationLost()
        return status, raw

    async def status(self) -> PublicationStatus:
        """read current native state without probing application readiness."""
        return (await self._read("status"))[0]

    async def _pause_observation(self) -> None:
        try:
            await asyncio.wait_for(self._stopped.wait(), 0.25)
        except TimeoutError:
            return
        raise RegistrationLost()

    async def wait(self, *, until: Literal["ready", "routable"] = "ready") -> None:
        """request fresh readiness; cancel this await without stopping publication."""
        if until not in ("ready", "routable"):
            raise TnlError("sdk.configuration_invalid", "wait until ready or routable")
        started = datetime.now(UTC)
        while True:
            status, _ = await self._read("status" if until == "routable" else "check")
            if status.failure is not None:
                raise TnlError("sdk.publication_failed", "the publication failed")
            if (
                status.routable
                if until == "routable"
                else status.ready and status.checked_at is not None and status.checked_at >= started
            ):
                return
            await self._pause_observation()

    async def watch(self, *, after: str | None = None) -> AsyncGenerator[PublicationEvent, None]:
        """resume exclusive native event cursors; cancellation affects observation only."""
        status, raw = await self._read("status")
        if after is None:
            after = status.cursor
            assert isinstance(raw, dict)
            yield parse_events(
                [{"cursor": after, "type": "snapshot", "at": raw["observed_at"], "snapshot": raw}],
                self._current_selection().service,
                status.tunnel_id,
            )[0]
        while True:
            raw, selection = await self._request("events", {"after": after})
            for event in parse_events(raw, selection.service, status.tunnel_id):
                after = event.cursor
                yield event
            await self._pause_observation()

    async def finished(self) -> None:
        """wait for shutdown or terminal publication failure, independently of readiness."""
        if self._finishing is None:
            self._finishing = asyncio.create_task(self._finish())
            self._finishing.add_done_callback(
                lambda task: task.exception() if not task.cancelled() else None
            )
        await asyncio.shield(self._finishing)

    async def _finish(self) -> None:
        async def owner_finished() -> None:
            await self._owner_finished()

        async def monitor() -> None:
            while True:
                try:
                    status = await self.status()
                    if status.failure is not None:
                        raise TnlError("sdk.publication_failed", "the publication failed")
                    await self._pause_observation()
                except (RegistrationLost, NativeUnavailable):
                    if self._stopped.is_set():
                        await self._owner_finished()
                        return
                    await asyncio.sleep(0.25)

        owner, observing = (
            asyncio.create_task(owner_finished()),
            asyncio.create_task(monitor()),
        )
        try:
            done, _ = await asyncio.wait({owner, observing}, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            owner.cancel()
            observing.cancel()
            await asyncio.gather(owner, observing, return_exceptions=True)

    async def close(self) -> None:
        await self._close_publication()

    async def __aenter__(self) -> Publication:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()
