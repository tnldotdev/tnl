"""cache ordinary application clients behind native-selected connection bindings."""

from __future__ import annotations

import asyncio
import inspect
import os
from collections.abc import Awaitable, Callable, Hashable
from dataclasses import dataclass
from typing import Protocol, cast

from ._protocol import TnlError


class ClientFactory[T](Protocol):
    async def __call__(self) -> T: ...

    async def aclose(self) -> None: ...


@dataclass(slots=True)
class _Outcome[T]:
    value: T | None = None
    error: BaseException | None = None

    def unwrap(self) -> T:
        if self.error is not None:
            raise self.error
        return cast(T, self.value)


@dataclass(slots=True)
class _Entry[T]:
    created: asyncio.Task[_Outcome[T]]


class _Factory[C, T]:
    def __init__(
        self,
        acquire: Callable[[], Awaitable[tuple[Hashable, C]]],
        *,
        create: Callable[[C], T | Awaitable[T]],
        close: Callable[[T], None | Awaitable[None]],
        finalize: Callable[[], Awaitable[list[BaseException]]] | None = None,
        on_closed: Callable[[], None] | None = None,
        shutdown_deadline: Callable[[], float | None] | None = None,
        acquisition_stopped: Callable[[BaseException], bool] | None = None,
    ) -> None:
        if not callable(create) or not callable(close):
            raise TnlError("sdk.configuration_invalid", "supply create and close client callbacks")
        self._acquire = acquire
        self._create = create
        self._close = close
        self._finalize = finalize
        self._finalized = finalize is None
        self._on_closed = on_closed
        self._pid = os.getpid()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._closed_error = TnlError("sdk.client_closed", "the client factory is closed")
        self._entries: dict[Hashable, _Entry[T]] = {}
        self._pending: set[asyncio.Task[_Outcome[T]]] = set()
        self._closing: asyncio.Task[list[BaseException]] | None = None
        self._shutdown_until: float | None = None
        self._parent_shutdown_deadline = shutdown_deadline
        self._stopping = asyncio.Event()
        self._timeout_failure: BaseException | None = None
        self._acquisition_stopped = acquisition_stopped

    async def _application[R](self, value: Awaitable[R]) -> R:
        """join interruptible SDK waits, not an application that ignores stop."""
        app = asyncio.ensure_future(value)
        stopping = asyncio.create_task(self._stopping.wait())
        try:
            done, _ = await asyncio.wait((app, stopping), return_when=asyncio.FIRST_COMPLETED)
            if app in done:
                return app.result()
            assert self._shutdown_until is not None
            done, _ = await asyncio.wait(
                (app,), timeout=max(0, self._shutdown_until - asyncio.get_running_loop().time())
            )
            if app in done:
                return app.result()
            app.cancel()
            timeout = TimeoutError("application client callback did not finish before shutdown")
        finally:
            stopping.cancel()
            await asyncio.gather(stopping, return_exceptions=True)
        # the stop waiter may already be done; give cancellation a turn to run.
        await asyncio.sleep(0)
        # inspect completed work, but do not wait for an uninterruptible callback.
        failure: BaseException = timeout
        if app.done():
            if not app.cancelled() and (cause := app.exception()) is not None:
                failure = BaseExceptionGroup(
                    "application callback shutdown failed", [timeout, cause]
                )
        else:
            app.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        self._timeout_failure = failure
        raise failure

    def __repr__(self) -> str:
        return "<tnl client factory (private)>"

    def _context(self) -> asyncio.AbstractEventLoop:
        # check before touching inherited tasks, locks, clients or callbacks.
        if self._pid != os.getpid():
            raise self._closed_error
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise TnlError(
                "sdk.client_context_invalid",
                "the client factory belongs to another event loop; create one in this context",
            )
        return loop

    async def __call__(self) -> T:
        if self._pid != os.getpid() or self._closed:
            raise self._closed_error
        loop = self._context()
        operation = loop.create_task(self._result())
        self._pending.add(operation)

        def finished(task: asyncio.Task[_Outcome[T]]) -> None:
            self._pending.discard(task)
            if not task.cancelled():
                task.exception()

        operation.add_done_callback(finished)
        # one canceled caller never abandons native acquisition or shared create.
        return (await asyncio.shield(operation)).unwrap()

    async def _result(self) -> _Outcome[T]:
        try:
            return _Outcome(value=await self._get())
        except BaseException as error:
            # callback cancellation is an application exception, not permission to
            # cancel another waiter or to lose its original exception identity.
            return _Outcome(error=error)

    async def _get(self) -> T:
        if self._closed:
            raise self._closed_error
        try:
            key, connection = await self._acquire()
        except BaseException as error:
            if (
                self._closed
                and self._acquisition_stopped is not None
                and self._acquisition_stopped(error)
            ):
                raise self._closed_error from None
            raise
        if self._closed:
            raise self._closed_error
        entry = self._entries.get(key)
        if entry is None:
            created = asyncio.create_task(self._make(connection))
            entry = _Entry(created)
            self._entries[key] = entry

            def failed(task: asyncio.Task[_Outcome[T]]) -> None:
                if task.cancelled() or task.result().error is not None:
                    if self._entries.get(key) is entry:
                        del self._entries[key]

            created.add_done_callback(failed)
        value = (await asyncio.shield(entry.created)).unwrap()
        if self._closed:
            raise self._closed_error
        return value

    async def _make(self, connection: C) -> _Outcome[T]:
        try:
            if self._closed:
                raise self._closed_error
            value = self._create(connection)
            if inspect.isawaitable(value):
                return _Outcome(value=await self._application(cast(Awaitable[T], value)))
            return _Outcome(value=cast(T, value))
        except BaseException as error:
            return _Outcome(error=error)

    async def aclose(self) -> None:
        # a forked child must not close its parent's ordinary driver or native IPC.
        if self._pid != os.getpid():
            return
        if self._timeout_failure is not None and self._closing is None:
            raise self._timeout_failure
        if (
            self._closed
            and not self._entries
            and not self._pending
            and self._closing is None
            and self._finalized
            and self._on_closed is None
        ):
            return
        self._context()
        self._closed = True
        if self._shutdown_until is None:
            self._shutdown_until = asyncio.get_running_loop().time() + 10
            if self._parent_shutdown_deadline is not None:
                parent = self._parent_shutdown_deadline()
                if parent is not None:
                    self._shutdown_until = min(self._shutdown_until, parent)
        self._stopping.set()
        closing = self._closing
        if closing is None:
            closing = asyncio.create_task(self._cleanup())
            self._closing = closing

            def finished(task: asyncio.Task[list[BaseException]]) -> None:
                if self._closing is task:
                    self._closing = None
                if not task.cancelled():
                    task.exception()

            closing.add_done_callback(finished)
        failures = await asyncio.shield(closing)
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("client cleanup failed", failures)

    async def _cleanup(self) -> list[BaseException]:
        pending = await asyncio.gather(*tuple(self._pending), return_exceptions=True)
        failures: list[BaseException] = []
        for value in pending:
            error = value.error if isinstance(value, _Outcome) else value
            if isinstance(error, BaseException) and error is not self._closed_error:
                if not any(previous is error for previous in failures):
                    failures.append(error)

        async def close_entry(key: Hashable, entry: _Entry[T]) -> BaseException | None:
            try:
                value = (await entry.created).unwrap()
                if (
                    self._shutdown_until is not None
                    and asyncio.get_running_loop().time() >= self._shutdown_until
                ):
                    self._timeout_failure = TimeoutError(
                        "client shutdown budget expired before application cleanup"
                    )
                    raise self._timeout_failure
                result = self._close(value)
                if result is not None:
                    await self._application(result)
                if self._entries.get(key) is entry:
                    del self._entries[key]
                return None
            except BaseException as error:
                return error

        results = await asyncio.gather(
            *(close_entry(key, entry) for key, entry in tuple(self._entries.items())),
            return_exceptions=True,
        )
        failures.extend(
            result
            for result in results
            if isinstance(result, BaseException)
            and not any(previous is result for previous in failures)
        )
        if self._finalize is not None and not self._finalized:
            try:
                final = await self._finalize()
            except BaseException as error:
                final = [error]
            self._finalized = not final
            failures.extend(final)
        # finalization may release independent resources after a driver failure.
        # retire the factory only once every owned cleanup has succeeded.
        if not failures and self._on_closed is not None:
            try:
                self._on_closed()
            except BaseException as error:
                failures.append(error)
            else:
                self._on_closed = None
        if self._timeout_failure is not None and failures:
            # retries must retain the whole joined failure, not the last timeout.
            self._timeout_failure = (
                failures[0]
                if len(failures) == 1
                else BaseExceptionGroup("client cleanup failed", failures)
            )
            return [self._timeout_failure]
        return failures
