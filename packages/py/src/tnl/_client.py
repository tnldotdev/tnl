"""cache ordinary application clients behind native-selected connection bindings."""

from __future__ import annotations

import asyncio
import inspect
import os
from collections.abc import Awaitable, Callable, Hashable
from dataclasses import dataclass
from typing import Protocol, cast

from . import _connections
from ._connections import Connection, ConnectionHandle
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
    ) -> None:
        if not callable(create) or not callable(close):
            raise TnlError("sdk.configuration_invalid", "supply create and close client callbacks")
        self._acquire = acquire
        self._create = create
        self._close = close
        self._pid = os.getpid()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._closed_error = TnlError("sdk.client_closed", "the client factory is closed")
        self._entries: dict[Hashable, _Entry[T]] = {}
        self._pending: set[asyncio.Task[_Outcome[T]]] = set()
        self._closing: asyncio.Task[list[BaseException]] | None = None

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
        key, connection = await self._acquire()
        if self._closed:
            raise self._closed_error
        entry = self._entries.get(key)
        if entry is None:
            if len(self._entries) >= 64:
                raise TnlError(
                    "sdk.client_capacity",
                    "the client factory has too many retained bindings; "
                    "close it before creating another",
                )
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
                return _Outcome(value=await cast(Awaitable[T], value))
            return _Outcome(value=cast(T, value))
        except BaseException as error:
            return _Outcome(error=error)

    async def aclose(self) -> None:
        # a forked child must not close its parent's ordinary driver or native IPC.
        if self._pid != os.getpid():
            return
        if self._closed and not self._entries and not self._pending and self._closing is None:
            return
        self._context()
        self._closed = True
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
        await asyncio.gather(*tuple(self._pending), return_exceptions=True)

        async def close_entry(key: Hashable, entry: _Entry[T]) -> BaseException | None:
            try:
                value = (await entry.created).unwrap()
                result = self._close(value)
                if result is not None:
                    await result
                if self._entries.get(key) is entry:
                    del self._entries[key]
                return None
            except BaseException as error:
                return error

        results = await asyncio.gather(
            *(close_entry(key, entry) for key, entry in tuple(self._entries.items())),
            return_exceptions=True,
        )
        return [result for result in results if isinstance(result, BaseException)]


def connection_client[C: Connection, T](
    selected: Callable[[], ConnectionHandle[C]],
    *,
    create: Callable[[C], T | Awaitable[T]],
    close: Callable[[T], None | Awaitable[None]],
) -> ClientFactory[T]:
    async def acquire() -> tuple[Hashable, C]:
        handle = selected()
        connection = await handle
        owner = handle._session.handle
        if owner is None or not connection._transport_id:
            raise _connections._error("invalid")
        key: tuple[object, ...] = (
            owner,
            connection._transport_id,
            connection.protocol,
            connection.host,
            connection.port,
        )
        if isinstance(connection, _connections._TLSConnection):
            key += (connection.server_hostname, connection.ca)
        if isinstance(connection, (_connections.HTTPConnection, _connections.KubernetesConnection)):
            key += (connection.url,)
        if isinstance(connection, _connections.KubernetesConnection):
            key += (connection.kubeconfig, connection.context)
        return key, connection

    return _Factory(acquire, create=create, close=close)


def client[T](
    service: str,
    *,
    create: Callable[[Connection], T | Awaitable[T]],
    close: Callable[[T], None | Awaitable[None]],
    directory: str | os.PathLike[str] | None = None,
) -> ClientFactory[T]:
    _connections.connect(service, directory=directory)
    return connection_client(
        lambda: _connections.connect(service, directory=directory), create=create, close=close
    )
