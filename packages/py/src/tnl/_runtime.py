"""independent runtime selection and publication-before-client cleanup."""

from __future__ import annotations

import asyncio
import os
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from enum import Enum
from pathlib import Path
from typing import Literal, Protocol, Self, overload
from urllib.parse import urlsplit

from starlette.types import ASGIApp

from ._app import PreparedPublication, PreparedService
from ._asgi import AccessPolicy, Limits, _ASGIPublication, publish_runtime
from ._client import ClientFactory, _Factory, connection_client
from ._connections import Connection, ConnectionHandle, _Scope, _Session
from ._credential import ApplicationDocument, application_document
from ._http import HTTPClientSettings, _HTTPResources
from ._native import NativeRuntime
from ._protocol import TnlError, service_name
from ._publication import Publication, join_cleanup
from ._workload import Workload
from ._workload_application import WorkloadApplication


class _Owned(Protocol):
    async def close(self) -> None: ...


class _Omitted(Enum):
    CREDENTIAL = 0


class _Lifetime:
    def __init__(self) -> None:
        self._pid = os.getpid()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._closing: asyncio.Task[None] | None = None
        self._publications: set[_Owned] = set()
        self._clients: set[ClientFactory[object]] = set()
        self._pending: set[asyncio.Task[object]] = set()

    def __repr__(self) -> str:
        return "<tnl runtime instance (private)>"

    def _check(self) -> None:
        if self._pid != os.getpid() or self._closed:
            raise TnlError("sdk.client_closed", "the runtime instance is closed")

    def _context(self) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise TnlError(
                "sdk.client_context_invalid", "the runtime instance belongs to another event loop"
            )

    async def _own[T](self, operation: Callable[[], Awaitable[T]]) -> T:
        self._check()
        self._context()

        async def run() -> T:
            try:
                self._check()
                value = await operation()
                self._check()
                return value
            except asyncio.CancelledError:
                self._check()
                raise

        work = asyncio.create_task(run())
        self._pending.add(work)

        def finished(task: asyncio.Task[T]) -> None:
            self._pending.discard(task)
            if not task.cancelled():
                task.exception()

        work.add_done_callback(finished)
        return await asyncio.shield(work)

    async def aclose(self) -> None:
        if self._pid != os.getpid():
            return
        self._context()
        self._closed = True
        self._fence()
        if self._closing is None:
            self._closing = asyncio.create_task(self._cleanup())
        try:
            await join_cleanup(self._closing)
        except BaseException:
            if self._closing.done():
                self._closing = None
            raise

    def _fence(self) -> None:
        pass

    async def _release(self) -> None:
        raise NotImplementedError

    @asynccontextmanager
    async def _publication_context(
        self,
        context: AbstractAsyncContextManager[_ASGIPublication],
    ) -> AsyncIterator[Publication]:
        publication = await self._own(context.__aenter__)
        try:
            yield publication
        except BaseException as primary:
            if not await context.__aexit__(type(primary), primary, primary.__traceback__):
                raise
        else:
            await context.__aexit__(None, None, None)
        finally:
            if publication._close_complete:
                self._publications.discard(publication)

    async def _cleanup(self) -> None:
        for task in tuple(self._pending):
            task.cancel()
        await asyncio.gather(*tuple(self._pending), return_exceptions=True)
        await self._close_all(tuple(self._publications), lambda item: item.close())
        self._publications.clear()
        await self._close_all(tuple(self._clients), lambda item: item.aclose())
        self._clients.clear()
        await self._release()

    async def _close_all[T](
        self, values: tuple[T, ...], close: Callable[[T], Awaitable[None]]
    ) -> None:
        results = await asyncio.gather(*(close(value) for value in values), return_exceptions=True)
        failures = [result for result in results if isinstance(result, BaseException)]
        if failures:
            raise BaseExceptionGroup("runtime cleanup failed", failures)

    async def __aenter__(self) -> Self:
        self._check()
        self._context()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()


class TnlInstance(_Lifetime):
    """pin native selection without mutating process-wide SDK configuration."""

    def __init__(
        self,
        *,
        directory: str | Path | None = None,
        state_dir: str | Path | None = None,
        server: str | None = None,
        credential: Workload | _Omitted = _Omitted.CREDENTIAL,
    ) -> None:
        workload = credential if isinstance(credential, Workload) else None
        if credential is not _Omitted.CREDENTIAL and workload is None:
            raise TnlError("sdk.configuration_invalid", "supply an explicit workload credential")
        try:
            root = Path(directory if directory is not None else os.getcwd()).resolve(strict=True)
            state = state_dir if state_dir is not None else os.environ.get("TNL_STATE_DIR")
            if directory == "" or state == "" or "\0" in str(root):
                raise ValueError("directory")
            state = None if state is None else str(Path(state).resolve())
            selected_server = server if server is not None else os.environ.get("TNL_SERVER")
            if not root.is_dir() or workload is not None and not isinstance(workload, Workload):
                raise ValueError("selection")
            if selected_server is not None:
                if not isinstance(selected_server, str):
                    raise ValueError("server")
                url = urlsplit(selected_server)
                if (
                    len(selected_server) > 4096
                    or url.geturl() != selected_server
                    or any(character.isspace() for character in selected_server)
                    or "\0" in selected_server
                    or url.scheme != "https"
                    or not url.hostname
                    or url.username is not None
                    or url.password is not None
                    or url.path
                    or url.query
                    or url.fragment
                    or url.port is not None
                    and not 1 <= url.port <= 65535
                ):
                    raise ValueError("server")
        except (OSError, ValueError, TypeError):
            raise TnlError(
                "sdk.configuration_invalid", "select an existing directory and HTTPS server origin"
            ) from None
        environment = {
            "TNL_STATE_DIR": state,
            "TNL_SERVER": selected_server,
            "TNL_CONFIG": os.environ.get("TNL_CONFIG"),
            "TNL_CONNECTION_HANDLE": None,
            "TNL_APP_ENDPOINT": None,
            "TNL_PUBLISHER_CREDENTIAL_FILE": os.environ.get("TNL_PUBLISHER_CREDENTIAL_FILE"),
        }
        self._scope = _Scope(str(root), None, environment=environment, workload=workload)
        self._native = NativeRuntime(environment)
        self._state_dir = state
        self._server = selected_server
        super().__init__()
        self._handles: weakref.WeakSet[ConnectionHandle[Connection]] = weakref.WeakSet()
        self._sources: set[WorkloadApplication] = set()

    async def _application(self) -> WorkloadApplication:
        self._check()
        source = WorkloadApplication(self._scope)
        self._sources.add(source)
        await source.start()
        return source

    def connect(self, service: str) -> ConnectionHandle[Connection]:
        self._check()
        name = service_name(service)
        if self._scope.uses_workload():
            session = _Session(self._scope)
        else:
            with self._scope.lock:
                if self._scope.selected.closed:
                    self._scope.selected = _Session(self._scope)
                session = self._scope.selected
        handle: ConnectionHandle[Connection] = ConnectionHandle(session, service=name)
        self._handles.add(handle)
        return handle

    def client[T](
        self,
        service: str,
        *,
        create: Callable[[Connection], T | Awaitable[T]],
        close: Callable[[T], None | Awaitable[None]],
    ) -> ClientFactory[T]:
        self._check()
        service_name(service)
        factory = connection_client(
            lambda: self.connect(service),
            create=create,
            close=close,
            active=lambda: not self._closed and self._pid == os.getpid(),
        )
        self._clients.add(factory)
        return factory

    async def prepare(
        self,
        *,
        service: str | None = None,
        resource: str | None = None,
    ) -> PreparedService:
        self._check()
        if service is not None:
            service_name(service)

        async def start() -> PreparedService:
            result: PreparedService
            if self._scope.uses_workload():
                if service is not None:
                    raise TnlError("sdk.credential_denied", "select an exact application resource")
                source = await self._application()
                result = PreparedPublication(
                    self._scope.directory,
                    self._state_dir,
                    self._native,
                    source.document,
                    resource,
                    authorize=source.authorize,
                    check=source.check,
                )
            else:
                if resource is not None:
                    raise TnlError(
                        "sdk.credential_denied", "select an explicit application credential"
                    )
                result = PreparedService(
                    self._scope.directory, service, self._state_dir, self._native
                )
            self._publications.add(result)
            await result.start()
            return result

        return await self._own(start)

    @asynccontextmanager
    async def _workload_publication(
        self,
        app: ASGIApp,
        resource: str | None,
    ) -> AsyncIterator[_ASGIPublication]:
        source = await self._application()
        owned: _ASGIPublication | None = None

        def own(publication: _ASGIPublication) -> None:
            nonlocal owned
            owned = publication
            self._publications.add(publication)

        try:
            async with publish_runtime(
                self._native,
                app,
                directory=self._scope.directory,
                state_dir=self._state_dir,
                application=source.document,
                resource=resource,
                own=own,
                authorize=source.authorize,
                check=source.check,
            ) as publication:
                yield publication
        finally:
            if owned is None or owned._close_complete:
                await source.close()
                self._sources.discard(source)

    @asynccontextmanager
    async def publish(
        self,
        app: ASGIApp,
        *,
        publisher_credential_file: str | Path | None = None,
        publisher_identity_id: str | None = None,
        access: Literal["restricted", "anonymous"] | AccessPolicy | None = None,
        limits: Limits | None = None,
        require_post_quantum: bool = False,
        resource: str | None = None,
    ) -> AsyncIterator[Publication]:
        self._check()
        if self._scope.uses_workload():
            if (
                publisher_credential_file is not None
                or publisher_identity_id is not None
                or access is not None
                or limits is not None
                or require_post_quantum
            ):
                raise TnlError(
                    "sdk.credential_denied", "the application grant selects saved policy"
                )
            context = self._workload_publication(app, resource)
        else:
            if resource is not None:
                raise TnlError("sdk.credential_denied", "select an explicit application credential")
            context = publish_runtime(
                self._native,
                app,
                publisher_credential_file=publisher_credential_file,
                publisher_identity_id=publisher_identity_id,
                directory=self._scope.directory,
                state_dir=self._state_dir,
                server=self._server,
                access=access,
                limits=limits,
                require_post_quantum=require_post_quantum,
                own=self._publications.add,
            )
        async with self._publication_context(context) as publication:
            yield publication

    def _fence(self) -> None:
        self._scope.closed = True
        for publication in tuple(self._publications):
            if isinstance(publication, PreparedService | _ASGIPublication):
                publication.fence()

    async def _release(self) -> None:
        await asyncio.gather(*tuple(self._scope.operations), return_exceptions=True)
        await self._close_all(tuple(self._sources), lambda item: item.close())
        self._sources.clear()
        await self._close_all(tuple(self._handles), lambda item: item.aclose())
        self._handles.clear()
        await asyncio.to_thread(self._scope.stop)


class TnlHTTPInstance(_Lifetime):
    """visit exact application resources or token HTTPS origins with ordinary clients."""

    def __init__(
        self,
        credential: str | Mapping[str, object],
        *,
        directory: str | Path | None = None,
        state_dir: str | Path | None = None,
        server: str | None = None,
    ) -> None:
        self._document: ApplicationDocument | None = None
        if (
            isinstance(credential, Mapping)
            or isinstance(credential, str)
            and credential.lstrip().startswith("{")
        ):
            self._document = application_document(credential)
        if self._document is None and any(
            value is not None for value in (directory, state_dir, server)
        ):
            raise TnlError("sdk.configuration_invalid", "token HTTP does not select native state")
        if self._document is not None:
            if server is not None and server != self._document.control_url:
                raise TnlError("sdk.credential_denied", "the credential selects its control URL")
            try:
                root = Path(directory if directory is not None else os.getcwd()).resolve(
                    strict=True
                )
                state = state_dir if state_dir is not None else os.environ.get("TNL_STATE_DIR")
                if not root.is_dir() or directory == "" or state == "" or "\0" in str(root):
                    raise ValueError("selection")
                self._publication_directory = str(root)
                self._publication_state = None if state is None else str(Path(state).resolve())
            except (OSError, ValueError, TypeError):
                raise TnlError(
                    "sdk.configuration_invalid", "select an existing publication directory"
                ) from None
            self._publication_native = NativeRuntime(
                {
                    "TNL_STATE_DIR": self._publication_state,
                    "TNL_SERVER": self._document.control_url,
                    "TNL_CONFIG": os.environ.get("TNL_CONFIG"),
                    "TNL_APP_ENDPOINT": None,
                    "TNL_PUBLISHER_CREDENTIAL_FILE": None,
                }
            )
        super().__init__()
        self._http = _HTTPResources(self._document or credential, self._check, self._http_context)

    def _http_context(self) -> None:
        self._check()
        self._context()

    def connect(self, resource: str) -> HTTPClientSettings:
        self._check()
        return self._http.connect(resource)

    def client[T](
        self,
        resource: str,
        *,
        create: Callable[[HTTPClientSettings], T | Awaitable[T]],
        close: Callable[[T], None | Awaitable[None]],
    ) -> ClientFactory[T]:
        self.connect(resource)

        factory = _Factory(
            lambda: self._http.acquire(resource),
            create=create,
            close=close,
            active=lambda: not self._closed and self._pid == os.getpid(),
        )
        self._clients.add(factory)
        return factory

    async def prepare(self, *, resource: str | None = None) -> PreparedPublication:
        self._check()
        if self._document is None:
            raise TnlError("sdk.credential_denied", "visitor tokens do not authorize publication")
        document = self._document
        document.publish(resource)

        async def start() -> PreparedPublication:
            result = PreparedPublication(
                self._publication_directory,
                self._publication_state,
                self._publication_native,
                document,
                resource,
            )
            self._publications.add(result)
            await result.start()
            return result

        return await self._own(start)

    @asynccontextmanager
    async def publish(
        self,
        app: ASGIApp,
        *,
        resource: str | None = None,
    ) -> AsyncIterator[Publication]:
        self._check()
        if self._document is None:
            raise TnlError("sdk.credential_denied", "visitor tokens do not authorize publication")
        self._document.publish(resource)
        context = publish_runtime(
            self._publication_native,
            app,
            directory=self._publication_directory,
            state_dir=self._publication_state,
            application=self._document,
            resource=resource,
            own=self._publications.add,
        )
        async with self._publication_context(context) as publication:
            yield publication

    async def _release(self) -> None:
        await self._http.close()

    def _fence(self) -> None:
        self._http.fence()
        for publication in tuple(self._publications):
            if isinstance(publication, PreparedPublication | _ASGIPublication):
                publication.fence()


@overload
def create_tnl(
    *,
    credential: str | Mapping[str, object],
    directory: str | Path | None = None,
    state_dir: str | Path | None = None,
    server: str | None = None,
) -> TnlHTTPInstance: ...


@overload
def create_tnl(
    *,
    directory: str | Path | None = None,
    state_dir: str | Path | None = None,
    server: str | None = None,
    credential: Workload | _Omitted = _Omitted.CREDENTIAL,
) -> TnlInstance: ...


def create_tnl(
    *,
    directory: str | Path | None = None,
    state_dir: str | Path | None = None,
    server: str | None = None,
    credential: str | Mapping[str, object] | Workload | _Omitted = _Omitted.CREDENTIAL,
) -> TnlInstance | TnlHTTPInstance:
    """construct an independently owned runtime without starting native work."""
    if isinstance(credential, (str, Mapping)):
        return TnlHTTPInstance(credential, directory=directory, state_dir=state_dir, server=server)
    return TnlInstance(
        directory=directory, state_dir=state_dir, server=server, credential=credential
    )
