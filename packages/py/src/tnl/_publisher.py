"""own a native publisher without handling its signing key in Python."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import os
import re
from collections.abc import Awaitable, Callable, Mapping
from types import TracebackType
from typing import Self
from urllib.parse import urlsplit

from starlette.types import ASGIApp

from ._asgi import Publication, start_publication
from ._native import NativeRuntime, _join_cleanup, _shutdown_deadline, native_binary
from ._protocol import (
    Endpoint,
    InvalidResponse,
    NativeUnavailable,
    TnlError,
    object_value,
    parse_endpoint,
    service_name,
    text,
)

type PublisherEnrollment = str | Callable[[], str | Awaitable[str]]


class _PublisherRuntime(NativeRuntime):
    def __init__(self, owner: Endpoint) -> None:
        self._owner = owner

    async def start(
        self,
        directory: str,
        *,
        service: str | None = None,
        invocation_id: str | None = None,
        state_dir: str | None = None,
        publications: bool = False,
        environment: Mapping[str, str] | None = None,
    ) -> Endpoint:
        if service is not None or invocation_id is None:
            raise InvalidResponse()
        value = await self.request(
            self._owner, "capabilities", {"scope": "invocation", "invocation_id": invocation_id}
        )
        endpoint = parse_endpoint(value, invocation_id=invocation_id)
        if endpoint.url != self._owner.url or endpoint.owner_id != self._owner.owner_id:
            raise InvalidResponse()
        return endpoint


def _valid_control_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        if (
            not parts.hostname
            or parts.username is not None
            or parts.path
            or parts.query
            or parts.fragment
            or len(value) > 2048
            or value != f"{parts.scheme}://{parts.netloc}"
            or parts.netloc != parts.netloc.lower()
            or (parts.port is not None and not 0 < parts.port < 65536)
        ):
            return False
        if parts.scheme == "https":
            return True
        return parts.scheme == "http" and (
            parts.hostname == "localhost" or ipaddress.ip_address(parts.hostname).is_loopback
        )
    except ValueError:
        return False


async def _stop(child: asyncio.subprocess.Process) -> None:
    assert child.stdin is not None
    child.stdin.close()
    try:
        async with asyncio.timeout(12):
            code = await child.wait()
    except TimeoutError:
        if child.returncode is None:
            try:
                child.kill()
            except ProcessLookupError:
                pass
        await child.wait()
        raise TnlError(
            "sdk.publication_cleanup_failed", "the native publisher did not stop"
        ) from None
    if code != 0:
        raise TnlError(
            "sdk.publication_cleanup_failed", "the native publisher did not stop cleanly"
        )


class Publisher:
    """a saved publisher identity and the named publications it owns."""

    def __init__(
        self,
        child: asyncio.subprocess.Process,
        endpoint: Endpoint,
        identity: str,
        deployment: str,
        control_url: str,
    ) -> None:
        self._child = child
        self._runtime = _PublisherRuntime(endpoint)
        self._identity = identity
        self._deployment = deployment
        self._control_url = control_url
        self._pid = os.getpid()
        self._loop = asyncio.get_running_loop()
        self._pending: set[asyncio.Task[Publication]] = set()
        self._publications: set[Publication] = set()
        self._close_task: asyncio.Task[None] | None = None
        self._shutdown_until: float | None = None

    @property
    def publisher_identity_id(self) -> str:
        return self._identity

    @property
    def deployment_id(self) -> str:
        return self._deployment

    @property
    def control_url(self) -> str:
        return self._control_url

    def _local(self) -> bool:
        return self._pid == os.getpid() and self._loop is asyncio.get_running_loop()

    async def publish(self, name: str, app: ASGIApp, *, telemetry: bool = True) -> Publication:
        if not self._local() or self._close_task is not None or self._child.returncode is not None:
            raise TnlError("sdk.client_closed", "the publisher is closed; open it again")
        if len(self._pending) + len(self._publications) >= 64:
            raise TnlError("sdk.client_capacity", "close an unused publication")
        service_name(name)
        work = asyncio.create_task(
            start_publication(
                app,
                native=self._runtime,
                enrolled_service=name,
                telemetry=telemetry,
                on_start=self._publications.add,
                on_close=self._publications.discard,
                shutdown_deadline=lambda: self._shutdown_until,
            )
        )
        self._pending.add(work)
        try:
            return await work
        finally:
            self._pending.discard(work)

    async def aclose(self) -> None:
        if not self._local():
            return
        if self._close_task is None:
            self._shutdown_until = _shutdown_deadline()
            self._close_task = asyncio.create_task(self._close())
        await _join_cleanup(self._close_task)

    async def _close(self) -> None:
        pending = tuple(self._pending)
        for work in pending:
            work.cancel()
        results = await asyncio.gather(*pending, return_exceptions=True)
        errors: list[BaseException] = [
            item
            for item in results
            if isinstance(item, BaseException) and not isinstance(item, asyncio.CancelledError)
        ]
        for item in await asyncio.gather(
            *(publication.aclose() for publication in self._publications), return_exceptions=True
        ):
            if isinstance(item, BaseException):
                errors.append(item)
        try:
            await _stop(self._child)
        except Exception as cause:
            errors.append(cause)
        if errors:
            raise BaseExceptionGroup("publisher cleanup failed", errors)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _type: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        await self.aclose()


async def publisher(
    *,
    instance: str = "default",
    control_url: str | None = None,
    enrollment: PublisherEnrollment | None = None,
) -> Publisher:
    """open or enroll a protected native publisher slot; close the returned owner."""
    service_name(instance)
    if control_url is not None and not _valid_control_url(control_url):
        raise TnlError("sdk.configuration_invalid", "control_url must be a control origin")
    if (
        enrollment is not None
        and not callable(enrollment)
        and not (isinstance(enrollment, str) and 0 < len(enrollment) <= 256)
    ):
        raise TnlError("sdk.configuration_invalid", "enrollment must be a key or callable")
    args = [str(native_binary()), "--no-telemetry", "runtime", "publisher", "--instance", instance]
    if control_url is not None:
        args.extend(["--control-url", control_url])
    environment = dict(os.environ)
    environment.pop("TNL_ENROLLMENT_KEY", None)
    try:
        child = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=8192,
            env=environment,
        )
    except OSError:
        raise NativeUnavailable() from None
    stdout = child.stdout
    assert stdout is not None and child.stdin is not None
    opened = False
    try:
        async with asyncio.timeout(30):

            async def read() -> object:
                try:
                    line = await stdout.readline()
                    if not line:
                        raise NativeUnavailable()
                    return json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    raise InvalidResponse() from None

            record = await read()
            if record == {"type": "enrollment"}:
                if enrollment is None:
                    raise TnlError("sdk.publisher_setup_required", "supply an enrollment key")
                async with asyncio.timeout(15):
                    key = enrollment() if callable(enrollment) else enrollment
                    if inspect.isawaitable(key):
                        key = await key
                if not isinstance(key, str) or not 0 < len(key) <= 256:
                    raise TnlError("sdk.configuration_invalid", "enrollment did not return a key")
                child.stdin.write((json.dumps(key, ensure_ascii=False) + "\n").encode())
                await child.stdin.drain()
                record = await read()
            body = object_value(
                record,
                {"type", "publisher_identity_id", "deployment_id", "control_url", "endpoint"},
            )
            identity = text(body.get("publisher_identity_id"), 26)
            deployment = text(body.get("deployment_id"), 26)
            origin = text(body.get("control_url"), 2048)
            if (
                body.get("type") != "ready"
                or re.fullmatch(r"pub_[A-Za-z0-9]{22}", identity) is None
                or re.fullmatch(r"dpl_[A-Za-z0-9]{22}", deployment) is None
                or not _valid_control_url(origin)
                or control_url is not None
                and origin != control_url
            ):
                raise InvalidResponse()
            endpoint = parse_endpoint(body.get("endpoint"), owner_endpoint=True)
            owner = Publisher(child, endpoint, identity, deployment, origin)
            opened = True
            return owner
    except (OSError, TimeoutError):
        raise NativeUnavailable() from None
    finally:
        if not opened:
            try:
                await _join_cleanup(asyncio.create_task(_stop(child)))
            except TnlError:
                pass  # a rejected startup can exit nonzero before returning an owner
