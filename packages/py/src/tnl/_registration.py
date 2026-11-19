"""native registration identity, acknowledgment recovery, and bounded cleanup."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass

from ._native import NativeRuntime, _shutdown_timestamp
from ._protocol import (
    Assignment,
    Endpoint,
    InvalidResponse,
    NativeUnavailable,
    PublicationCleanupFailed,
    RegistrationLost,
    TnlError,
    parse_assignment,
    parse_registration,
)


@dataclass(frozen=True, slots=True)
class _Registration:
    endpoint: Endpoint
    registration_id: str
    target: str | None = None


class NativeRegistration:
    """callers hold lock across compound registration/recovery operations.

    listener ownership, renewal scheduling, and routability stay with callers.
    stop fences new work before callers join their workers and unregister.
    """

    def __init__(
        self,
        native: NativeRuntime,
        directory: str,
        state_dir: str | None,
        payload: dict[str, object],
        *,
        service: str | None = None,
        invocation_id: str | None = None,
        publications: bool = False,
        environment: Mapping[str, str] | None = None,
        target: str | None = None,
    ) -> None:
        self._native = native
        self._directory = directory
        self._state_dir = state_dir
        self._service = service
        self._invocation_id = invocation_id
        self._publications = publications
        self._environment = None if environment is None else dict(environment)
        self._payload = deepcopy(payload)
        self._owner = str(payload["owner"])
        self.target = target
        self.endpoint: Endpoint | None = None
        self.current: _Registration | None = None
        self.candidate: _Registration | None = None
        self.uncertain = False
        self.closed = False
        self.lock = asyncio.Lock()
        self._requests: set[asyncio.Task[object]] = set()
        self._shutdown_until: float | None = None
        self._shutdown_timestamp: str | None = None

    @property
    def complete(self) -> bool:
        return self.current is None and self.candidate is None and not self.uncertain

    def _check(self) -> None:
        if self.closed:
            raise RegistrationLost()

    async def discover(self) -> None:
        self._check()
        if self._environment is None and self._invocation_id is None:
            self.endpoint = await self._native.start(
                self._directory, service=self._service, state_dir=self._state_dir
            )
        else:
            self.endpoint = await self._native.start(
                self._directory,
                service=self._service,
                invocation_id=self._invocation_id,
                state_dir=self._state_dir,
                publications=self._publications,
                environment=self._environment,
            )
        self._check()

    async def _request(
        self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
    ) -> object:
        task = asyncio.create_task(self._native.request(endpoint, operation, payload))
        self._requests.add(task)
        try:
            return await task
        finally:
            self._requests.discard(task)

    async def prepare(self) -> Assignment:
        self._check()
        assert self.endpoint is not None
        self.uncertain = True
        assignment = parse_assignment(
            await self._request(self.endpoint, "prepare", deepcopy(self._payload)), self.endpoint
        )
        # preserve a valid acknowledgment before caller-specific metadata checks.
        self.candidate = _Registration(self.endpoint, assignment.registration_id, self.target)
        self.uncertain = False
        return assignment

    def accept(self) -> None:
        self._check()
        assert self.candidate is not None
        self.current, self.candidate = self.candidate, None

    def payload(self, registration: _Registration | None = None) -> dict[str, object]:
        registration = registration or self.current
        if registration is None:
            raise RegistrationLost()
        return {
            "version": 1,
            "registration_id": registration.registration_id,
            "owner": self._owner,
            **({} if registration.target is None else {"target": registration.target}),
        }

    async def bind(self, target: str) -> None:
        self._check()
        if self.current is None:
            raise RegistrationLost()
        self.target = target
        self.current = _Registration(self.current.endpoint, self.current.registration_id, target)
        await self._request(self.current.endpoint, "register", self.payload())

    async def acquire_invocation(self, *, cleanup: bool = False) -> None:
        if not cleanup:
            self._check()
        assert self.endpoint is not None and self.target is not None
        self.uncertain = True
        try:
            registration = parse_registration(
                await self._request(
                    self.endpoint, "publications/register", deepcopy(self._payload)
                ),
                self._owner,
                self.target,
            )
            self.current = _Registration(
                self.endpoint, str(registration["registration_id"]), self.target
            )
        except (NativeUnavailable, InvalidResponse, asyncio.CancelledError):
            raise
        except TnlError:
            self.uncertain = False
            raise
        self.uncertain = False

    async def renew(self) -> None:
        self._check()
        if self.current is None:
            raise RegistrationLost()
        await self._request(self.current.endpoint, "renew", self.payload())

    async def status(self) -> object:
        self._check()
        assert self.endpoint is not None
        return await self._request(self.endpoint, "status")

    def stop(self) -> asyncio.Task[list[BaseException]]:
        self.closed = True
        requests = tuple(self._requests)
        for request in requests:
            request.cancel()

        async def join() -> list[BaseException]:
            return [
                result
                for result in await asyncio.gather(*requests, return_exceptions=True)
                if isinstance(result, BaseException)
                and not isinstance(result, asyncio.CancelledError)
            ]

        return asyncio.create_task(join())

    def begin_shutdown(self, until: float) -> float:
        if self._shutdown_until is None or until < self._shutdown_until:
            self._shutdown_until = until
            self._shutdown_timestamp = _shutdown_timestamp(until)
        return self._shutdown_until

    async def discard_candidate(self, until: float) -> None:
        if self.candidate is None:
            return
        # rejected preparation has not acknowledged a listener binding.
        await self._release(
            _Registration(self.candidate.endpoint, self.candidate.registration_id), until, 1
        )
        self.candidate = None

    async def _release(self, registration: _Registration, until: float, attempts: int) -> None:
        if asyncio.get_running_loop().time() >= until:
            raise TimeoutError("publication shutdown timed out; remote cleanup is unconfirmed")
        timestamp = (
            self._shutdown_timestamp
            if until == self._shutdown_until
            else _shutdown_timestamp(until)
        )
        async with asyncio.timeout_at(until):
            for attempt in range(attempts):
                try:
                    await self._native.request(
                        registration.endpoint,
                        "unregister",
                        {
                            **self.payload(registration),
                            "shutdown_deadline": timestamp,
                        },
                    )
                    return
                except RegistrationLost:
                    # absence cannot acknowledge a previously lost cleanup outcome.
                    raise NativeUnavailable() from None
                except NativeUnavailable:
                    if attempt + 1 == attempts:
                        raise
                    await asyncio.sleep(0.1)

    async def unregister(self, until: float, *, attempts: int = 1) -> None:
        until = self.begin_shutdown(until)
        failures: list[BaseException] = []
        async with self.lock:
            if self.uncertain:
                if self._invocation_id is None:
                    failures.append(
                        TnlError(
                            "sdk.dev_unavailable",
                            "native registration cleanup could not be confirmed",
                        )
                    )
                else:
                    if asyncio.get_running_loop().time() >= until:
                        raise TimeoutError(
                            "publication shutdown timed out; remote cleanup is unconfirmed"
                        )
                    async with asyncio.timeout_at(until):
                        for attempt in range(attempts):
                            try:
                                await self.acquire_invocation(cleanup=True)
                                break
                            except NativeUnavailable:
                                if attempt + 1 == attempts:
                                    raise
                                await asyncio.sleep(0.1)
            registrations = list(
                dict.fromkeys(item for item in (self.current, self.candidate) if item is not None)
            )
            for registration in registrations:
                try:
                    await self._release(registration, until, attempts)
                except PublicationCleanupFailed as cause:
                    failures.append(cause)
                except BaseException as cause:
                    failures.append(cause)
                    continue
                if self.current == registration:
                    self.current = None
                if self.candidate == registration:
                    self.candidate = None
            if not failures:
                self.uncertain = False
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("native registration cleanup failed", failures)
