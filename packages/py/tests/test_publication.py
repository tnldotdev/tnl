"""shared native observations and configured registration ownership."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import cast

import pytest

import tnl
from tnl._native import NativeRuntime
from tnl._protocol import (
    Endpoint,
    InvalidResponse,
    NativeUnavailable,
    RegistrationLost,
    TnlError,
    parse_events,
    parse_status,
)


class PublicationRuntime(NativeRuntime):
    def __init__(self, assignment: dict[str, object]) -> None:
        self.assignment = assignment
        self.endpoint = Endpoint("http://127.0.0.1:1234", "b" * 64, "a" * 32, "app", service="web")
        self.target = ""
        self.operations: list[tuple[str, dict[str, object] | None]] = []
        self.ready = True
        self.fail_close = False
        self.failure: str | None = None
        self.gate: asyncio.Event | None = None
        self.entered = asyncio.Event()
        self.expired: TnlError | None = None

    async def start(
        self,
        directory: str,
        *,
        service: str | None = None,
        invocation_id: str | None = None,
        state_dir: str | None = None,
    ) -> Endpoint:
        return self.endpoint

    def snapshot(self, checked: bool = False) -> dict[str, object]:
        service: dict[str, object] = {
            "service": "web",
            "directory": ".",
            "registration_id": self.assignment["registration_id"],
            "target": self.target,
            "tunnel_id": "tunnel",
            "registered": True,
            "routable": True,
            "ready": checked and self.ready,
            "run_number": 2,
            "readiness": {"path": "/ready"},
            "public_url": "https://web.example",
        }
        if checked:
            service["observation"] = {
                "registration_id": self.assignment["registration_id"],
                "run_number": 2,
                "checked_at": datetime.now(UTC).isoformat(),
                "ready": self.ready,
                "readiness": {"path": "/ready"},
            }
        if self.failure is not None:
            service["failure"] = self.failure
        return {
            "schema_version": 1,
            "project": "/project",
            "cursor": "initial",
            "observed_at": datetime.now(UTC).isoformat(),
            "services": [service],
        }

    async def request(
        self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
    ) -> object:
        self.operations.append((operation, payload))
        if operation == "prepare":
            return self.assignment
        if operation == "register":
            assert payload is not None
            self.target = str(payload["target"])
        if operation == "unregister" and self.fail_close:
            raise NativeUnavailable()
        if operation in {"status", "check"}:
            if self.gate is not None:
                self.entered.set()
                await self.gate.wait()
            return self.snapshot(operation == "check")
        if operation == "events":
            if self.expired is not None:
                raise self.expired
            return [{"cursor": "next", "type": "cursor", "at": datetime.now(UTC).isoformat()}]
        return None


def test_configured_registration_returns_common_handle_without_probing(
    native_app_assignment: dict[str, object],
) -> None:
    async def scenario() -> None:
        native = PublicationRuntime(native_app_assignment)
        prepared = tnl.PreparedService("/project", "web", None, native)
        await prepared.start()
        try:
            handle = await prepared.register("http://127.0.0.1:3000")
            assert isinstance(handle, tnl.Publication)
            assert [operation for operation, _ in native.operations] == ["prepare", "register"]
            status = await handle.status()
            assert (
                status.routable
                and not status.ready
                and status.publish_run_number == 2
                and status.cursor == "initial"
            )
            await handle.wait(until="routable")
            assert native.operations[-1] == ("status", None)
            await handle.wait()
            assert native.operations[-1] == ("check", {"services": ["web"]})
            await handle.close()
            await handle.finished()
        finally:
            await prepared.close()

    asyncio.run(scenario())


def test_observation_cancellation_does_not_close_publication(
    native_app_assignment: dict[str, object],
) -> None:
    async def scenario() -> None:
        native = PublicationRuntime(native_app_assignment)
        prepared = tnl.PreparedService("/project", "web", None, native)
        await prepared.start()
        try:
            handle = await prepared.register("http://127.0.0.1:3000")
            native.gate = asyncio.Event()
            waiting = asyncio.create_task(handle.wait())
            await native.entered.wait()
            waiting.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiting
            assert not any(operation == "unregister" for operation, _ in native.operations)
            native.gate = None
            assert (await handle.status()).routable
            finished = asyncio.create_task(handle.finished())
            await asyncio.sleep(0)
            finished.cancel()
            with pytest.raises(asyncio.CancelledError):
                await finished
            await handle.close()
            await handle.finished()
        finally:
            await prepared.close()

    asyncio.run(scenario())


def test_superseded_handles_cannot_close_replacement_and_cleanup_can_retry(
    native_app_assignment: dict[str, object],
) -> None:
    async def scenario() -> None:
        native = PublicationRuntime(native_app_assignment)
        prepared = tnl.PreparedService("/project", "web", None, native)
        await prepared.start()
        try:
            first = await prepared.register("http://127.0.0.1:3000")
            replacement = await prepared.register("http://127.0.0.1:4000")
            await first.finished()
            await first.close()
            with pytest.raises(RegistrationLost):
                await first.status()
            assert not any(operation == "unregister" for operation, _ in native.operations)
            native.fail_close = True
            with pytest.raises(NativeUnavailable):
                await replacement.close()
            native.fail_close = False
            await replacement.close()
            await replacement.finished()
            third = await prepared.register("http://127.0.0.1:5000")
            assert (await third.status()).registered
        finally:
            await prepared.close()

    asyncio.run(scenario())


def test_watch_resumes_native_exclusive_cursors_and_retains_expiry(
    native_app_assignment: dict[str, object],
) -> None:
    async def scenario() -> None:
        native = PublicationRuntime(native_app_assignment)
        prepared = tnl.PreparedService("/project", "web", None, native)
        await prepared.start()
        try:
            handle = await prepared.register("http://127.0.0.1:3000")
            stream = handle.watch()
            assert (await anext(stream)).type == "snapshot"
            assert (await anext(stream)).cursor == "next"
            assert native.operations[-1] == ("events", {"after": "initial"})
            await stream.aclose()
            resumed = handle.watch(after="saved")
            assert (await anext(resumed)).type == "cursor"
            assert native.operations[-1] == ("events", {"after": "saved"})
            await resumed.aclose()
            native.expired = TnlError("sdk.event_cursor_expired", "read status")
            with pytest.raises(TnlError) as caught:
                await anext(handle.watch(after="expired"))
            assert caught.value is native.expired
        finally:
            await prepared.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("boundary", ["registration", "run", "path"])
def test_ready_status_requires_exact_registration_run_and_path(
    boundary: str, native_app_assignment: dict[str, object]
) -> None:
    native = PublicationRuntime(native_app_assignment)
    raw = native.snapshot(True)
    services = cast(list[dict[str, object]], raw["services"])
    observed = cast(dict[str, object], services[0]["observation"])
    if boundary == "registration":
        observed["registration_id"] = "reg_" + "b" * 32
    if boundary == "run":
        observed["run_number"] = 1
    if boundary == "path":
        observed["readiness"] = {"path": "/other"}
    with pytest.raises(InvalidResponse):
        parse_status(raw, "web", str(native.assignment["registration_id"]), native.target)


def test_publication_watch_rejects_sibling_payloads_and_removed_api_has_no_alias() -> None:
    assert not hasattr(tnl, "open") and not hasattr(tnl, "Tunnel")
    with pytest.raises(InvalidResponse):
        parse_events(
            [
                {
                    "cursor": "next",
                    "type": "changed",
                    "at": datetime.now(UTC).isoformat(),
                    "publication": {"service": "private-sibling", "tunnel_id": "other"},
                }
            ],
            "web",
            "own",
        )


def test_finished_reports_terminal_native_failure(native_app_assignment: dict[str, object]) -> None:
    async def scenario() -> None:
        native = PublicationRuntime(native_app_assignment)
        prepared = tnl.PreparedService("/project", "web", None, native)
        await prepared.start()
        try:
            handle = await prepared.register("http://127.0.0.1:3000")
            native.failure = "runtime.publication_failed"
            with pytest.raises(TnlError) as caught:
                await handle.finished()
            assert caught.value.code == "sdk.publication_failed"
        finally:
            await prepared.close()

    asyncio.run(scenario())


def test_pending_status_cannot_cross_replacement_and_prepared_close_retains_failed_drain(
    native_app_assignment: dict[str, object],
) -> None:
    async def scenario() -> None:
        native = PublicationRuntime(native_app_assignment)
        prepared = tnl.PreparedService("/project", "web", None, native)
        await prepared.start()
        first = await prepared.register("http://127.0.0.1:3000")
        native.gate = asyncio.Event()
        pending = asyncio.create_task(first.status())
        await native.entered.wait()
        replacement = await prepared.register("http://127.0.0.1:4000")
        with pytest.raises(RegistrationLost):
            await pending
        native.gate = None
        native.fail_close = True
        with pytest.raises(NativeUnavailable):
            await prepared.close()
        native.fail_close = False
        await prepared.close()
        await replacement.finished()
        assert [operation for operation, _ in native.operations].count("unregister") == 2

    asyncio.run(scenario())
