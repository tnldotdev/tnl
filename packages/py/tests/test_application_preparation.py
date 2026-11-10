"""exact application publication preparation over the existing registration owner."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_application_http import PUBLISH, SERVICE, URL, Authority, document, grants
from test_token_http import TOKEN

import tnl
from tnl import _app, _credential, _runtime
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, InvalidResponse, NativeUnavailable


class Native(NativeRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.starts: list[tuple[str, str | None, dict[str, str]]] = []
        self.environments: list[dict[str, str | None]] = []
        self.entries: dict[str, dict[str, object]] = {}
        self.public = True
        self.fail_prepare = False
        self.fail_register = False
        self.fail_renew = False
        self.fail_cleanup: set[str] = set()
        self.wait = False
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cleanup_failed = asyncio.Event()
        self.reply: Callable[[dict[str, object]], dict[str, object]] | None = None

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def select(environment: Mapping[str, str | None]) -> Native:
            self._environment = dict(environment)
            self.environments.append(dict(environment))
            return self

        monkeypatch.setattr(_runtime, "NativeRuntime", select)

    async def start(
        self,
        directory: str,
        *,
        service: str | None = None,
        invocation_id: str | None = None,
        state_dir: str | None = None,
    ) -> Endpoint:
        assert service is None and invocation_id is not None
        self.starts.append((directory, state_dir, dict(self.environment())))
        return Endpoint(
            "http://127.0.0.1:12345", "b" * 64, "a" * 32, "invocation", invocation_id=invocation_id
        )

    async def request(
        self,
        endpoint: Endpoint,
        operation: str,
        payload: dict[str, object] | None = None,
    ) -> object:
        self.calls.append((operation, dict(payload or {})))
        assert endpoint.invocation_id is not None
        invocation = endpoint.invocation_id
        if operation == "publications/prepare":
            assert payload is not None
            assert set(payload) == {
                "version",
                "invocation_id",
                "owner",
                "pid",
                "server_url",
                "application_credential",
                "resource_id",
            }
            assert payload["invocation_id"] == invocation
            parsed = _credential.application_document(payload["application_credential"])
            assert len(parsed.grants) == 1 and parsed.grants[0].operation == "publish"
            assert parsed.control_url == payload["server_url"] == "https://control.example"
            assert parsed.grants[0].resource == payload["resource_id"]
            entry = self.entries.setdefault(
                invocation,
                {
                    "registration_id": "reg_" + f"{len(self.entries) + 1:032x}",
                    "owner": payload["owner"],
                    "resource": payload["resource_id"],
                    "target": None,
                },
            )
            self.started.set()
            if self.wait:
                await self.release.wait()
            if self.fail_prepare:
                self.fail_prepare = False
                raise NativeUnavailable()
            reply: dict[str, object] = {
                "version": 1,
                "registration_id": entry["registration_id"],
                "resource_id": entry["resource"],
                "hostname": "preview.example" if entry["resource"] == PUBLISH else "api.example",
                "public_url": "https://preview.example"
                if entry["resource"] == PUBLISH
                else "https://api.example:20001"
                if self.public
                else "",
            }
            return self.reply(reply) if self.reply else reply
        entry = self.entries[invocation]
        if operation == "publications/register":
            assert payload is not None and payload["owner"] == entry["owner"]
            if self.fail_register:
                self.fail_register = False
                raise NativeUnavailable()
            entry["target"] = payload["target"]
            return None
        if operation == "unregister":
            if invocation in self.fail_cleanup:
                self.cleanup_failed.set()
                raise NativeUnavailable()
            entry["target"] = None
            return None
        if operation == "renew":
            if self.fail_renew:
                self.fail_renew = False
                raise NativeUnavailable()
            return None
        assert operation == "status"
        service: dict[str, object] = {
            "service": invocation,
            "directory": ".",
            "registration_id": entry["registration_id"],
            "target": entry["target"],
            "registered": entry["target"] is not None,
            "routable": False,
            "ready": False,
            "readiness": {"path": "/"},
        }
        return {
            "schema_version": 1,
            "project": "/project",
            "cursor": "cursor",
            "observed_at": datetime.now(UTC).isoformat(),
            "services": [service],
        }


def publisher_document() -> dict[str, object]:
    value = document()
    grants(value).append(
        {
            "id": "pgrant_" + "Q" * 22,
            "operation": "publish",
            "kind": "service",
            "service_id": SERVICE,
        }
    )
    return value


@pytest.mark.parametrize("serialized", [False, True])
@pytest.mark.parametrize("resource,public", [(PUBLISH, True), (SERVICE, True), (SERVICE, False)])
def test_exact_preparation_and_listener_replacement_reuse_the_existing_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    serialized: bool,
    resource: str,
    public: bool,
) -> None:
    native = Native()
    native.public = public
    native.install(monkeypatch)
    monkeypatch.setenv("TNL_SERVER", "https://personal.example")
    monkeypatch.setenv("TNL_PUBLISHER_CREDENTIAL_FILE", "/private/must-not-read.json")
    value = publisher_document()
    app = tnl.create_tnl(
        credential=json.dumps(value) if serialized else value,
        directory=tmp_path,
        state_dir=tmp_path / "state",
    )
    assert not native.calls

    async def scenario() -> None:
        prepared = await app.prepare(resource=resource)
        assert isinstance(prepared, tnl.PreparedPublication)
        expected = (
            "https://preview.example"
            if resource == PUBLISH
            else "https://api.example:20001"
            if public
            else ""
        )
        assert prepared.public_url == expected
        assert [op for op, _ in native.calls] == ["publications/prepare"]
        assert native.starts[0][:2] == (
            str(tmp_path.resolve()),
            str((tmp_path / "state").resolve()),
        )
        assert native.starts[0][2]["TNL_SERVER"] == "https://control.example"
        assert "TNL_PUBLISHER_CREDENTIAL_FILE" not in native.starts[0][2]
        assert str(value["private_key"]) not in repr(prepared)
        first = await prepared.register("http://127.0.0.1:3001")
        assert first.url == (expected or None)
        status = await first.status()
        assert status.registered and not status.routable and not status.ready
        second = await prepared.register("http://127.0.0.1:3002")
        with pytest.raises(tnl.RegistrationLost):
            await first.status()
        await first.close()
        assert not any(op == "unregister" for op, _ in native.calls)
        assert (await second.status()).registered
        await app.aclose()
        assert native.calls[-1][0] == "unregister"
        assert native.calls[-1][1]["target"] == "http://127.0.0.1:3002"
        with pytest.raises(tnl.RegistrationLost):
            await prepared.register("http://127.0.0.1:3003")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "credential,resource", [(TOKEN, PUBLISH), (document(), SERVICE), (publisher_document(), None)]
)
def test_tokens_missing_grants_and_ambiguous_selection_never_start_native(
    monkeypatch: pytest.MonkeyPatch,
    credential: str | dict[str, object],
    resource: str | None,
) -> None:
    native = Native()
    native.install(monkeypatch)

    async def scenario() -> None:
        async with tnl.create_tnl(credential=credential) as app:
            with pytest.raises(tnl.TnlError) as denied:
                await app.prepare(resource=resource)
            assert denied.value.code == "sdk.credential_denied"
            assert not native.starts and not native.calls

    asyncio.run(scenario())


def test_canceled_preparation_waiter_retains_late_assignment_for_joined_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Native()
    native.wait = True
    native.install(monkeypatch)

    async def scenario() -> None:
        app = tnl.create_tnl(credential=document())
        pending = asyncio.create_task(app.prepare())
        await native.started.wait()
        pending.cancel("only the caller")
        with pytest.raises(asyncio.CancelledError):
            await pending
        closing = asyncio.create_task(app.aclose())
        await asyncio.sleep(0)
        assert not closing.done()
        native.release.set()
        await asyncio.wait_for(asyncio.shield(closing), 1)
        assert [op for op, _ in native.calls] == ["publications/prepare", "unregister"]

    asyncio.run(scenario())


def test_lost_preparation_reply_reconciles_only_the_original_unbound_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Native()
    native.fail_prepare = True
    native.install(monkeypatch)

    async def scenario() -> None:
        app = tnl.create_tnl(credential=document())
        with pytest.raises(NativeUnavailable):
            await app.prepare()
        await app.aclose()
        assert [op for op, _ in native.calls] == [
            "publications/prepare",
            "publications/prepare",
            "unregister",
        ]
        assert native.calls[0][1] == native.calls[1][1]
        assert len(native.entries) == 1

    asyncio.run(scenario())


def test_registration_recovery_reuses_the_pinned_resource_and_bound_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Native()
    native.install(monkeypatch)

    async def scenario() -> None:
        app = tnl.create_tnl(credential=document())
        prepared = await app.prepare()
        native.fail_register = True
        publication = await prepared.register("http://127.0.0.1:3001")
        assert (await publication.status()).registered
        requests = [
            (operation, payload) for operation, payload in native.calls if operation != "status"
        ]
        assert [operation for operation, _ in requests] == [
            "publications/prepare",
            "publications/register",
            "publications/prepare",
            "publications/register",
        ]
        assert requests[0][1] == requests[2][1]
        assert requests[1][1] == requests[3][1]
        assert len(native.entries) == 1
        await app.aclose()

    asyncio.run(scenario())


def test_cleanup_failure_fences_new_work_and_is_retryable_without_stopping_a_sibling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Native()
    native.install(monkeypatch)

    async def scenario() -> None:
        app, sibling = tnl.create_tnl(credential=document()), tnl.create_tnl(credential=document())
        first, other = await app.prepare(), await sibling.prepare()
        await first.register("http://127.0.0.1:3001")
        peer = await other.register("http://127.0.0.1:3002")
        invocation = next(iter(native.entries))
        native.fail_cleanup.add(invocation)
        with pytest.raises(ExceptionGroup):
            await app.aclose()
        with pytest.raises(tnl.RegistrationLost):
            await first.register("http://127.0.0.1:3003")
        assert (await peer.status()).registered
        native.fail_cleanup.clear()
        await app.aclose()
        assert (await peer.status()).registered
        await sibling.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("fault", ["resource", "public_url", "id", "extra"])
def test_invalid_assignment_retains_reconcilable_cleanup_before_exposing_a_handle(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    native = Native()
    native.install(monkeypatch)

    def reply(value: dict[str, object]) -> dict[str, object]:
        if fault == "resource":
            value["resource_id"] = SERVICE
        if fault == "public_url":
            value["public_url"] = "https://preview.example:20001"
        if fault == "id":
            value["registration_id"] = "private-invalid"
        if fault == "extra":
            value["credential"] = "private-invalid"
        return value

    native.reply = reply

    async def scenario() -> None:
        app = tnl.create_tnl(credential=document())
        with pytest.raises(InvalidResponse):
            await app.prepare()
        native.reply = None
        await app.aclose()
        assert native.calls[0][1] == native.calls[1][1]
        assert native.calls[-1][0] == "unregister"

    asyncio.run(scenario())


def test_expired_publish_grant_fences_retained_handles_but_does_not_prevent_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Native()
    native.install(monkeypatch)
    value = document()
    now = time.time()
    grants(value)[2]["expires_at"] = datetime.fromtimestamp(now + 60, UTC).isoformat()

    async def scenario() -> None:
        app = tnl.create_tnl(credential=value)
        prepared = await app.prepare()
        publication = await prepared.register("http://127.0.0.1:3001")
        monkeypatch.setattr(_credential.time, "time", lambda: now + 61)
        with pytest.raises(tnl.TnlError) as expired:
            await prepared.register("http://127.0.0.1:3002")
        assert expired.value.code == "sdk.credential_denied"
        await publication.close()
        await app.aclose()
        assert native.calls[-1][0] == "unregister"

    asyncio.run(scenario())


def test_runtime_cleanup_keeps_ordinary_clients_until_prepared_native_cleanup_is_confirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    authority = Authority(monkeypatch, value)
    native = Native()
    native.install(monkeypatch)
    closed: list[object] = []

    async def scenario() -> None:
        app = tnl.create_tnl(credential=value)
        get = app.client(URL, create=lambda _: object(), close=closed.append)
        ordinary = await get()
        prepared = await app.prepare()
        await prepared.register("http://127.0.0.1:3001")
        native.fail_cleanup.update(native.entries)
        with pytest.raises(ExceptionGroup):
            await app.aclose()
        assert not closed and authority.closed == 0
        native.fail_cleanup.clear()
        await app.aclose()
        assert closed == [ordinary] and authority.closed == 1

    asyncio.run(scenario())


def test_expiry_finishes_the_retained_publication_without_acquiring_another_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Native()
    native.install(monkeypatch)
    monkeypatch.setattr(_app, "_RENEW_INTERVAL", 0.001)
    value = document()
    now = time.time()
    grants(value)[2]["expires_at"] = datetime.fromtimestamp(now + 60, UTC).isoformat()

    async def scenario() -> None:
        app = tnl.create_tnl(credential=value)
        prepared = await app.prepare()
        publication = await prepared.register("http://127.0.0.1:3001")
        monkeypatch.setattr(_credential.time, "time", lambda: now + 61)
        with pytest.raises(tnl.TnlError) as expired:
            await asyncio.wait_for(publication.finished(), 1)
        assert expired.value.code == "sdk.credential_denied"
        assert len(native.starts) == 1
        await app.aclose()
        assert native.calls[-1][0] == "unregister"

    asyncio.run(scenario())


def test_changed_recovery_assignment_retains_rejected_cleanup_for_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Native()
    native.install(monkeypatch)
    monkeypatch.setattr(_app, "_RENEW_INTERVAL", 0.001)

    async def scenario() -> None:
        app = tnl.create_tnl(credential=document())
        prepared = await app.prepare()
        await prepared.register("http://127.0.0.1:3001")
        original = native.calls[0][1]
        native.reply = lambda reply: {
            **reply,
            "hostname": "other.example",
            "public_url": "https://other.example",
            "registration_id": "reg_" + "d" * 32,
        }
        native.fail_cleanup.update(native.entries)
        native.fail_renew = True
        await asyncio.wait_for(native.cleanup_failed.wait(), 1)
        assert native.calls[3][1] == original
        with pytest.raises(ExceptionGroup):
            await app.aclose()
        native.fail_cleanup.clear()
        await app.aclose()
        cleanups = [
            payload["registration_id"]
            for operation, payload in native.calls
            if operation == "unregister"
        ]
        assert cleanups[-2:] == ["reg_" + "d" * 32, "reg_" + f"{1:032x}"]

    asyncio.run(scenario())
