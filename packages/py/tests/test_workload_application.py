"""publication and visiting share native source selection without sharing SDK lifetimes."""

from __future__ import annotations

import asyncio
import contextvars
import copy
import hashlib
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_application_asgi import ApplicationNative, asgi
from test_application_http import PUBLISH, document, grants
from test_application_preparation import Native as PreparationNative
from test_runtime import ScopedNative

import tnl
from tnl import _app, _asgi, _connections, _workload_application


class Sources(ScopedNative):
    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        super().__init__(root, monkeypatch)
        self.documents = {identity: document() for identity in ("A", "B")}
        self.fault: str | None = None
        self.refresh_denied = False
        self.started, self.release = threading.Event(), threading.Event()
        self.wait = False
        self.ipc_calls: list[tuple[str, bool, str | None]] = []
        self.ipc_closed: list[str] = []
        self.leases = {identity: time.time() + 60 for identity in ("A", "B")}
        fixture = self

        class IPC:
            def __init__(self, file: str) -> None:
                self.file = file

            def prepare(
                self,
                name: str,
                assertion: str | None = None,
                *,
                sdk: bool = False,
                requested_at: str | None = None,
                request_handle: str | None = None,
                selection: dict[str, object] | None = None,
                preview: bool = False,
                application: bool = False,
            ) -> object:
                if preview:
                    assert selection is not None
                    return fixture.preview(selection["sdk_workload"])
                if application and not sdk:
                    identity = next(
                        key[1] for key, file in fixture.owners.items() if file == self.file
                    )
                    assert identity is not None
                    fixture.ipc_calls.append((identity, selection is not None, assertion))
                    if selection is not None and (fixture.refresh_denied or assertion != identity):
                        return {"schema": 1, "reason": "TNL_CLIENT_WORKLOAD_SERVICE_DENIED"}
                    return fixture.application(identity)
                return fixture.select(
                    fixture.registries[self.file], "" if application else name, assertion
                )

            def close(self) -> None:
                fixture.ipc_closed.append(self.file)

        monkeypatch.setattr(_connections, "OwnerIPC", IPC)
        monkeypatch.setattr(_workload_application, "OwnerIPC", IPC)

    def application(self, identity: str) -> dict[str, object]:
        credential = copy.deepcopy(self.documents[identity])
        if self.fault == "grant":
            credential["grants"] = []
        if self.fault == "grant_id":
            grants(credential)[2]["id"] = "pgrant_" + "Z" * 22
        if self.fault == "key":
            credential["key_id"] = "pkey_" + "Z" * 22
        if self.fault == "private_key":
            credential["private_key"] = self.documents["B"]["private_key"]
        if self.fault == "control":
            credential["control_url"] = "https://other.example"
        proof: dict[str, object] = {
            "digest": hashlib.sha256(identity.encode()).hexdigest(),
            "binding": identity.lower() * 64,
            "expires_at": datetime.fromtimestamp(time.time() + 60, UTC).isoformat(),
        }
        if self.fault == "proof":
            proof["expires_at"] = "2020-01-01T00:00:00Z"
        if self.fault == "binding":
            proof["binding"] = "z" * 64
        return {
            "schema": 1,
            "credential": credential,
            "source_session_id": "wls_" + ("Z" if self.fault == "session" else identity) * 22,
            "lease_expires_at": datetime.fromtimestamp(
                time.time() - 1
                if self.fault == "lease"
                else time.time() + 120
                if self.fault == "duration"
                else self.leases[identity],
                UTC,
            ).isoformat(),
            "verification": proof,
        }

    def select(self, registry: str, service: str, assertion: str | None) -> object:
        selected = super().select(registry, service or "db", assertion)
        assert isinstance(selected, dict)
        if service:
            return selected
        assert assertion in {"A", "B"}
        selected.pop("prepared")
        selected["application"] = self.application(assertion)
        self.started.set()
        if self.wait:
            assert self.release.wait(3)
        return selected

    def command(
        self,
        binary: Path,
        *args: str,
        input_value: object = None,
        environment: Mapping[str, str | None] | None = None,
    ) -> object:
        if args[0] == "sdk-application":
            self.calls.append((args, environment))
            assert isinstance(input_value, dict) and input_value["assertion"] in {"A", "B"}
            assert "--selected-service" not in args and "--retain-start-failure" not in args
            assert "--sdk-request-handle" in args
            return self.select(
                args[args.index("--registry") + 1], "", str(input_value["assertion"])
            )
        return super().command(binary, *args, input_value=input_value, environment=environment)


def test_source_acquisition_shares_the_visitor_registry_and_reuses_a_b_a_owners(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Sources(tmp_path, monkeypatch)
    current = contextvars.ContextVar("assertion", default="A")
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=current.get))

    async def scenario() -> None:
        a = await app._application()
        await a.authorize(PUBLISH)
        visitor = await app.connect("db")
        assert visitor.protocol == "postgres"
        assert len(native.owners) == 1
        current.set("B")
        b = await app._application()
        await a.authorize(PUBLISH)
        assert a.document.key.private_bytes_raw() != b.document.key.private_bytes_raw()
        current.set("A")
        again = await app._application()
        assert again.document.key.private_bytes_raw() == a.document.key.private_bytes_raw()
        assert len(native.owners) == 2
        assert [args[0] for args, _ in native.calls].count("sdk-application") == 1
        assert not any(args[0] == "sdk-prepare" for args, _ in native.calls)
        await app.aclose()
        assert len(native.closed) == 2 and len(app._sources) == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault",
    [
        "grant",
        "grant_id",
        "key",
        "private_key",
        "control",
        "proof",
        "binding",
        "session",
        "lease",
        "duration",
    ],
)
def test_source_refresh_cannot_borrow_changed_authority_or_another_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    native = Sources(tmp_path, monkeypatch)
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=lambda: "A"))

    async def scenario() -> None:
        source = await app._application()
        native.refresh_denied = True
        await source.authorize(PUBLISH)
        native.fault = fault
        with pytest.raises(tnl.TnlError) as denied:
            await source.authorize(PUBLISH)
        assert denied.value.code == "sdk.workload_denied"
        native.fault = None
        with pytest.raises(tnl.TnlError):
            source.check(PUBLISH)
        assert len(native.owners) == 1
        await app.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("prepared", [False, True])
def test_workload_publication_retains_source_clients_and_listener_until_drain_is_confirmed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prepared: bool,
) -> None:
    sources = Sources(tmp_path, monkeypatch)
    native = PreparationNative() if prepared else ApplicationNative()
    native.install(monkeypatch)
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=lambda: "A"))
    closed: list[object] = []

    async def scenario() -> None:
        get = app.client("db", create=lambda _: object(), close=closed.append)
        ordinary = await get()
        context = None
        if prepared:
            owner = await app.prepare(resource=PUBLISH)
            assert isinstance(owner, tnl.PreparedPublication)
            publication = await owner.register("http://127.0.0.1:3001")
            assert isinstance(native, PreparationNative)
            native.fail_cleanup.update(native.entries)
        else:
            assert isinstance(native, ApplicationNative)
            context = app.publish(asgi(native.events), resource=PUBLISH)
            publication = await context.__aenter__()
            native.fail_cleanup = True
        assert len(sources.owners) == 1 and len(sources.ipc_calls) >= 1
        with pytest.raises(ExceptionGroup):
            await app.aclose()
        assert not sources.closed and not sources.ipc_closed and not closed
        if isinstance(native, PreparationNative):
            native.fail_cleanup.clear()
        else:
            assert "shutdown" not in native.events
            native.fail_cleanup = False
        await app.aclose()
        assert closed == [ordinary] and sources.closed and sources.ipc_closed
        await publication.finished()
        if context is not None:
            await context.__aexit__(None, None, None)

    asyncio.run(scenario())


def test_canceled_source_waiter_joins_the_native_exchange_before_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Sources(tmp_path, monkeypatch)
    native.wait = True
    publication = PreparationNative()
    publication.install(monkeypatch)
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=lambda: "A"))

    async def scenario() -> None:
        opening = asyncio.create_task(app.prepare(resource=PUBLISH))
        assert await asyncio.to_thread(native.started.wait, 2)
        opening.cancel()
        with pytest.raises(asyncio.CancelledError):
            await opening
        closing = asyncio.create_task(app.aclose())
        try:
            await asyncio.sleep(0)
            assert not closing.done() and not native.closed
        finally:
            native.release.set()
            await asyncio.wait_for(asyncio.shield(closing), 2)
        assert native.closed and not publication.calls

    asyncio.run(scenario())


@pytest.mark.parametrize("prepared", [False, True])
def test_workload_source_expiry_finishes_retained_publication_without_reselecting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prepared: bool,
) -> None:
    sources = Sources(tmp_path, monkeypatch)
    native = PreparationNative() if prepared else ApplicationNative()
    native.install(monkeypatch)
    monkeypatch.setattr(_app, "_RENEW_INTERVAL", 0.001)
    monkeypatch.setattr(_asgi, "_RENEW_INTERVAL", 0.001)
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=lambda: "A"))

    async def scenario() -> None:
        context = None
        if prepared:
            owner = await app.prepare(resource=PUBLISH)
            publication = await owner.register("http://127.0.0.1:3001")
        else:
            assert isinstance(native, ApplicationNative)
            context = app.publish(asgi(native.events), resource=PUBLISH)
            publication = await context.__aenter__()
        sources.fault = "lease"
        with pytest.raises(tnl.TnlError) as denied:
            await asyncio.wait_for(publication.finished(), 1)
        assert denied.value.code == "sdk.workload_denied" and len(sources.owners) == 1
        async with asyncio.timeout(1):
            if isinstance(native, PreparationNative):
                while not any(operation == "unregister" for operation, _ in native.calls):
                    await asyncio.sleep(0)
            else:
                await native.cleanup_started.wait()
        assert not sources.closed
        await app.aclose()
        if context is not None:
            await context.__aexit__(None, None, None)

    asyncio.run(scenario())


def test_source_cached_expiry_is_a_permanent_fence_even_if_native_later_reports_a_new_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Sources(tmp_path, monkeypatch)
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=lambda: "A"))

    async def scenario() -> None:
        source = await app._application()
        now = time.time()
        monkeypatch.setattr(_workload_application.time, "time", lambda: now + 61)
        with pytest.raises(tnl.TnlError):
            source.check(PUBLISH)
        monkeypatch.setattr(_workload_application.time, "time", lambda: now)
        with pytest.raises(tnl.TnlError):
            await source.authorize(PUBLISH)
        assert not native.ipc_calls
        await app.aclose()

    asyncio.run(scenario())


def test_source_grant_expiry_can_narrow_but_cannot_be_restored_on_the_same_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Sources(tmp_path, monkeypatch)
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=lambda: "A"))

    async def scenario() -> None:
        source = await app._application()
        grants(native.documents["A"])[2]["expires_at"] = datetime.fromtimestamp(
            time.time() + 30, UTC
        ).isoformat()
        await source.authorize(PUBLISH)
        grants(native.documents["A"])[2].pop("expires_at")
        with pytest.raises(tnl.TnlError) as denied:
            await source.authorize(PUBLISH)
        assert denied.value.code == "sdk.workload_denied"
        await app.aclose()

    asyncio.run(scenario())


def test_canceled_refresh_waiter_keeps_its_callback_owned_until_source_shutdown_joins_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Sources(tmp_path, monkeypatch)

    async def scenario() -> None:
        started, release = asyncio.Event(), asyncio.Event()
        calls = 0

        async def token() -> str:
            nonlocal calls
            calls += 1
            if calls > 1:
                started.set()
                await release.wait()
            return "A"

        app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=token))
        source = await app._application()
        refreshing = asyncio.create_task(source.authorize(PUBLISH))
        await asyncio.wait_for(started.wait(), 1)
        refreshing.cancel("only the request")
        with pytest.raises(asyncio.CancelledError):
            await refreshing
        closing = asyncio.create_task(app.aclose())
        try:
            await asyncio.sleep(0)
            assert not closing.done() and not native.closed
        finally:
            release.set()
            await asyncio.wait_for(asyncio.shield(closing), 1)
        assert native.closed and native.ipc_closed

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault", ["schema", "extra", "verification", "digest", "session", "lease", "duration", "proof"]
)
def test_prepared_source_rejects_malformed_or_unbounded_native_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    native = Sources(tmp_path, monkeypatch)
    raw = native.application("A")
    if fault == "schema":
        raw["schema"] = True
    if fault == "extra":
        raw["token"] = "private unexpected value"
    if fault == "verification":
        raw["verification"] = None
    if fault == "digest":
        proof = raw["verification"]
        assert isinstance(proof, dict)
        proof["digest"] = "not a digest"
    if fault == "session":
        raw["source_session_id"] = "private unexpected value"
    if fault in {"lease", "duration", "proof"}:
        native.fault = fault
        raw = native.application("A")
    with pytest.raises(tnl.TnlError) as denied:
        _workload_application._prepared(raw)
    assert denied.value.code == "sdk.workload_denied"
    assert denied.value.__context__ is None
    assert "private unexpected" not in str(denied.value)


def test_closed_asgi_context_releases_its_private_source_client_without_stopping_shared_visiting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = Sources(tmp_path, monkeypatch)
    native = ApplicationNative()
    native.install(monkeypatch)
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=lambda: "A"))

    async def scenario() -> None:
        visitor = app.connect("db")
        await visitor
        for _ in range(2):
            async with app.publish(asgi(native.events), resource=PUBLISH):
                assert len(app._sources) == 1
            assert not app._sources and not sources.closed
            assert (await visitor).protocol == "postgres"
        assert len(sources.owners) == 1
        await app.aclose()
        assert sources.closed

    asyncio.run(scenario())


def test_lost_initial_source_reply_retains_the_native_request_receipt_until_joined_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = Sources(tmp_path, monkeypatch)
    command = native.command

    def lost_reply(
        binary: Path,
        *args: str,
        input_value: object = None,
        environment: Mapping[str, str | None] | None = None,
    ) -> object:
        raw = command(binary, *args, input_value=input_value, environment=environment)
        if args[0] == "sdk-application":
            raise _connections._InterruptedError(
                "sdk.connection_unavailable", "the native reply was lost"
            )
        return raw

    monkeypatch.setattr(_connections, "_command", lost_reply)
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("deploy", token=lambda: "A"))

    async def scenario() -> None:
        with pytest.raises(tnl.TnlError) as unavailable:
            await app.prepare(resource=PUBLISH)
        assert unavailable.value.code == "sdk.connection_unavailable"
        receipts = tuple(Path(file) for file in app._scope.request_handles)
        assert len(receipts) == 1 and receipts[0].exists() and native.owners
        await app.aclose()
        assert native.closed and not receipts[0].exists() and not app._scope.request_handles

    asyncio.run(scenario())
