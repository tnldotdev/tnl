"""independent Python runtime selection, bindings and joined ownership."""

from __future__ import annotations

import asyncio
import contextvars
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from starlette.applications import Starlette
from test_asgi import FakeNative
from test_publication import PublicationRuntime
from test_workload_connections import prepared

import tnl
from tnl import _connections, _runtime


class ScopedNative:
    """native replies keyed by registry and selection; no SDK identity parsing."""

    def __init__(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.root = root
        self.calls: list[tuple[tuple[str, ...], Mapping[str, str | None] | None]] = []
        self.owners: dict[tuple[str, str | None], str] = {}
        self.registries: dict[str, str] = {}
        self.closed: set[str] = set()
        self.previews: list[dict[str, object]] = []
        self.deadline = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        self.fail_close = False
        self.order: list[str] = []
        monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
        monkeypatch.setattr(_connections, "_command", self.command)
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
            ) -> object:
                if preview:
                    assert selection is not None
                    return fixture.preview(selection["sdk_workload"])
                return fixture.select(fixture.registries[self.file], name, assertion)

            def close(self) -> None:
                pass

        monkeypatch.setattr(_connections, "OwnerIPC", IPC)

    def preview(self, request: object) -> object:
        assert isinstance(request, dict)
        self.previews.append(dict(request))
        return {
            "schema": 1,
            "name": request.get("name", "platform"),
            "policy": "a" * 64,
            "directory": str(self.root),
            "manifest": str(self.root / ".tnl/generated/workloads.json"),
            "source": "callback" if request.get("callback") is True else "native",
        }

    def select(self, registry: str, service: str, assertion: str | None) -> object:
        key = (registry, assertion)
        if key not in self.owners:
            file = str(self.root / f"native-{len(self.owners)}.json")
            self.owners[key] = file
            self.registries[file] = registry
        file = self.owners[key]
        assert file not in self.closed
        return {
            "schema": 1,
            "owner": {
                "executable": str(Path(sys.executable).resolve()),
                "connection_handle": file,
                "expires_at": self.deadline,
            },
            "prepared": prepared(service, self.deadline),
        }

    def command(
        self,
        binary: Path,
        *args: str,
        input_value: object = None,
        environment: Mapping[str, str | None] | None = None,
    ) -> object:
        self.calls.append((args, environment))
        if args[0] == "sdk-workload":
            assert isinstance(input_value, dict)
            return self.preview(input_value["sdk_workload"])
        if args[0] == "sdk-prepare":
            assert isinstance(input_value, dict)
            return self.select(
                args[args.index("--registry") + 1],
                args[args.index("--selected-service") + 1],
                cast(str | None, input_value.get("assertion")),
            )
        if args[0] == "sdk-close":
            self.order.append("native")
            if self.fail_close:
                raise tnl.TnlError("sdk.connection_unavailable", "native cleanup failed")
            self.closed.add(args[args.index("--handle") + 1])
            return {"schema": 1, "state": "stopped"}
        if args[0] == "sdk-stop":
            self.order.append("native")
            registry = args[args.index("--registry") + 1]
            self.closed.update(
                file for file, selected in self.registries.items() if selected == registry
            )
            return {"schema": 1, "state": "stopped"}
        assert args[0] == "read" and args[args.index("--handle") + 1] not in self.closed
        return prepared(args[-1], self.deadline)


def test_instances_pin_selection_without_native_work_or_ambient_handle_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = ScopedNative(tmp_path, monkeypatch)
    monkeypatch.setenv("TNL_CONNECTION_HANDLE", "/private/ambient.json")
    monkeypatch.setenv("TNL_STATE_DIR", str(tmp_path / "state-a"))
    monkeypatch.setenv("TNL_SERVER", "https://control-a.example")
    app = tnl.create_tnl(directory=tmp_path)
    handle = app.connect("db")
    assert not native.calls
    monkeypatch.setenv("TNL_STATE_DIR", str(tmp_path / "state-b"))
    monkeypatch.setenv("TNL_SERVER", "https://control-b.example")

    async def scenario() -> None:
        try:
            assert isinstance(await handle, tnl.PostgresConnection)
            environment = native.calls[0][1]
            assert environment is not None
            assert environment["TNL_CONNECTION_HANDLE"] is None
            assert environment["TNL_STATE_DIR"] == str(tmp_path / "state-a")
            assert environment["TNL_SERVER"] == "https://control-a.example"
            assert (await handle).port == handle.snapshot().port
        finally:
            await app.aclose()

    asyncio.run(scenario())


def test_equal_instances_keep_native_owners_and_cleanup_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = ScopedNative(tmp_path, monkeypatch)
    first, sibling = tnl.create_tnl(directory=tmp_path), tnl.create_tnl(directory=tmp_path)

    async def scenario() -> None:
        a, b = first.connect("db"), sibling.connect("db")
        await a
        await b
        assert a._session.handle != b._session.handle
        await first.aclose()
        assert a._session.handle in native.closed and b._session.handle not in native.closed
        with pytest.raises(tnl.TnlError) as error:
            await a
        assert error.value.code == "sdk.connection_closed"
        assert (await b).port == b.snapshot().port
        await sibling.aclose()

    asyncio.run(scenario())


def test_scoped_callbacks_select_each_getter_and_reuse_a_b_a_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = ScopedNative(tmp_path, monkeypatch)
    current = contextvars.ContextVar("assertion", default="first")
    global_calls: list[str] = []

    def global_token() -> str:
        global_calls.append("called")
        return "global"

    unrelated = tnl.create_tnl(credential=tnl.Workload("global", token=global_token))
    app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("job", token=current.get))
    monkeypatch.setenv("TNL_WORKLOAD", "changed")
    created: list[object] = []
    closed: list[object] = []

    def create(_: tnl.Connection) -> object:
        value = object()
        created.append(value)
        return value

    async def scenario() -> None:
        get = app.client("db", create=create, close=closed.append)
        first = await get()
        current.set("second")
        second = await get()
        current.set("first")
        native.deadline = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        assert await get() is first and second is not first
        assert len(created) == 2 and not global_calls
        await unrelated.aclose()
        assert all(request["name"] == "job" for request in native.previews)
        for request in native.previews:
            runtime = request["runtime"]
            assert isinstance(runtime, dict) and "workload" not in runtime
        await app.aclose()
        assert len(closed) == 2

    asyncio.run(scenario())


def test_failed_publication_drain_keeps_clients_and_native_ownership_for_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = ScopedNative(tmp_path, monkeypatch)
    app = tnl.create_tnl(directory=tmp_path)

    class Publication:
        fail = True

        async def close(self) -> None:
            native.order.append("publication")
            if self.fail:
                raise tnl.TnlError("sdk.publication_failed", "drain failed")

    publication = Publication()
    app._publications.add(publication)

    async def scenario() -> None:
        get = app.client(
            "db",
            create=lambda connection: connection,
            close=lambda _: native.order.append("client"),
        )
        await get()
        with pytest.raises(BaseExceptionGroup):
            await app.aclose()
        assert native.order == ["publication"]
        with pytest.raises(tnl.TnlError) as caught:
            await get()
        assert caught.value.code == "sdk.client_closed"
        publication.fail = False
        await app.aclose()
        assert native.order == ["publication", "publication", "client", "native"]

    asyncio.run(scenario())


def test_instance_close_joins_late_client_creation_before_releasing_native(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = ScopedNative(tmp_path, monkeypatch)
    app = tnl.create_tnl(directory=tmp_path)

    async def scenario() -> None:
        entered, release = asyncio.Event(), asyncio.Event()
        closed: list[object] = []
        value = object()

        async def create(_: tnl.Connection) -> object:
            entered.set()
            await release.wait()
            return value

        get = app.client("db", create=create, close=closed.append)
        creating = asyncio.create_task(get())
        await entered.wait()
        closing = asyncio.create_task(app.aclose())
        await asyncio.sleep(0)
        assert not closing.done() and not native.closed
        release.set()
        with pytest.raises(tnl.TnlError) as error:
            await creating
        assert error.value.code == "sdk.client_closed"
        await closing
        assert closed == [value] and native.closed

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel", [False, True])
def test_pending_workload_callback_is_joined_without_human_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cancel: bool,
) -> None:
    native = ScopedNative(tmp_path, monkeypatch)

    async def scenario() -> None:
        entered, release = asyncio.Event(), asyncio.Event()

        async def token() -> str:
            entered.set()
            await release.wait()
            return "first"

        app = tnl.create_tnl(directory=tmp_path, credential=tnl.Workload("job", token=token))
        handle = app.connect("db")

        async def prepare() -> tnl.Connection:
            return await handle

        pending = asyncio.create_task(prepare())
        await entered.wait()
        if cancel:
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        closing = asyncio.create_task(app.aclose())
        await asyncio.sleep(0)
        assert not closing.done()
        release.set()
        if not cancel:
            with pytest.raises(tnl.TnlError) as caught:
                await pending
            assert caught.value.code == "sdk.connection_closed"
        await closing
        assert not native.owners

    asyncio.run(scenario())


def test_prepared_publications_belong_to_their_instance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native_app_assignment: dict[str, object],
) -> None:
    native = PublicationRuntime(native_app_assignment)
    monkeypatch.setattr(_runtime, "NativeRuntime", lambda environment: native)
    app = tnl.create_tnl(directory=tmp_path)

    async def scenario() -> None:
        prepared = await app.prepare(service="web")
        publication = await prepared.register("http://127.0.0.1:3000")
        assert isinstance(publication, tnl.Publication)
        await app.aclose()
        await publication.finished()
        assert [operation for operation, _ in native.operations].count("unregister") == 1

    asyncio.run(scenario())


def test_platform_selected_instance_cannot_publish_via_a_personal_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    app = tnl.create_tnl(directory=tmp_path)
    monkeypatch.delenv("GITHUB_ACTIONS")

    async def asgi(scope: object, receive: object, send: object) -> None:
        pass

    async def scenario() -> None:
        with pytest.raises(tnl.TnlError) as caught:
            await app.prepare()
        assert caught.value.code == "sdk.workload_denied"
        with pytest.raises(tnl.TnlError) as caught:
            async with app.publish(asgi):
                pass
        assert caught.value.code == "sdk.workload_denied"
        await app.aclose()

    asyncio.run(scenario())


def test_instance_asgi_cleanup_drains_native_before_listener_and_clients(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = ScopedNative(tmp_path, monkeypatch)
    events: list[str] = []
    native = FakeNative(events)
    monkeypatch.setattr(_runtime, "NativeRuntime", lambda environment: native)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        events.append("lifespan.start")
        yield
        events.append("lifespan.stop")

    async def scenario() -> None:
        app = tnl.create_tnl(directory=tmp_path)
        get = app.client(
            "db",
            create=lambda connection: connection,
            close=lambda _: events.append("client.close"),
        )
        await get()
        async with app.publish(Starlette(lifespan=lifespan)) as publication:
            assert publication.url is not None
            await app.aclose()
            await publication.finished()
        assert (
            events.index("unregister")
            < events.index("lifespan.stop")
            < events.index("client.close")
        )
        assert connector.closed

    asyncio.run(scenario())


def test_scoped_native_launch_environment_pins_selection_but_not_rotating_tokens(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TNL_STATE_DIR", str(tmp_path / "first"))
    monkeypatch.setenv("VERCEL_OIDC_TOKEN", "first-token")
    app = tnl.create_tnl(directory=tmp_path)
    monkeypatch.setenv("TNL_STATE_DIR", str(tmp_path / "changed"))
    monkeypatch.setenv("TNL_APP_ENDPOINT", "/private/ambient-endpoint")
    monkeypatch.setenv("VERCEL_OIDC_TOKEN", "rotated-token")
    environment = app._native.environment()
    assert environment["TNL_STATE_DIR"] == str(tmp_path / "first")
    assert environment["VERCEL_OIDC_TOKEN"] == "rotated-token"
    assert "TNL_APP_ENDPOINT" not in environment and "TNL_CONNECTION_HANDLE" not in environment
    asyncio.run(app.aclose())


@pytest.mark.parametrize(
    "selection",
    [
        "http://control.example",
        "https://user:secret@control.example",
        "https://control.example/path",
        "https://control.example:99999",
        "https://control.example/#fragment",
    ],
)
def test_instance_rejects_invalid_server_selection_without_private_output(
    tmp_path: Path,
    selection: str,
) -> None:
    with pytest.raises(tnl.TnlError) as caught:
        tnl.create_tnl(directory=tmp_path, server=selection)
    assert caught.value.code == "sdk.configuration_invalid" and selection not in str(caught.value)
