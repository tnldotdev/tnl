"""native process bounds, sync/async lifecycle, and verified Python TLS snapshots."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import ssl
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tnl
from tnl import _connections


def snapshot(**changes: object) -> dict[str, object]:
    return {
        "schema": 1,
        "protocol": "postgres",
        "host": "127.0.0.1",
        "port": 34567,
        "ssl": {"servername": "database.example.test", "rejectUnauthorized": True},
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        **changes,
    }


def prepared(**changes: object) -> dict[str, object]:
    connection = snapshot(**changes)
    return {
        "schema": 1,
        "public_runtime": {
            "dev": False,
            "namespace": "example.test",
            "services": {
                "database": {
                    "protocol": connection["protocol"],
                    "namespace": "example.test",
                    "hostname": "database.example.test",
                    "port": 15443,
                    "public": True,
                    **({"url": connection["url"]} if "url" in connection else {}),
                }
            },
        },
        "connection": connection,
    }


@pytest.fixture(autouse=True)
def isolated_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_connections, "_sessions", {})
    monkeypatch.delenv("TNL_CONNECTION_HANDLE", raising=False)
    for key in ("TNL_WORKLOAD", "GITHUB_ACTIONS", "VERCEL", "FLY_APP_NAME"):
        monkeypatch.delenv(key, raising=False)

    class IPC:
        def __init__(self, file: str) -> None:
            self.file = file

        def prepare(self, name: str, assertion: str | None = None) -> object:
            return _connections._command(
                _connections.native_binary().resolve(strict=True),
                "prepare",
                "--handle",
                self.file,
                "--service",
                name,
            )

        def close(self) -> None:
            pass

    monkeypatch.setattr(_connections, "OwnerIPC", IPC)


def test_sync_properties_require_preparation_without_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable() -> Path:
        pytest.fail("a sync read started native discovery")

    monkeypatch.setattr(_connections, "native_binary", unavailable)
    db = tnl.connect("database", directory=tmp_path)
    with pytest.raises(tnl.TnlError, match="prepare connections first") as caught:
        _ = db.port
    assert caught.value.code == "sdk.connection_not_prepared"
    assert "database" not in repr(db)


def test_sync_sibling_read_never_dispatches_prepare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []

    def command(binary: Path, *args: str) -> object:
        calls.append(args[0])
        if args[0] == "start":
            return ready(binary, tmp_path / "handle", datetime.now(UTC) + timedelta(hours=1))
        if args[0] == "stop":
            return {"schema": 1, "state": "stopped"}
        if args[0] == "read" and args[-1] == "sibling":
            raise tnl.TnlError("sdk.connection_not_prepared", "service not prepared")
        assert args[0] == "prepare"
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        db = tnl.connect("database", directory=tmp_path)
        await db
        before = calls.count("prepare")
        with pytest.raises(tnl.TnlError):
            _ = tnl.connect("sibling", directory=tmp_path).port
        assert calls.count("prepare") == before
        assert calls == ["start", "prepare", "read"]
        await db.aclose()

    asyncio.run(scenario())


def test_import_has_no_process_environment_or_client_state_side_effects(tmp_path: Path) -> None:
    environment = {
        **os.environ,
        "TNL_CONNECTION_HANDLE": str(tmp_path / "absent-handle"),
        "TNL_STATE_DIR": str(tmp_path / "unused-state"),
    }
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import os, subprocess\n"
            "before = dict(os.environ)\n"
            "def forbidden(*args, **kwargs):\n"
            "    raise AssertionError('import started a native process')\n"
            "subprocess.Popen = forbidden\n"
            "import tnl\n"
            "assert dict(os.environ) == before\n",
        ],
        check=True,
        env=environment,
        capture_output=True,
        timeout=10,
    )
    assert not (tmp_path / "unused-state").exists()


def test_mounted_sync_reads_are_fresh_and_await_is_a_coherent_nonawaitable_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mounted = str(tmp_path / "private-handle.json")
    monkeypatch.setenv("TNL_CONNECTION_HANDLE", mounted)
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[tuple[str, ...]] = []

    def command(binary: Path, *args: str) -> object:
        assert binary == Path(sys.executable).resolve()
        assert args[0] in {"read", "prepare"} and args[1:] == (
            "--handle",
            mounted,
            "--service",
            "database",
        )
        calls.append(args)
        return prepared(port=34566 + len(calls))

    monkeypatch.setattr(_connections, "_command", command)
    handle = tnl.connect("database", directory=tmp_path)
    assert handle.port == 34567
    assert handle.port == 34568

    async def scenario() -> None:
        # sync CLI reads can run in an active event loop; no loop nesting or
        # Python async IPC is involved.
        assert handle.host == "127.0.0.1"
        connection = await handle
        assert isinstance(connection, tnl.PostgresConnection)
        assert connection.port == 34570
        assert not inspect.isawaitable(connection)
        assert connection.ssl.check_hostname
        assert connection.ssl.verify_mode == ssl.CERT_REQUIRED
        assert connection.server_hostname == "database.example.test"
        assert not hasattr(connection, "key") and not hasattr(connection, "cert")
        assert "example.test" not in repr(connection)
        with pytest.raises(FrozenInstanceError):
            connection.port = 1  # type: ignore[misc]
        await handle.aclose()

    asyncio.run(scenario())
    assert len(calls) == 4  # close does not stop an externally prepared owner.


def test_concurrent_threads_and_awaiters_share_one_lazy_native_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    starting, release = threading.Event(), threading.Event()
    mounted = str(tmp_path / "private-handle.json")

    def command(binary: Path, *args: str) -> object:
        calls.append(args[0])
        if args[0] == "start":
            assert args[1:] == (
                "--directory",
                str(tmp_path),
                "--parent-pid",
                str(os.getpid()),
            )
            starting.set()
            assert release.wait(5)
            return {
                "schema": 1,
                "state": "ready",
                "pid": 123,
                "expires_at": snapshot()["expires_at"],
                "private_handle": mounted,
                "executable": str(binary),
                "public_runtime": {},
            }
        if args[0] == "stop":
            return {"schema": 1, "state": "stopped"}
        assert args[0] in {"read", "prepare"} and args[1:] == (
            "--handle",
            mounted,
            "--service",
            "database",
        )
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)
    first = tnl.connect("database", directory=tmp_path)
    second = tnl.connect("database", directory=tmp_path)

    async def one() -> tnl.Connection:
        return await second

    async def scenario() -> None:
        task = asyncio.create_task(one())
        assert await asyncio.to_thread(starting.wait, 5)
        canceled = asyncio.create_task(one())
        await asyncio.sleep(0)
        canceled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await canceled
        with ThreadPoolExecutor() as pool:
            sync = pool.submit(lambda: first.port)
            await asyncio.sleep(0)  # the event loop remains usable during startup.
            release.set()
            result = await task
            assert result.port == sync.result(timeout=5) == 34567
        results = await asyncio.gather(*(one() for _ in range(8)))
        assert len(results) == 8
        await second.aclose()
        first.close()

    asyncio.run(scenario())
    assert calls.count("start") == calls.count("stop") == 1
    with pytest.raises(tnl.TnlError, match="closed"):
        first.snapshot()


def test_failed_preparation_is_shared_without_implicit_authentication_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls = 0

    def command(binary: Path, *args: str) -> object:
        nonlocal calls
        calls += 1
        raise tnl.TnlError("sdk.connection_unavailable", "native connection failed")

    monkeypatch.setattr(_connections, "_command", command)
    handle = tnl.connect("database", directory=tmp_path)

    async def one() -> tnl.Connection:
        return await handle

    async def scenario() -> None:
        failures = await asyncio.gather(*(one() for _ in range(8)), return_exceptions=True)
        assert all(isinstance(error, tnl.TnlError) for error in failures)

    asyncio.run(scenario())
    assert calls == 1
    handle.close()


def test_failed_initial_service_snapshot_retains_the_shared_native_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []

    def command(binary: Path, *args: str) -> object:
        calls.append(args[0])
        if args[0] == "start":
            return {
                "schema": 1,
                "state": "ready",
                "pid": 123,
                "expires_at": snapshot()["expires_at"],
                "private_handle": str(tmp_path / "handle"),
                "executable": str(binary),
                "public_runtime": {},
            }
        if args[0] == "stop":
            return {"schema": 1, "state": "stopped"}
        return prepared(expires_at="2020-01-01T00:00:00Z")

    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        with pytest.raises(tnl.TnlError) as caught:
            await tnl.connect("database", directory=tmp_path)
        assert caught.value.code == "sdk.connection_expired"

    asyncio.run(scenario())
    assert calls == ["start", "prepare"]


def ready(binary: Path, handle: Path, deadline: datetime) -> dict[str, object]:
    return {
        "schema": 1,
        "state": "ready",
        "pid": 123,
        "expires_at": deadline.isoformat(),
        "private_handle": str(handle),
        "executable": str(binary),
        "public_runtime": {},
    }


def test_known_owned_expiry_requires_await_and_coalesces_joined_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    stopping, release = threading.Event(), threading.Event()

    def command(binary: Path, *args: str) -> object:
        calls.append(args[0])
        if args[0] == "start":
            assert args[1:] == (
                "--directory",
                str(tmp_path),
                "--parent-pid",
                str(os.getpid()),
            )
            return ready(binary, tmp_path / "handle", deadline)
        if args[0] == "stop":
            stopping.set()
            assert release.wait(5)
            return {"schema": 1, "state": "stopped"}
        return prepared(expires_at=deadline.isoformat())

    monkeypatch.setattr(_connections, "_command", command)
    handle = tnl.connect("database", directory=tmp_path)

    async def one() -> tnl.Connection:
        return await tnl.connect("database", directory=tmp_path)

    async def scenario() -> None:
        first = await handle
        original_deadline = first.expires_at
        assert handle._session.expires_at == deadline
        handle._session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        before = list(calls)
        with pytest.raises(tnl.TnlError) as caught:
            handle.snapshot()
        assert caught.value.code == "sdk.connection_expired"
        assert calls == before
        pending = [asyncio.create_task(one()) for _ in range(8)]
        assert await asyncio.to_thread(stopping.wait, 5)
        assert calls.count("start") == 1
        canceled = asyncio.create_task(one())
        await asyncio.sleep(0)
        canceled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await canceled
        release.set()
        results = await asyncio.gather(*pending)
        assert all(result.port == first.port for result in results)
        assert first.expires_at == original_deadline
        assert calls.count("start") == 2 and calls.count("stop") == 1
        assert calls.index("stop") < len(calls) - 1 - calls[::-1].index("start")
        assert handle.snapshot().port == first.port
        await handle.aclose()

    asyncio.run(scenario())


def test_expiry_cleanup_must_acknowledge_join_before_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    joined = False
    deadline = datetime.now(UTC) + timedelta(minutes=5)

    def command(binary: Path, *args: str) -> object:
        calls.append(args[0])
        if args[0] == "start":
            return ready(binary, tmp_path / "handle", deadline)
        if args[0] == "stop":
            return {"schema": 1, "state": "stopped" if joined else "stopping"}
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)
    handle = tnl.connect("database", directory=tmp_path)

    async def scenario() -> None:
        nonlocal joined
        await handle
        handle._session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        with pytest.raises(tnl.TnlError) as caught:
            await handle
        assert caught.value.code == "sdk.connection_invalid"
        assert calls == ["start", "prepare", "stop"]
        with pytest.raises(tnl.TnlError) as expired:
            handle.snapshot()
        assert expired.value.code == "sdk.connection_expired"
        joined = True
        await handle
        assert calls == ["start", "prepare", "stop", "stop", "start", "prepare"]
        await handle.aclose()

    asyncio.run(scenario())


def test_expiry_restart_observes_current_authentication_denial_without_retrying_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    allowed = True
    denied = tnl.TnlError("sdk.connection_unavailable", "current native authentication was denied")

    def command(binary: Path, *args: str) -> object:
        calls.append(args[0])
        if args[0] == "start":
            if not allowed:
                raise denied
            return ready(binary, tmp_path / "handle", datetime.now(UTC) + timedelta(minutes=5))
        if args[0] == "stop":
            return {"schema": 1, "state": "stopped"}
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)
    handle = tnl.connect("database", directory=tmp_path)

    async def one() -> tnl.Connection:
        return await handle

    async def scenario() -> None:
        nonlocal allowed
        await handle
        handle._session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        allowed = False
        failures = await asyncio.gather(*(one() for _ in range(8)), return_exceptions=True)
        assert all(error is denied for error in failures)
        assert calls == ["start", "prepare", "stop", "start"]
        with pytest.raises(tnl.TnlError) as caught:
            await handle
        assert caught.value is denied
        assert calls == ["start", "prepare", "stop", "start"]
        await handle.aclose()

    asyncio.run(scenario())


def test_expired_external_snapshots_never_stop_or_replace_the_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TNL_CONNECTION_HANDLE", str(tmp_path / "caller-owned"))
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []

    def command(binary: Path, *args: str) -> object:
        calls.append(args[0])
        return prepared(expires_at="2020-01-01T00:00:00Z")

    monkeypatch.setattr(_connections, "_command", command)
    handle = tnl.connect("database", directory=tmp_path)

    async def scenario() -> None:
        with pytest.raises(tnl.TnlError) as caught:
            await handle
        assert caught.value.code == "sdk.connection_expired"

    asyncio.run(scenario())
    with pytest.raises(tnl.TnlError):
        handle.snapshot()
    handle.close()
    assert calls == ["prepare", "read"]


def test_snapshot_expiry_and_transient_reads_do_not_replace_a_live_owned_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    fail: str | None = None

    def command(binary: Path, *args: str) -> object:
        calls.append(args[0])
        if args[0] == "start":
            return ready(binary, tmp_path / "handle", datetime.now(UTC) + timedelta(minutes=5))
        if args[0] == "stop":
            return {"schema": 1, "state": "stopped"}
        if fail == "unavailable":
            raise tnl.TnlError("sdk.connection_unavailable", "native read timed out")
        if fail == "expired":
            return prepared(expires_at="2020-01-01T00:00:00Z")
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)
    handle = tnl.connect("database", directory=tmp_path)

    async def scenario() -> None:
        nonlocal fail
        await handle
        for failure in ("expired", "unavailable"):
            fail = failure
            with pytest.raises(tnl.TnlError):
                await handle
        fail = None
        await handle
        assert calls == ["start", "prepare", "prepare", "recover", "prepare", "recover", "prepare"]
        await handle.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("service", ["", "Database", "../secret", "db;env", "a" * 33])
def test_invalid_names_fail_before_native(service: str, tmp_path: Path) -> None:
    with pytest.raises(tnl.TnlError) as caught:
        tnl.connect(service, directory=tmp_path)
    assert caught.value.code == "sdk.connection_input"
    assert service not in str(caught.value) or service == ""


@pytest.mark.parametrize(
    "changes",
    [
        {"host": "database.example.test"},
        {"port": True},
        {"port": 0},
        {"protocol": {}},
        {"schema": True},
        {"ssl": {"servername": "database.example.test", "rejectUnauthorized": False}},
        {
            "ssl": {
                "servername": "database.example.test",
                "rejectUnauthorized": True,
                "key": "secret",
            }
        },
        {
            "ssl": {
                "servername": "database.example.test",
                "rejectUnauthorized": True,
                "ca": "bad PEM",
            }
        },
        {"expires_at": "2020-01-01T00:00:00Z"},
        {"expires_at": "2099-01-01T00:00:00"},
        {"url": "https://database.example.test"},
    ],
)
def test_invalid_or_expired_native_material_fails_closed(changes: dict[str, object]) -> None:
    with pytest.raises(tnl.TnlError) as caught:
        _connections._snapshot(snapshot(**changes))
    assert "secret" not in str(caught.value)


def test_http_keeps_managed_origin_and_project_protocol_drift_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = snapshot(protocol="http", url="https://database.example.test:15443")
    connection = _connections._snapshot(value)
    assert isinstance(connection, tnl.HTTPConnection)
    assert connection.url == "https://database.example.test:15443"
    assert connection.port == 34567  # local port is independent of the managed origin.
    monkeypatch.setenv("TNL_CONNECTION_HANDLE", str(tmp_path / "handle"))
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    monkeypatch.setattr(
        _connections, "_command", lambda *args: prepared(protocol="http", url=connection.url)
    )
    project = tnl.Project({"database": "postgres"})
    with pytest.raises(tnl.TnlError):
        project.connect("missing", directory=tmp_path)
    with pytest.raises(tnl.TnlError):
        project.connect("database", directory=tmp_path).snapshot()


@pytest.mark.parametrize(
    "value",
    [
        snapshot(),
        {**prepared(), "schema": True},
        {**prepared(), "private_key": "secret"},
        {**prepared(), "public_runtime": {}},
        {**prepared(), "connection": snapshot(protocol="mysql")},
        {
            **prepared(),
            "connection": snapshot(
                ssl={"servername": "other.example.test", "rejectUnauthorized": True}
            ),
        },
    ],
)
def test_prepared_contract_rejects_bare_widened_or_mismatched_responses(value: object) -> None:
    with pytest.raises(tnl.TnlError) as caught:
        _connections._prepared(value, "database")
    assert caught.value.code == "sdk.connection_invalid"
    assert "secret" not in str(caught.value)


def test_opaque_tcp_uses_native_verified_transport_without_application_tls() -> None:
    value = snapshot(protocol="tcp")
    del value["ssl"]
    connection = _connections._snapshot(value)
    assert isinstance(connection, tnl.TCPConnection)
    assert connection.host == "127.0.0.1" and connection.port == 34567
    assert not hasattr(connection, "ssl")


def test_cli_output_is_bounded_and_private_errors_are_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "tnl"
    binary.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write('s' * (129 << 10))\n")
    binary.chmod(0o700)
    with pytest.raises(tnl.TnlError) as caught:
        _connections._command(binary, "read")
    assert caught.value.code == "sdk.connection_invalid"
    binary.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(5)\n")
    with monkeypatch.context() as timing:
        timing.setattr(_connections, "_TIMEOUT", 0.05)
        with pytest.raises(tnl.TnlError) as caught:
            _connections._command(binary, "read")
    assert caught.value.code == "sdk.connection_unavailable"
    binary.write_text(f"#!{sys.executable}\nimport sys\nsys.stderr.write('secret')\nsys.exit(1)\n")
    with pytest.raises(tnl.TnlError) as caught:
        _connections._command(binary, "read")
    assert "secret" not in repr(caught.value)
    binary.write_text(f"#!{sys.executable}\nimport json\nprint(json.dumps({{'schema': 1}}))\n")
    assert _connections._command(binary, "read") == json.loads('{"schema": 1}')
