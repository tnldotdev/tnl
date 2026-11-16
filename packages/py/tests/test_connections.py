"""native acquisition bounds, joined cleanup, and verified Python TLS snapshots."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import ssl
import subprocess
import sys
import threading
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
        "transport_id": "ctg_aaaaaaaaaaaaaaaaaaaaaa",
        **changes,
    }


def prepared(**changes: object) -> dict[str, object]:
    connection = snapshot(**changes)
    return {
        "schema": 1,
        "project_runtime": {
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
    monkeypatch.delenv("TNL_CONNECTION_HANDLE", raising=False)
    for key in ("TNL_WORKLOAD", "GITHUB_ACTIONS", "VERCEL", "FLY_APP_NAME"):
        monkeypatch.delenv(key, raising=False)

    class IPC:
        def __init__(self, file: str) -> None:
            self.file = file

        def prepare(
            self,
            name: str,
            assertion: str | None = None,
            *,
            sdk: bool = False,
            selection: dict[str, object] | None = None,
            requested_at: str | None = None,
            request_handle: str | None = None,
        ) -> object:
            return _connections._command(
                _connections.native_binary().resolve(strict=True),
                "sdk-request" if sdk else "prepare",
                "--handle",
                self.file,
                "--service",
                name,
            )

        def close(self) -> None:
            pass

    monkeypatch.setattr(_connections, "OwnerIPC", IPC)


def test_acquisition_construction_does_not_discover_native_or_expose_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable() -> Path:
        pytest.fail("constructing an acquisition started native discovery")

    monkeypatch.setattr(_connections, "native_binary", unavailable)
    scope = _connections._Scope(str(tmp_path), None)
    db = _connections.ConnectionAcquisition(scope, "database")
    assert scope.registry is None
    assert not hasattr(db, "port")
    assert "database" not in repr(db)


def test_constructing_a_sibling_acquisition_does_not_prepare_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-prepare":
            calls.extend(["start", "prepare"])
            return {
                "schema": 1,
                "owner": ready(binary, tmp_path / "handle", datetime.now(UTC) + timedelta(hours=1)),
                "prepared": prepared(),
            }
        calls.append(args[0])
        if args[0] == "sdk-close":
            return {"schema": 1, "state": "stopped"}
        assert args[0] == "sdk-request"
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        scope = _connections._Scope(str(tmp_path), None)
        db = _connections.ConnectionAcquisition(scope, "database")
        await db.prepare()
        before = calls.count("prepare")
        sibling = _connections.ConnectionAcquisition(scope, "sibling")
        assert not hasattr(sibling, "port")
        assert calls.count("prepare") == before
        assert calls == ["start", "prepare"]
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


def test_borrowed_preparation_returns_immutable_verified_settings_and_leaves_owner_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mounted = str(tmp_path / "private-handle.json")
    monkeypatch.setenv("TNL_CONNECTION_HANDLE", mounted)
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[tuple[str, ...]] = []

    def command(binary: Path, *args: str) -> object:
        assert binary == Path(sys.executable).resolve()
        assert args[0] == "prepare" and args[1:] == (
            "--handle",
            mounted,
            "--service",
            "database",
        )
        calls.append(args)
        return prepared(port=34566 + len(calls))

    monkeypatch.setattr(_connections, "_command", command)
    scope = _connections._Scope(str(tmp_path), mounted)
    handle = _connections.ConnectionAcquisition(scope, "database")

    async def scenario() -> None:
        connection = await handle.prepare()
        assert isinstance(connection, tnl.PostgresConnection)
        assert connection.port == 34567
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
    assert len(calls) == 1  # close does not stop an externally prepared owner.


def test_concurrent_acquisitions_share_native_startup_without_canceling_another_waiter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    starting, release = threading.Event(), threading.Event()
    mounted = str(tmp_path / "private-handle.json")

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-prepare":
            assert args[args.index("--directory") + 1] == str(tmp_path)
            assert args[args.index("--parent-pid") + 1] == str(os.getpid())
            assert "--retain-start-failure" in args
            calls.append("start")
            starting.set()
            assert release.wait(5)
            return {
                "schema": 1,
                "owner": ready(binary, Path(mounted), datetime.now(UTC) + timedelta(minutes=5)),
                "prepared": prepared(),
            }
        calls.append(args[0])
        if args[0] == "sdk-close":
            return {"schema": 1, "state": "stopped"}
        assert args[0] == "sdk-request" and args[1:] == (
            "--handle",
            mounted,
            "--service",
            "database",
        )
        return {
            "schema": 1,
            "owner": ready(binary, Path(mounted), datetime.now(UTC) + timedelta(minutes=5)),
            "prepared": prepared(),
        }

    monkeypatch.setattr(_connections, "_command", command)
    scope = _connections._Scope(str(tmp_path), None)
    first = _connections.ConnectionAcquisition(scope, "database")
    second = _connections.ConnectionAcquisition(scope, "database")

    async def one() -> tnl.Connection:
        return await second.prepare()

    async def scenario() -> None:
        task = asyncio.create_task(one())
        assert await asyncio.to_thread(starting.wait, 5)
        canceled = asyncio.create_task(one())
        await asyncio.sleep(0)
        canceled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await canceled
        release.set()
        result = await task
        assert result.port == 34567
        results = await asyncio.gather(*(one() for _ in range(8)))
        assert len(results) == 8
        await second.aclose()
        first.close()

    asyncio.run(scenario())
    assert calls.count("start") == calls.count("sdk-close") == 1
    with pytest.raises(tnl.TnlError, match="closed"):
        asyncio.run(first.prepare())


def test_native_retained_failure_preserves_exception_identity_and_private_causes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary, counter = tmp_path / "native", tmp_path / "attempts"
    binary.write_text(
        f"#!{sys.executable}\nimport json, pathlib, sys\n"
        f"counter = pathlib.Path({str(counter)!r})\n"
        "if sys.argv[3] in ('sdk-stop', 'sdk-close'):\n"
        " print(json.dumps({'schema': 1, 'state': 'stopped'}))\n"
        "else:\n counter.write_text(counter.read_text() + 'x' if counter.exists() else 'x')\n"
        " sys.stderr.write(json.dumps({'reason': 'TNL_CLIENT_AUTHENTICATION_REQUIRED', "
        "'sdk_retained_start_failure': True, "
        f"'sdk_failure_handle': {'a' * 64 + '.' + '1' * 16!r}, "
        "'message': 'private-credential'}))\n sys.exit(1)\n"
    )
    binary.chmod(0o700)
    monkeypatch.setattr(_connections, "native_binary", lambda: binary)
    scope = _connections._Scope(str(tmp_path), None)
    handle = _connections.ConnectionAcquisition(scope, "database")

    async def one() -> tnl.Connection:
        return await handle.prepare()

    async def scenario() -> None:
        failures = await asyncio.gather(*(one() for _ in range(8)), return_exceptions=True)
        assert all(isinstance(error, tnl.TnlError) for error in failures)
        assert all(error is failures[0] for error in failures)
        with pytest.raises(tnl.TnlError) as repeated:
            await handle.prepare()
        assert repeated.value is failures[0]
        assert "private-credential" not in str(repeated.value)
        assert "private-credential" not in json.dumps(vars(repeated.value))

    asyncio.run(scenario())
    # native decides whether a new await may retry authentication; its retained
    # failure proof is TestConnectionSDKPythonRetainsStartupFailureUntilClosed. Python
    # only shares an active wait and the exception for the returned reference.
    assert counter.read_text() == "xx"
    handle.close()


def test_failed_initial_service_snapshot_retains_the_shared_native_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-prepare":
            calls.extend(["start", "prepare"])
            return {
                "schema": 1,
                "owner": ready(
                    binary, tmp_path / "handle", datetime.now(UTC) + timedelta(minutes=5)
                ),
                "prepared": prepared(expires_at="2020-01-01T00:00:00Z"),
            }
        calls.append(args[0])
        if args[0] == "sdk-close":
            return {"schema": 1, "state": "stopped"}
        return prepared(expires_at="2020-01-01T00:00:00Z")

    monkeypatch.setattr(_connections, "_command", command)

    async def scenario() -> None:
        with pytest.raises(tnl.TnlError) as caught:
            scope = _connections._Scope(str(tmp_path), None)
            await _connections.ConnectionAcquisition(scope, "database").prepare()
        assert caught.value.code == "sdk.connection_expired"

    asyncio.run(scenario())
    assert calls == ["start", "prepare"]


def ready(binary: Path, handle: Path, deadline: datetime) -> dict[str, object]:
    return {
        "expires_at": deadline.isoformat(),
        "connection_handle": str(handle),
        "executable": str(binary),
    }


def sdk_ready(binary: Path, handle: Path, deadline: datetime) -> dict[str, object]:
    return {
        "schema": 1,
        "owner": ready(binary, handle, deadline),
        "prepared": prepared(expires_at=deadline.isoformat()),
    }


def test_known_owned_expiry_requires_await_and_coalesces_joined_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    stopping, release = threading.Event(), threading.Event()
    expired = False
    run = 1

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        nonlocal expired, run
        # these counters describe the native fixture's selected lifecycle.
        if args[0] == "sdk-prepare":
            calls.extend(["start", "prepare"])
            return sdk_ready(binary, tmp_path / "handle-1", deadline)
        if args[0] == "sdk-request":
            if expired:
                calls.append("stop")
                stopping.set()
                assert release.wait(5)
                run += 1
                expired = False
                calls.append("start")
            calls.append("prepare")
            return sdk_ready(binary, tmp_path / f"handle-{run}", deadline)
        calls.append(args[0])
        if args[0] == "sdk-close":
            return {"schema": 1, "state": "stopped"}
        return prepared(expires_at=deadline.isoformat())

    monkeypatch.setattr(_connections, "_command", command)
    scope = _connections._Scope(str(tmp_path), None)
    handle = _connections.ConnectionAcquisition(scope, "database")
    replacements: list[_connections.ConnectionAcquisition] = []

    async def one() -> tnl.Connection:
        replacement = _connections.ConnectionAcquisition(scope, "database")
        replacements.append(replacement)
        return await replacement.prepare()

    async def scenario() -> None:
        nonlocal expired
        first = await handle.prepare()
        original_deadline = first.expires_at
        assert handle._session.expires_at == deadline
        handle._session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        expired = True
        before = list(calls)
        assert first.expires_at == original_deadline
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
        assert first.port == results[0].port
        await handle.aclose()
        assert (await replacements[0].prepare()).port == first.port
        await replacements[0].aclose()

    asyncio.run(scenario())


def test_expiry_cleanup_must_acknowledge_join_before_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    joined = False
    deadline = datetime.now(UTC) + timedelta(minutes=5)
    expired = False

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        nonlocal expired
        if args[0] == "sdk-prepare":
            calls.extend(["start", "prepare"])
            return sdk_ready(binary, tmp_path / "handle-1", deadline)
        if args[0] == "sdk-request":
            if expired:
                calls.append("stop")
                if not joined:
                    return {"schema": 1, "reason": "TNL_SERVER_RESPONSE_INVALID"}
                calls.append("start")
                expired = False
            calls.append("prepare")
            return sdk_ready(binary, tmp_path / "handle-2", deadline)
        calls.append(args[0])
        if args[0] == "sdk-close":
            return {"schema": 1, "state": "stopped" if joined else "stopping"}
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)
    scope = _connections._Scope(str(tmp_path), None)
    handle = _connections.ConnectionAcquisition(scope, "database")

    async def scenario() -> None:
        nonlocal joined, expired
        await handle.prepare()
        handle._session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        expired = True
        with pytest.raises(tnl.TnlError) as caught:
            await handle.prepare()
        assert caught.value.code == "sdk.connection_invalid"
        assert calls == ["start", "prepare", "stop"]
        assert handle._session.expires_at is not None
        assert handle._session.expires_at < datetime.now(UTC)
        joined = True
        await handle.prepare()
        assert calls == ["start", "prepare", "stop", "stop", "start", "prepare"]
        await handle.aclose()

    asyncio.run(scenario())


def test_expiry_restart_preserves_native_retained_denial_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    allowed = True
    expired = False
    denied = False

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        nonlocal denied
        if args[0] == "sdk-prepare":
            calls.extend(["start", "prepare"])
            return sdk_ready(binary, tmp_path / "handle", datetime.now(UTC) + timedelta(minutes=5))
        if args[0] == "sdk-request":
            if expired:
                if not denied:
                    calls.extend(["stop", "start"])
                    denied = True
                assert not allowed
                return {
                    "schema": 1,
                    "reason": "TNL_CLIENT_AUTHENTICATION_REQUIRED",
                    "sdk_retained_start_failure": True,
                    "sdk_failure_handle": "a" * 64 + "." + "1" * 16,
                }
            calls.append("prepare")
            return sdk_ready(binary, tmp_path / "handle", datetime.now(UTC) + timedelta(minutes=5))
        calls.append(args[0])
        if args[0] == "sdk-close":
            return {"schema": 1, "state": "stopped"}
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)
    scope = _connections._Scope(str(tmp_path), None)
    handle = _connections.ConnectionAcquisition(scope, "database")

    async def one() -> tnl.Connection:
        return await handle.prepare()

    async def scenario() -> None:
        nonlocal allowed, expired
        await handle.prepare()
        handle._session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        allowed = False
        expired = True
        failures = await asyncio.gather(*(one() for _ in range(8)), return_exceptions=True)
        denied = failures[0]
        assert isinstance(denied, tnl.TnlError) and denied.code == "sdk.connection_unavailable"
        assert all(error is denied for error in failures)
        assert calls == ["start", "prepare", "stop", "start"]
        with pytest.raises(tnl.TnlError) as caught:
            await handle.prepare()
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
    scope = _connections._Scope(str(tmp_path), str(tmp_path / "caller-owned"))
    handle = _connections.ConnectionAcquisition(scope, "database")

    async def scenario() -> None:
        with pytest.raises(tnl.TnlError) as caught:
            await handle.prepare()
        assert caught.value.code == "sdk.connection_expired"

    asyncio.run(scenario())
    handle.close()
    assert calls == ["prepare"]


def test_snapshot_expiry_and_transient_reads_do_not_replace_a_live_owned_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    calls: list[str] = []
    fail: str | None = None

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-prepare" and "--recover-handle" not in args:
            calls.extend(["start", "prepare"])
            return sdk_ready(binary, tmp_path / "handle", datetime.now(UTC) + timedelta(minutes=5))
        if "--recover-handle" in args:
            calls.append("recover")
            raise tnl.TnlError("sdk.connection_unavailable", "kernel lifetime lock is held")
        if args[0] == "sdk-request":
            calls.append("prepare")
            if fail == "unavailable":
                raise tnl.TnlError("sdk.connection_unavailable", "native read timed out")
            if fail == "expired":
                raise tnl.TnlError("sdk.connection_expired", "snapshot expired")
            return sdk_ready(binary, tmp_path / "handle", datetime.now(UTC) + timedelta(minutes=5))
        calls.append(args[0])
        if args[0] == "sdk-close":
            return {"schema": 1, "state": "stopped"}
        if fail == "unavailable":
            raise tnl.TnlError("sdk.connection_unavailable", "native read timed out")
        if fail == "expired":
            return prepared(expires_at="2020-01-01T00:00:00Z")
        return prepared()

    monkeypatch.setattr(_connections, "_command", command)
    scope = _connections._Scope(str(tmp_path), None)
    handle = _connections.ConnectionAcquisition(scope, "database")

    async def scenario() -> None:
        nonlocal fail
        await handle.prepare()
        for failure in ("expired", "unavailable"):
            fail = failure
            with pytest.raises(tnl.TnlError):
                await handle.prepare()
        fail = None
        await handle.prepare()
        assert calls == ["start", "prepare", "prepare", "recover", "prepare", "recover", "prepare"]
        await handle.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("service", ["", "Database", "../secret", "db;env", "a" * 33])
def test_invalid_names_fail_before_native(service: str, tmp_path: Path) -> None:
    with pytest.raises(tnl.TnlError) as caught:
        _connections.ConnectionAcquisition(_connections._Scope(str(tmp_path), None), service)
    assert caught.value.code == "sdk.response_invalid"
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


@pytest.mark.parametrize(
    "transport",
    [
        pytest.param(..., id="missing"),
        None,
        "",
        1,
        "ctg_short",
        "old_" + "a" * 22,
        "ctg_" + "a" * 21,
        "ctg_" + "a" * 23,
        "ctg_" + "a" * 21 + "_",
        "ctg_" + "a" * 21 + "é",
        "ctg_" + "a" * 22 + "\n",
    ],
)
def test_snapshot_and_prepared_require_a_valid_transport_identity(transport: object) -> None:
    value = prepared(transport_id=transport)
    connection = value["connection"]
    assert isinstance(connection, dict)
    if transport is ...:
        del connection["transport_id"]
    for parse in (
        lambda: _connections._snapshot(connection),
        lambda: _connections._prepared(value, "database"),
    ):
        with pytest.raises(tnl.TnlError) as caught:
            parse()
        assert caught.value.code == "sdk.connection_invalid"


def test_transport_identity_is_private_native_metadata() -> None:
    connection = _connections._snapshot(snapshot(transport_id="ctg_0123456789ABCDEFGHIJaz"))
    assert isinstance(connection, tnl.PostgresConnection)
    assert not hasattr(connection, "transport_id")


def test_http_keeps_managed_origin_separate_from_local_port() -> None:
    value = snapshot(protocol="http", url="https://database.example.test:15443")
    connection = _connections._snapshot(value)
    assert isinstance(connection, tnl.HTTPConnection)
    assert connection.url == "https://database.example.test:15443"
    assert connection.port == 34567  # local port is independent of the managed origin.


@pytest.mark.parametrize(
    "value",
    [
        snapshot(),
        {**prepared(), "schema": True},
        {**prepared(), "private_key": "secret"},
        {**prepared(), "project_runtime": {}},
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
