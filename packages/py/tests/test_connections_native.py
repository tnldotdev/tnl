"""real Go owner IPC, native CLI reads, and hostname-verified Python TLS."""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import selectors
import socket
import ssl
import struct
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

import tnl
from tnl import _connections


def test_installed_psycopg_uses_verified_hostname_and_explicit_transport_options(
    tmp_path: Path,
    native_connections: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if importlib.util.find_spec("psycopg") is None:
        pytest.skip("optional installed psycopg/libpq qualification; no SDK driver dependency")
    psycopg = importlib.import_module("psycopg")
    binary, owner = native_connections
    monkeypatch.setattr(_connections, "native_binary", lambda: binary)
    with subprocess.Popen(
        [str(owner), "-tnl-postgres-auth", str(tmp_path), str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        assert process.stdout is not None
        handle = None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(10)
            status = json.loads(process.stdout.readline())
            monkeypatch.setenv("TNL_CONNECTION_HANDLE", status["connection_handle"])
            handle = tnl.connect("database", directory=tmp_path)
            db = handle.snapshot()
            assert isinstance(db, tnl.PostgresConnection) and db.ca is not None
            root = tmp_path / "root.pem"
            root.write_text(db.ca)
            root.chmod(0o600)
            options = {
                "host": db.server_hostname,
                "hostaddr": db.host,
                "port": db.port,
                "sslmode": "verify-full",
                "sslrootcert": str(root),
                "channel_binding": "disable",
                "gssencmode": "disable",
                "user": "fixture",
                "dbname": "fixture",
                "password": "fixture-password",
                "connect_timeout": 3,
            }
            with psycopg.connect(**options) as connection:
                assert connection.pgconn.ssl_in_use
            with pytest.raises(psycopg.OperationalError):
                psycopg.connect(**{**options, "host": "wrong.example.test"})
            with pytest.raises(psycopg.OperationalError):
                psycopg.connect(**{**options, "channel_binding": "require"})
        finally:
            if handle is not None:
                handle.close()
            process.terminate()
            process.wait(timeout=10)


def assert_port_reusable(port: int) -> None:
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))
        probe.listen(1)


def assert_tls_echo(connection: tnl.PostgresConnection) -> None:
    with socket.create_connection((connection.host, connection.port), timeout=5) as raw:
        raw.sendall(struct.pack("!II", 8, 80877103))
        assert raw.recv(1) == b"S"
        with connection.ssl.wrap_socket(raw, server_hostname=connection.server_hostname) as stream:
            stream.sendall(b"ping")
            assert stream.recv(4) == b"ping"


def test_owned_deadline_recovery_joins_real_native_owner_before_same_port_restart(
    tmp_path: Path,
    native_connections: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary, owner = native_connections
    monkeypatch.delenv("TNL_CONNECTION_HANDLE", raising=False)
    monkeypatch.setattr(_connections, "native_binary", lambda: binary)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    processes: list[subprocess.Popen[bytes]] = []
    calls: list[str] = []
    command = _connections._command

    def native(binary: Path, *args: str) -> object:
        calls.append(args[0])
        if args[0] != "start":
            result = command(binary, *args)
            if args[0] == "stop":
                # the real native CLI must observe joined listener cleanup, even
                # when expiry already removed the live handle file.
                assert not Path(args[-1]).exists()
                assert_port_reusable(port)
            return result
        if processes:
            assert_port_reusable(port)
        process = subprocess.Popen(
            [
                str(owner),
                "-tnl-lifetime",
                "6s" if not processes else "30s",
                "-tnl-listen-address",
                f"127.0.0.1:{port}",
                str(tmp_path),
                str(binary),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        processes.append(process)
        assert process.stdout is not None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(10), "connector owner did not become ready"
        return _connections._object(
            json.loads(process.stdout.readline()),
            {
                "schema",
                "state",
                "pid",
                "expires_at",
                "project_runtime",
                "connection_handle",
                "executable",
            },
        )

    monkeypatch.setattr(_connections, "_command", native)
    handle = tnl.connect("database", directory=tmp_path)

    async def one() -> tnl.Connection:
        return await tnl.connect("database", directory=tmp_path)

    async def scenario() -> None:
        first = await handle
        assert isinstance(first, tnl.PostgresConnection)
        assert_tls_echo(first)
        original_expiry = first.expires_at
        assert first.port == port
        await asyncio.sleep(max(0, (original_expiry - datetime.now(UTC)).total_seconds()) + 0.05)
        await asyncio.to_thread(processes[0].wait, 5)
        before = list(calls)
        with pytest.raises(tnl.TnlError) as caught:
            handle.snapshot()
        assert caught.value.code == "sdk.connection_expired"
        assert calls == before
        results = await asyncio.gather(*(one() for _ in range(8)))
        current = results[0]
        assert isinstance(current, tnl.PostgresConnection)
        assert_tls_echo(current)
        assert all(
            result.port == port and result.expires_at == current.expires_at for result in results
        )
        assert len(processes) == calls.count("start") == 2
        assert calls.count("stop") == 1
        assert processes[0].pid != processes[1].pid
        assert first.expires_at == original_expiry < current.expires_at
        assert first.ca != current.ca
        await handle.aclose()
        assert_port_reusable(port)

    try:
        asyncio.run(scenario())
    finally:
        try:
            handle.close()
        finally:
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)


def test_prepared_native_cli_and_python_verified_tls(
    tmp_path: Path,
    native_connections: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary, owner = native_connections
    monkeypatch.setattr(_connections, "native_binary", lambda: binary)
    with subprocess.Popen(
        [str(owner), str(tmp_path), str(binary)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        assert process.stdout is not None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(10), "connector owner did not become ready"
            value = cast(dict[str, object], json.loads(process.stdout.readline()))
            assert value["schema"] == 1 and value["state"] == "ready"
            handle_path = value["connection_handle"]
            assert isinstance(handle_path, str)
            assert Path(handle_path).stat().st_mode & 0o777 == 0o600
            assert Path(handle_path).parent.stat().st_mode & 0o777 == 0o700
            monkeypatch.setenv("TNL_CONNECTION_HANDLE", handle_path)
            handle = tnl.connect("database", directory=tmp_path)
            assert handle.host == "127.0.0.1"

            async def scenario() -> tnl.Connection:
                # a sync native read inside this loop must not depend on it.
                assert handle.port > 0
                snapshots = await asyncio.gather(*(read() for _ in range(8)))
                assert len({value.port for value in snapshots}) == 1
                return snapshots[0]

            async def read() -> tnl.Connection:
                return await handle

            connection = asyncio.run(scenario())
            assert isinstance(connection, tnl.PostgresConnection)
            with socket.create_connection((connection.host, connection.port), timeout=5) as raw:
                raw.sendall(struct.pack("!II", 8, 80877103))
                assert raw.recv(1) == b"S"
                with connection.ssl.wrap_socket(
                    raw, server_hostname=connection.server_hostname
                ) as s:
                    s.sendall(b"ping")
                    assert s.recv(4) == b"ping"
            with socket.create_connection((connection.host, connection.port), timeout=5) as raw:
                raw.sendall(struct.pack("!II", 8, 80877103))
                assert raw.recv(1) == b"S"
                with pytest.raises(ssl.SSLCertVerificationError):
                    connection.ssl.wrap_socket(raw, server_hostname="wrong.example.test")
            stream = tnl.connect("stream", directory=tmp_path).snapshot()
            assert isinstance(stream, tnl.TCPConnection) and not hasattr(stream, "ssl")
            with socket.create_connection((stream.host, stream.port), timeout=5) as raw:
                raw.sendall(b"ping")
                assert raw.recv(4) == b"ping"
            with pytest.raises(tnl.TnlError):
                tnl.connect("missing", directory=tmp_path).snapshot()
            handle.close()
            assert process.poll() is None  # a mounted connector owner is not SDK-owned.
            os.chmod(handle_path, 0o644)
            with pytest.raises(tnl.TnlError):
                tnl.connect("database", directory=tmp_path).snapshot()
            os.chmod(handle_path, 0o600)
            original = Path(handle_path).read_bytes()
            descriptor = cast(dict[str, object], json.loads(original))
            descriptor["expires_at"] = "2020-01-01T00:00:00Z"
            try:
                Path(handle_path).write_text(json.dumps(descriptor))
                with pytest.raises(tnl.TnlError):
                    tnl.connect("database", directory=tmp_path).snapshot()
                assert process.poll() is None
            finally:
                Path(handle_path).write_bytes(original)
            _connections._command(binary, "stop", "--handle", handle_path)
            process.wait(timeout=10)
            assert not Path(handle_path).exists()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
