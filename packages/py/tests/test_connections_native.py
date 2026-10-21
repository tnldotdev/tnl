"""real Go owner IPC, native CLI reads, and hostname-verified Python TLS."""

from __future__ import annotations

import asyncio
import json
import os
import selectors
import socket
import ssl
import struct
import subprocess
from pathlib import Path
from typing import cast

import pytest

import tnl
from tnl import _connections


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
                assert selector.select(10), "native owner did not become ready"
            value = cast(dict[str, object], json.loads(process.stdout.readline()))
            assert value["schema"] == 1 and value["state"] == "ready"
            handle_path = value["private_handle"]
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
            assert process.poll() is None  # a mounted native owner is not SDK-owned.
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
