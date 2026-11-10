"""real authenticated IPC sockets, bounded capabilities, and sibling isolation."""

from __future__ import annotations

import json
import socket
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock

import pytest

import tnl
from tnl import _connection_ipc
from tnl._connection_ipc import OwnerIPC


@pytest.mark.parametrize("operation", ["prepare", "application", "sdk-application"])
def test_private_ipc_reuses_socket_and_service_denial_does_not_poison_owner(
    tmp_path: Path,
    operation: str,
) -> None:
    key = "a" * 64
    requests: list[str] = []

    connections: set[int] = set()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            assert self.path == "/v1/connections/" + operation
            assert self.headers["Authorization"] == "Bearer " + key
            raw: object = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert isinstance(raw, dict)
            service = raw.get("service")
            assert isinstance(service, str)
            assert raw.get("assertion") == "private-assertion"
            requests.append(service)
            connections.add(self.client_address[1])
            data = json.dumps({"schema": 1, "state": "prepared"}).encode()
            self.send_response(403 if service == "denied" else 200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    file = directory / "handle.json"
    file.write_text(
        json.dumps(
            {
                "schema": 1,
                "url": f"http://127.0.0.1:{server.server_port}",
                "key": key,
                "directory": str(tmp_path),
                "config_digest": "c" * 64,
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "executable": "/installed/tnl",
            }
        )
    )
    file.chmod(0o600)
    client: OwnerIPC | None = None
    try:
        client = OwnerIPC(str(file))

        def prepare(service: str) -> object:
            assert client is not None
            return client.prepare(
                service,
                "private-assertion",
                sdk=operation.startswith("sdk-"),
                application="application" in operation,
            )

        for _ in range(10):
            assert prepare("db") == {"schema": 1, "state": "prepared"}
        assert len(requests) == 10 and len(connections) == 1
        if operation.startswith("sdk-"):
            assert prepare("denied") == {"schema": 1, "state": "prepared"}
        else:
            with pytest.raises(tnl.TnlError):
                prepare("denied")
        assert prepare("db") == {"schema": 1, "state": "prepared"}
        assert requests == ["db"] * 10 + ["denied", "db"]
        file.chmod(0o644)
        with pytest.raises(tnl.TnlError):
            OwnerIPC(str(file))
        file.chmod(0o600)
        alias = directory / "alias.json"
        alias.symlink_to(file)
        with pytest.raises(tnl.TnlError):
            OwnerIPC(str(alias))
        assert key not in repr(client)
    finally:
        if client is not None:
            client.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.mark.parametrize(
    "change",
    [
        "renewed",
        "unchanged",
        "missing",
        "key",
        "url",
        "directory",
        "config_digest",
        "executable",
        "workload",
        "team_id",
        "unsafe",
        "symlink",
        "oversized",
        "closed",
    ],
)
def test_private_ipc_expiry_accepts_only_an_exact_renewed_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    requests: list[str] = []
    peers: list[socket.socket] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            requests.append(self.path)
            peers.append(self.connection)
            self.rfile.read(int(self.headers["Content-Length"]))
            data = b'{"schema":1}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    servers = [ThreadingHTTPServer(("127.0.0.1", 0), Handler) for _ in range(2)]
    workers = [
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        for server in servers
    ]
    for worker in workers:
        worker.start()
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    file = directory / "handle.json"
    expires = datetime.now(UTC) + timedelta(hours=1)
    handle: dict[str, object] = {
        "schema": 1,
        "url": f"http://127.0.0.1:{servers[0].server_port}",
        "key": "a" * 64,
        "directory": str(tmp_path),
        "config_digest": "c" * 64,
        "expires_at": expires.isoformat(),
        "executable": "/installed/tnl",
        "workload": "job",
        "team_id": "tm_" + "a" * 22,
    }
    file.write_text(json.dumps(handle))
    file.chmod(0o600)
    client: OwnerIPC | None = None
    try:
        client = OwnerIPC(str(file))
        assert client.prepare("db") == {"schema": 1}
        if change == "renewed":
            # an idle peer can already be closed when the descriptor advances.
            for peer in peers:
                peer.shutdown(socket.SHUT_RDWR)
        next_handle = {**handle, "expires_at": (expires + timedelta(hours=1)).isoformat()}
        changes: dict[str, object] = {
            "key": "b" * 64,
            "url": f"http://127.0.0.1:{servers[1].server_port}",
            "directory": str(tmp_path / "other"),
            "config_digest": "d" * 64,
            "executable": "/installed/other-tnl",
            "workload": "other",
            "team_id": "tm_" + "b" * 22,
        }
        if change in changes:
            next_handle[change] = changes[change]
        if change == "missing":
            file.unlink()
        elif change != "unchanged":
            temporary = file.with_suffix(".next")
            temporary.write_text(
                json.dumps(next_handle) + (" " * (128 << 10) if change == "oversized" else "")
            )
            temporary.chmod(0o644 if change == "unsafe" else 0o600)
            if change == "symlink":
                file.unlink()
                file.symlink_to(temporary)
            else:
                temporary.replace(file)
        if change == "closed":
            client.close()
        clock = Mock(wraps=datetime)
        clock.now.return_value = expires + timedelta(milliseconds=1)
        monkeypatch.setattr(_connection_ipc, "datetime", clock)
        if change == "renewed":
            assert client.prepare("db") == {"schema": 1}
            assert client.expires == expires + timedelta(hours=1)
            clock.now.return_value += timedelta(hours=1)
        with pytest.raises(tnl.TnlError) as caught:
            client.prepare("db")
        assert caught.value.code == "sdk.connection_unavailable"
        assert requests == ["/v1/connections/prepare"] * (2 if change == "renewed" else 1)
    finally:
        if client is not None:
            client.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        for worker in workers:
            worker.join(timeout=5)
