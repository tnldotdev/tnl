"""real authenticated IPC sockets, bounded capabilities, and sibling isolation."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import tnl
from tnl._connection_ipc import OwnerIPC


def test_private_ipc_reuses_socket_and_service_denial_does_not_poison_owner(tmp_path: Path) -> None:
    key = "a" * 64
    requests: list[str] = []
    connections: set[int] = set()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            assert self.path == "/v1/connections/prepare"
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
        for _ in range(10):
            assert client.prepare("db", "private-assertion") == {"schema": 1, "state": "prepared"}
        assert len(requests) == 10 and len(connections) == 1
        with pytest.raises(tnl.TnlError):
            client.prepare("denied", "private-assertion")
        assert client.prepare("db", "private-assertion") == {"schema": 1, "state": "prepared"}
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
