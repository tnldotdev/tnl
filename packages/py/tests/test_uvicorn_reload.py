"""exercise actual Uvicorn reload workers in two independent worktrees."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit


def test_reload_registers_the_serving_worker_in_each_worktree(tmp_path: Path) -> None:
    events: list[tuple[str, str, int, str]] = []
    registrations: dict[str, tuple[str, int]] = {}
    targets: dict[str, str] = {}
    mutex = threading.Lock()

    class Publisher(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path != "/v1/status":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def do_POST(self) -> None:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 64 << 10:
                self.send_error(400)
                return
            payload: dict[str, object] = json.loads(self.rfile.read(size))
            if self.path == "/v1/prepare":
                directory = str(payload["directory"])
                pid = payload["pid"]
                assert type(pid) is int
                with mutex:
                    registration = f"reg_{len(registrations) + 1:032x}"
                    registrations[registration] = (directory, pid)
                    events.append(("prepare", directory, pid, registration))
                response = json.dumps(
                    {
                        "version": 1,
                        "registration_id": registration,
                        "service": "web",
                        "hostname": "web.example.test",
                        "public_url": "https://web.example.test",
                        "project": {},
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
                return
            registration = str(payload["registration_id"])
            with mutex:
                directory, pid = registrations[registration]
                if self.path == "/v1/register":
                    targets[registration] = str(payload["target"])
                events.append((self.path.rsplit("/", 1)[-1], directory, pid, registration))
            self.send_response(204)
            self.end_headers()

    publisher = ThreadingHTTPServer(("127.0.0.1", 0), Publisher)
    thread = threading.Thread(target=publisher.serve_forever, daemon=True)
    thread.start()
    endpoint = tmp_path / "publisher.endpoint.json"
    endpoint.write_text(
        json.dumps(
            {
                "version": 1,
                "url": f"http://127.0.0.1:{publisher.server_port}",
                "credential": "a" * 43,
            }
        )
    )
    processes: list[subprocess.Popen[bytes]] = []
    logs: list[BinaryIO] = []
    roots = [tmp_path / "one", tmp_path / "two"]

    def wait_for(directory: Path, kind: str, count: int) -> list[tuple[str, str, int, str]]:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            with mutex:
                matched = [
                    event for event in events if event[0] == kind and event[1] == str(directory)
                ]
            if len(matched) >= count:
                return matched
            if any(process.poll() is not None for process in processes):
                raise AssertionError(f"reloader exited before {kind} for {directory}: {events}")
            time.sleep(0.05)
        raise AssertionError(f"timed out waiting for {kind} in {directory}: {events}")

    try:
        for directory in roots:
            directory.mkdir()
            (directory / "app.py").write_text("""async def app(scope, receive, send):
    if scope['type'] == 'lifespan':
        while True:
            event = await receive()
            if event['type'] == 'lifespan.startup':
                await send({'type': 'lifespan.startup.complete'})
            elif event['type'] == 'lifespan.shutdown':
                await send({'type': 'lifespan.shutdown.complete'})
                return
""")
            (directory / "dev.py").write_text(
                "from tnl.uvicorn import run\n"
                'run("app:app", service="web", port=0, reload=True, reload_dirs=["."])\n'
            )
            log = (directory / "server.log").open("wb")
            logs.append(log)
            env = dict(os.environ)
            env["TNL_PUBLISHER_ENDPOINT_FILE"] = str(endpoint)
            env["TNL_NO_TELEMETRY"] = "1"
            processes.append(
                subprocess.Popen(
                    [sys.executable, "dev.py"],
                    cwd=directory,
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
            )
        first = [wait_for(root, "register", 1)[0] for root in roots]
        assert all(first[index][2] != processes[index].pid for index in range(2))
        assert targets[first[0][3]] != targets[first[1][3]]
        for initial in first:
            address = urlsplit(targets[initial[3]])
            assert address.hostname == "127.0.0.1" and address.port is not None
            with socket.create_connection((address.hostname, address.port), timeout=1):
                pass
        # StatReload records initial mtimes on its first poll, which can happen
        # after a worker has already registered its listener.
        time.sleep(1)
        for directory in roots:
            with (directory / "app.py").open("a") as app:
                app.write("\n# reload\n")
        for directory, initial in zip(roots, first, strict=True):
            replacement = wait_for(directory, "register", 2)[-1]
            assert replacement[2] != initial[2]
            assert targets[replacement[3]] == targets[initial[3]]
            with mutex:
                old_stop = next(
                    index
                    for index, item in enumerate(events)
                    if item[0] == "unregister" and item[3] == initial[3]
                )
                new_start = next(
                    index
                    for index, item in enumerate(events)
                    if item[0] == "register" and item[3] == replacement[3]
                )
            assert old_stop < new_start
    finally:
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for output_file in logs:
            output_file.close()
        publisher.shutdown()
        publisher.server_close()
        thread.join(timeout=2)
