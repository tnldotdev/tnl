"""isolated probes whose outer process deadline also contains pre-fix deadlocks."""

from __future__ import annotations

import asyncio
import atexit
import http.client
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import tnl
from tnl import _connection_ipc, _connections, _native
from tnl._protocol import Endpoint


def command_probe(root: Path, mode: str) -> None:
    binary = root / "cli"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import os, sys, time\n"
        f"open({str(root / 'pid')!r}, 'w').write(str(os.getpid()))\n"
        + {
            "blocked-input": "time.sleep(30)\n",
            "duplex": (
                "sys.stdout.write(' ' * (96 << 10)); sys.stdout.flush()\n"
                "sys.stdin.buffer.read()\nprint('{}')\n"
            ),
            "exit": "sys.stdin.buffer.read()\nos.close(1)\ntime.sleep(30)\n",
            "flood": "while True: os.write(1, b'x' * 8192)\n",
        }[mode]
    )
    binary.chmod(0o700)
    _connections._TIMEOUT = 2.0

    async def scenario() -> None:
        task = asyncio.create_task(
            asyncio.to_thread(_connections._command, binary, "start", input_value="x" * (120 << 10))
        )
        if mode == "blocked-input":
            while not (root / "pid").exists():
                await asyncio.sleep(0.005)
            # cancellation must not leave an unbounded worker in the executor.
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return
        try:
            result = await task
        except tnl.TnlError as error:
            assert mode != "duplex", error.code
            assert error.code == (
                "sdk.connection_invalid" if mode == "flood" else "sdk.connection_unavailable"
            )
        else:
            assert mode == "duplex" and result == {}

    asyncio.run(scenario())  # joins canceled executor workers too.
    pid = int((root / "pid").read_text())
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise AssertionError("native child was not killed and reaped")


def fifo_probe(root: Path) -> None:
    root.chmod(0o700)
    file = root / "endpoint"
    os.mkfifo(file, 0o600)
    try:
        _native._read_endpoint(str(file), "web", None)
    except tnl.TnlError as error:
        assert error.code == "sdk.response_invalid"
    else:
        raise AssertionError("FIFO accepted")


def ipc_probe(root: Path, mode: str) -> None:
    """a peer making progress cannot extend the whole exchange deadline."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(3)
    port = listener.getsockname()[1]
    root.chmod(0o700)
    file = root / "handle.json"
    file.write_text(
        json.dumps(
            {
                "schema": 1,
                "url": f"http://127.0.0.1:{port}",
                "key": "a" * 64,
                "directory": str(root),
                "config_digest": "b" * 64,
                "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
                "executable": "/installed/tnl",
            }
        )
    )
    file.chmod(0o600)
    finished = threading.Event()
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            for slow in (True, False):
                with listener.accept()[0] as peer:
                    peer.settimeout(2)
                    peer.recv(16384)
                    if slow:
                        if mode.endswith("body"):
                            peer.sendall(
                                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                b"Content-Length: 65536\r\n\r\n"
                            )
                        else:
                            peer.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                        try:
                            while True:
                                peer.sendall(b" ")
                                time.sleep(0.03)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                    else:
                        peer.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            b"Content-Length: 2\r\nConnection: close\r\n\r\n{}"
                        )
        except BaseException as error:
            failures.append(error)
        finally:
            listener.close()
            finished.set()

    worker = threading.Thread(target=serve)
    worker.start()
    before = set(threading.enumerate())
    if mode.startswith("ipc-publisher"):
        _native._REQUEST_TIMEOUT = 0.2
        native = _native.NativeRuntime()
        endpoint = Endpoint(f"http://127.0.0.1:{port}", "a" * 64, "b" * 32, "app", "web")

        async def request() -> None:
            started = time.monotonic()
            try:
                await native.request(endpoint, "status")
            except tnl.TnlError:
                assert time.monotonic() - started < 2
            else:
                raise AssertionError("slow reply escaped total deadline")
            assert await native.request(endpoint, "status") == {}

        asyncio.run(request())
    else:
        _connection_ipc._TIMEOUT = 0.2
        client = _connection_ipc.OwnerIPC(str(file))
        started = time.monotonic()
        try:
            client.prepare("db")
        except tnl.TnlError:
            assert time.monotonic() - started < 2
        else:
            raise AssertionError("slow reply escaped total deadline")
        assert client.prepare("db") == {}
        client.close()
    assert finished.wait(3)
    worker.join(3)
    assert not failures, failures
    assert not (set(threading.enumerate()) - before), "IPC left a deadline worker alive"


def fork_probe(root: Path, binary: Path, owner: Path, *, locked: bool, busy: bool) -> None:
    _connections.native_binary = lambda: binary
    process = subprocess.Popen(
        [str(owner), str(root), str(binary)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    assert process.stdout is not None
    status = cast(dict[str, object], json.loads(process.stdout.readline()))
    original_command = _connections._command

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "sdk-close":
            return original_command(binary, "stop", "--handle", args[-1])
        if args[0] == "sdk-prepare":
            return {
                "schema": 1,
                "owner": {
                    key: status[key] for key in ("connection_handle", "executable", "expires_at")
                },
                "prepared": original_command(
                    binary,
                    "prepare",
                    "--handle",
                    _connections._text(status["connection_handle"]),
                    "--service",
                    "database",
                ),
            }
        return original_command(binary, *args, input_value=input_value)

    _connections._command = command
    deployment = tnl.create_client(
        project="acme/project",
        services={"database": {"protocol": "postgres"}},
        token="fixture-private",
    ).deployment("production")

    class Client:
        def __init__(self, connection: tnl.Connection | tnl.LocalConnection) -> None:
            assert isinstance(connection, tnl.PostgresConnection)
            self.port = connection.port

    closed_clients: list[Client] = []
    get_client = deployment.client("database", create=Client, close=closed_clients.append)
    client_runner = asyncio.Runner()

    async def prepare() -> tnl.Connection:
        connection = await deployment.connect("database")
        assert isinstance(connection, tnl.PostgresConnection)
        return connection

    try:
        db = asyncio.run(prepare())
        client = client_runner.run(get_client())
        assert client.port == db.port
        assert isinstance(db, tnl.PostgresConnection)
        held, release = threading.Event(), threading.Event()
        assert deployment._scope.entry is not None
        ipc = deployment._scope.entry[1]
        assert ipc is not None
        port = ipc.port
        workers: list[threading.Thread] = []
        failures: list[BaseException] = []
        if busy:
            # pause an actual native prepare response inside HTTPResponse.read.
            # the proxy retains native scope/authentication and changes only
            # when response bytes reach Python's inherited buffered reader.
            proxy = socket.socket()
            proxy.bind(("127.0.0.1", 0))
            proxy.listen(1)

            def forward() -> None:
                try:
                    with proxy, proxy.accept()[0] as peer, peer.makefile("rb") as stream:
                        assert stream.readline().startswith(b"POST /v1/connections/sdk-prepare ")
                        headers = {}
                        while (line := stream.readline()) != b"\r\n":
                            key, value = line.decode().split(":", 1)
                            headers[key.lower()] = value.strip()
                        body = stream.read(int(headers["content-length"]))
                        headers["host"] = f"127.0.0.1:{port}"
                        upstream = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            upstream.request("POST", "/v1/connections/sdk-prepare", body, headers)
                            response = upstream.getresponse()
                            data = response.read()
                            assert response.status == 200 and len(data) > 1
                        finally:
                            upstream.close()
                        peer.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            + f"Content-Length: {len(data)}\r\n".encode()
                            + b"Connection: keep-alive\r\n\r\n"
                            + data[:1]
                        )
                        held.set()
                        assert release.wait(5)
                        peer.sendall(data[1:])
                except BaseException as error:
                    failures.append(error)

            def prepare_busy() -> None:
                try:
                    deployment._scope.prepare("database", None)
                except BaseException as error:
                    failures.append(error)

            ipc.connections[0].close()
            ipc.connections[0].port = proxy.getsockname()[1]
            workers = [threading.Thread(target=forward), threading.Thread(target=prepare_busy)]
            for worker in workers:
                worker.start()

        def hold_locks() -> None:
            if busy:
                return
            if not locked:
                held.set()
                return
            with deployment._scope.lock, deployment._acquisitions["database"]._session.lock:
                held.set()
                assert release.wait(10)

        thread = threading.Thread(target=hold_locks)
        thread.start()
        assert held.wait(5)
        if busy:

            def reading_response() -> bool:
                frame = sys._current_frames().get(workers[1].ident or 0)
                while frame is not None:
                    if frame.f_code is http.client.HTTPResponse.read.__code__:
                        return True
                    frame = frame.f_back
                return False

            for _ in range(400):
                if reading_response():
                    break
                release.wait(0.005)
            assert reading_response(), "native response did not reach the buffered-reader boundary"
        pid = os.fork()
        if pid == 0:
            try:
                asyncio.run(get_client())
            except tnl.TnlError as error:
                assert error.code == "sdk.client_closed"
            else:
                raise AssertionError("child reused its parent's ordinary client")
            asyncio.run(get_client.aclose())
            assert not closed_clients
            try:
                ipc.prepare("database")
            except tnl.TnlError as error:
                assert error.code == "sdk.connection_unavailable"
            else:
                raise AssertionError("child reused inherited IPC")
            # run inherited exit hooks even if the child never uses a handle.
            atexit._run_exitfuncs()
            asyncio.run(deployment.aclose())
            try:
                asyncio.run(deployment.connect("database"))
            except tnl.TnlError as error:
                assert error.code == "sdk.connection_closed"
            else:
                raise AssertionError("inherited handle remained usable")
            fresh = tnl.create_client(
                project="acme/project",
                services={"database": {"protocol": "postgres"}},
                token="fixture-private",
            ).deployment("production")
            assert fresh._scope is not deployment._scope and fresh._scope.registry is None
            os._exit(0)
        release.set()
        thread.join(5)
        for worker in workers:
            worker.join(5)
            assert not worker.is_alive()
        assert not failures, failures
        if busy:
            ipc.connections[0].close()
            ipc.connections[0].port = port
        _, result = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(result) == 0
        assert process.poll() is None
        # the parent's IPC socket and its connector owner still work after child exit.
        assert asyncio.run(prepare()).port == db.port
        assert client_runner.run(get_client()) is client
        client_runner.run(get_client.aclose())
        assert closed_clients == [client] and process.poll() is None
        with socket.create_connection((db.host, db.port), timeout=5) as raw:
            raw.sendall(struct.pack("!II", 8, 80877103))
            assert raw.recv(1) == b"S"
            with db.ssl.wrap_socket(raw, server_hostname=db.server_hostname) as stream:
                stream.sendall(b"ping")
                assert stream.recv(4) == b"ping"
        client_runner.run(deployment.aclose())
        process.wait(timeout=5)
    finally:
        client_runner.close()
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)


if __name__ == "__main__":
    mode, directory, *args = sys.argv[1:]
    if mode == "fifo":
        fifo_probe(Path(directory))
    elif mode.startswith("ipc-"):
        ipc_probe(Path(directory), mode)
    elif mode.startswith("fork"):
        fork_probe(
            Path(directory),
            *(Path(arg) for arg in args),
            locked=mode == "fork-locked",
            busy=mode == "fork-busy",
        )
    else:
        command_probe(Path(directory), mode)
