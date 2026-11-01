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
from pathlib import Path
from typing import cast

import tnl
from tnl import _connections, _native


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


def fork_probe(root: Path, binary: Path, owner: Path, *, locked: bool, busy: bool) -> None:
    _connections.native_binary = lambda: binary
    process = subprocess.Popen(
        [str(owner), str(root), str(binary)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    assert process.stdout is not None
    status = cast(dict[str, object], json.loads(process.stdout.readline()))
    original_command = _connections._command

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        if args[0] == "start":
            return status
        return original_command(binary, *args, input_value=input_value)

    _connections._command = command
    handle = tnl.connect("database", directory=root)

    async def prepare() -> tnl.Connection:
        return await handle

    try:
        db = asyncio.run(prepare())
        assert isinstance(db, tnl.PostgresConnection)
        held, release = threading.Event(), threading.Event()
        ipc = handle._session.ipc
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
                        assert stream.readline().startswith(b"POST /v1/connections/prepare ")
                        headers = {}
                        while (line := stream.readline()) != b"\r\n":
                            key, value = line.decode().split(":", 1)
                            headers[key.lower()] = value.strip()
                        body = stream.read(int(headers["content-length"]))
                        headers["host"] = f"127.0.0.1:{port}"
                        upstream = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        try:
                            upstream.request("POST", "/v1/connections/prepare", body, headers)
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
                    handle._session.read(True, service="database")
                except BaseException as error:
                    failures.append(error)

            assert ipc.connection is not None
            ipc.connection.close()
            ipc.connection = http.client.HTTPConnection(
                "127.0.0.1", proxy.getsockname()[1], timeout=5
            )
            workers = [threading.Thread(target=forward), threading.Thread(target=prepare_busy)]
            for worker in workers:
                worker.start()

        def hold_locks() -> None:
            if busy:
                return
            if not locked:
                held.set()
                return
            with _connections._sessions_lock, handle._session.lock:
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
                ipc.prepare("database")
            except tnl.TnlError as error:
                assert error.code == "sdk.connection_unavailable"
            else:
                raise AssertionError("child reused inherited IPC")
            # run inherited exit hooks even if the child never uses a handle.
            atexit._run_exitfuncs()
            handle.close()
            try:
                handle.snapshot()
            except tnl.TnlError as error:
                assert error.code == "sdk.connection_closed"
            else:
                raise AssertionError("inherited handle remained usable")
            fresh = tnl.connect("database", directory=root)
            assert fresh._session is not handle._session
            try:
                fresh.snapshot()
            except tnl.TnlError as error:
                assert error.code == "sdk.connection_not_prepared"
            else:
                raise AssertionError("child reused parent capability")
            os._exit(0)
        release.set()
        thread.join(5)
        for worker in workers:
            worker.join(5)
            assert not worker.is_alive()
        assert not failures, failures
        if busy:
            assert ipc.connection is not None
            ipc.connection.close()
            ipc.connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        _, result = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(result) == 0
        assert process.poll() is None
        # the parent's IPC socket and its connector owner still work after child exit.
        assert asyncio.run(prepare()).port == db.port
        with socket.create_connection((db.host, db.port), timeout=5) as raw:
            raw.sendall(struct.pack("!II", 8, 80877103))
            assert raw.recv(1) == b"S"
            with db.ssl.wrap_socket(raw, server_hostname=db.server_hostname) as stream:
                stream.sendall(b"ping")
                assert stream.recv(4) == b"ping"
        handle.close()
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)


if __name__ == "__main__":
    mode, directory, *args = sys.argv[1:]
    if mode == "fifo":
        fifo_probe(Path(directory))
    elif mode.startswith("fork"):
        fork_probe(
            Path(directory),
            *(Path(arg) for arg in args),
            locked=mode == "fork-locked",
            busy=mode == "fork-busy",
        )
    else:
        command_probe(Path(directory), mode)
