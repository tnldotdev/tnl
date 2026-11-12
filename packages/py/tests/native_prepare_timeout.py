"""real native startup/IPC deadlines retain exact cleanup and an independent peer."""

import asyncio
import http.client
import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

import tnl
from native_lifecycle import unavailable
from native_services import actual_owner, context, new_client
from tnl import _connection_ipc, _connections, _environment


def peer_responds(connection: tnl.HTTPConnection) -> None:
    with socket.create_connection((connection.host, connection.port), timeout=5) as raw, connection.ssl.wrap_socket(raw, server_hostname=connection.server_hostname) as stream:
        stream.sendall(b"POST / HTTP/1.1\r\nHost: service.example.test\r\nAuthorization: Bearer application-only\r\nContent-Length: 13\r\nConnection: close\r\n\r\nstreamed-body")
        response = http.client.HTTPResponse(stream)
        response.begin()
        assert response.status == 201 and response.read() == b"streamed-body"


def released(port: int) -> None:
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)


async def main(binary: Path, startup: bool) -> None:
    _connections.native_binary = lambda: binary
    _environment.native_binary = lambda: binary
    original_start, original_ipc = _environment._START_TIMEOUT, _connection_ipc._TIMEOUT
    failed = new_client(Path("assertion").read_text().strip())
    selected = context(failed)
    before = set(Path(os.environ["TMPDIR"]).glob("tnl-connections-*"))
    peer = None
    try:
        _environment._START_TIMEOUT = 5.0
        _connection_ipc._TIMEOUT = 5.0
        try:
            await failed.connect("api")
        except tnl.TnlError as error:
            assert error.code == "sdk.connection_unavailable"
        else:
            raise AssertionError("blocked native preparation did not reach its actual deadline")
        finally:
            _environment._START_TIMEOUT, _connection_ipc._TIMEOUT = original_start, original_ipc
        assert not selected._workers
        assert len(selected._owners) == 1
        owned = selected._owners[0]
        directories = set(Path(os.environ["TMPDIR"]).glob("tnl-connections-*")) - before
        assert len(directories) == 1
        directory = directories.pop()
        orphan = directory / "handle.json"
        endpoint_port = None
        if startup:
            assert not orphan.exists()
            try:
                await failed.aclose()
            except BaseException as error:
                unavailable(error)
            else:
                raise AssertionError("close reported clean without native startup cleanup acknowledgement")
            assert not owned.stopped and not failed._cleaned
            assert directory.exists()
        else:
            assert actual_owner(failed) == orphan and orphan.exists()
            endpoint = urlsplit(json.loads(orphan.read_text())["url"])
            assert endpoint.hostname == "127.0.0.1" and endpoint.port is not None
            endpoint_port = endpoint.port
            with socket.create_connection((endpoint.hostname, endpoint.port), timeout=5):
                pass
        print("timed-out", flush=True)
        assert await asyncio.to_thread(input) == "released"

        peer = new_client(Path("peer-assertion").read_text().strip())
        snapshot = await peer.connect("api")
        peer_owner = actual_owner(peer)
        assert peer_owner != orphan
        peer_responds(snapshot)
        if not startup:
            orphan.chmod(0o644)
            try:
                try:
                    await failed.aclose()
                except BaseException as error:
                    unavailable(error)
                else:
                    raise AssertionError("cleanup accepted an unprotected native handle")
                assert not failed._cleaned and not owned.stopped and orphan.exists()
                peer_responds(snapshot)
            finally:
                orphan.chmod(0o600)
        # retain the strict startup recovery assertion. key disposal or an
        # unconfirmed native release is a production failure, not test success.
        await failed.aclose()
        assert failed._cleaned and owned.stopped and owned.process.returncode is not None
        assert not selected._workers and not selected._sources
        assert peer_owner.exists() and (await peer.connect("api")).port == snapshot.port
        peer_responds(snapshot)
        if not startup:
            assert not orphan.exists()
        if endpoint_port is not None:
            released(endpoint_port)
        await failed.aclose()
        assert (await peer.connect("api")).port == snapshot.port
        peer_responds(snapshot)
        print("joined", flush=True)
    finally:
        _environment._START_TIMEOUT, _connection_ipc._TIMEOUT = original_start, original_ipc
        if peer is not None:
            await peer.aclose()


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]).resolve(strict=True), "startup" in sys.argv[2:]))
