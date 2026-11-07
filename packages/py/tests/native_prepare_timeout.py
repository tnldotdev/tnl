"""a cold command timeout must retain exact cleanup without stopping a peer."""

import asyncio
import http.client
import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlsplit

import tnl
from tnl import _connections


def peer_responds(connection: tnl.HTTPConnection) -> None:
    with (
        socket.create_connection((connection.host, connection.port), timeout=5) as raw,
        connection.ssl.wrap_socket(raw, server_hostname=connection.server_hostname) as stream,
    ):
        stream.sendall(
            b"POST / HTTP/1.1\r\nHost: service.example.test\r\n"
            b"Authorization: Bearer application-only\r\n"
            b"Content-Length: 13\r\nConnection: close\r\n\r\nstreamed-body"
        )
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
    assertion = Path("assertion").read_text().strip()
    tnl.configure_workload("test", token=lambda: assertion)
    failed = tnl.connect("api")
    scope = failed._session.scope
    original_timeout = _connections._TIMEOUT
    registry: str | None = None
    orphan: Path | None = None
    peer: tnl.ConnectionHandle[tnl.Connection] | None = None
    try:
        # the authority stalls service preparation, after sdkOwner has registered
        # its detached child. exercise the actual command deadline and SIGKILL,
        # not a synthetic exception or an abandoned asyncio worker.
        _connections._TIMEOUT = 5.0
        try:
            await failed
        except tnl.TnlError as error:
            assert error.code == "sdk.connection_unavailable"
        else:
            raise AssertionError("blocked cold preparation did not time out")
        finally:
            _connections._TIMEOUT = original_timeout

        registry = scope.registry
        assert registry is not None and scope.pending == 0
        records = json.loads((Path(registry) / "registry.json").read_text())["owners"]
        assert len(records) == 1
        requests = list(scope.request_handles)
        assert len(requests) == 1
        receipt = json.loads(Path(requests[0]).read_text())
        orphan = Path(receipt["owner_handle"])
        endpoint_port: int | None = None
        if startup:
            assert not orphan.exists()
            # the detached child owns its lifetime lock but has no ready IPC
            # handle. close must retain the receipt, not claim blind success.
            _connections._TIMEOUT = 1.0
            try:
                try:
                    await failed.aclose()
                except tnl.TnlError as error:
                    assert error.code == "sdk.connection_unavailable"
                else:
                    raise AssertionError("close reported joined while native startup was blocked")
            finally:
                _connections._TIMEOUT = original_timeout
            assert not failed._lifetime.joined and list(scope.request_handles) == requests
            assert json.loads(Path(requests[0]).read_text())["closed"] is True
        else:
            assert orphan.exists(), "timeout occurred before native owner registration"
            assert next(iter(records.values()))["owner"]["connection_handle"] == str(orphan)
            endpoint = urlsplit(json.loads(orphan.read_text())["url"])
            assert endpoint.hostname == "127.0.0.1" and endpoint.port is not None
            endpoint_port = endpoint.port
            with socket.create_connection((endpoint.hostname, endpoint.port), timeout=5):
                pass
        print("timed-out", flush=True)
        assert await asyncio.to_thread(input) == "released"

        # a different native-verified identity shares this registry. no SDK entry
        # was returned by the first command, so this is another cold dispatch.
        assertion = Path("peer-assertion").read_text().strip()
        peer = tnl.connect("api")
        assert peer._session.scope is scope
        snapshot = await peer
        assert isinstance(snapshot, tnl.HTTPConnection)
        peer_owner = peer._session.handle
        assert peer_owner is not None and Path(peer_owner) != orphan
        peer_responds(snapshot)

        # failed exact cleanup remains retryable without changing the preparation
        # error or replacing its preallocated request reference.
        if not startup:
            orphan.chmod(0o644)
            try:
                try:
                    await failed.aclose()
                except tnl.TnlError as error:
                    assert error.code == "sdk.connection_unavailable"
                else:
                    raise AssertionError("native accepted an unprotected owner handle")
                assert not failed._lifetime.joined and list(scope.request_handles) == requests
                assert orphan.exists()
                peer_responds(snapshot)
            finally:
                orphan.chmod(0o600)
        await failed.aclose()
        assert failed._lifetime.joined
        assert Path(peer_owner).exists(), "timed-out close stopped its healthy peer"
        assert (await peer).port == snapshot.port
        peer_responds(snapshot)
        if not startup:
            assert not orphan.exists(), (
                "aclose() reported joined after cold sdk-prepare timed out, "
                "but its registered native owner and IPC listener remain alive"
            )
        # a late startup may exit on its broken ready pipe, leaving a stale
        # descriptor. prove kernel lifetime completion rather than file absence.
        stopped = await asyncio.to_thread(
            _connections._command, binary, "recover", "--handle", str(orphan)
        )
        assert stopped == {"schema": 1, "state": "stopped"}
        if startup and orphan.exists():
            stale_endpoint = urlsplit(json.loads(orphan.read_text())["url"])
            assert stale_endpoint.port is not None
            released(stale_endpoint.port)
        if endpoint_port is not None:
            released(endpoint_port)
        if startup:
            records = json.loads((Path(registry) / "registry.json").read_text())["owners"]
            retired = records[receipt["owner_key"]]
            assert retired["failure"] == "TNL_CLIENT_CONNECTION_EXPIRED"
            assert retired["owner"]["connection_handle"] == ""
        assert not scope.request_handles
        await failed.aclose()
        assert (await peer).port == snapshot.port
        peer_responds(snapshot)
        print("joined", flush=True)
    finally:
        _connections._TIMEOUT = original_timeout
        try:
            # contain the pre-fix leak with the production exact-reference path.
            # a registry-wide stop would hide a peer-isolation regression.
            if registry is not None and orphan is not None:
                await asyncio.to_thread(
                    _connections._command,
                    binary,
                    "sdk-close",
                    "--registry",
                    registry,
                    "--parent-pid",
                    str(os.getpid()),
                    "--handle",
                    str(orphan),
                )
                if not startup:
                    assert not orphan.exists()
                if peer is not None and peer._session.handle is not None:
                    healthy = peer.snapshot()
                    assert isinstance(healthy, tnl.HTTPConnection)
                    peer_responds(healthy)
        finally:
            if peer is not None:
                await peer.aclose()


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]).resolve(strict=True), "startup" in sys.argv[2:]))
