"""exercise actual normal SDK clients against the canonical integration topology."""

import asyncio
import http.client
import json
import os
import socket
import ssl
import sys
from pathlib import Path

import tnl
from native_services import actual_owner, new_client
from tnl import _connections, _environment

binary = Path(sys.argv[1])
_connections.native_binary = lambda: binary
_environment.native_binary = lambda: binary
token = Path("assertion").read_text().strip()
native_provider = "provider" in sys.argv
rotating_file = "refresh" in sys.argv


async def main() -> None:
    acquisition = None
    if native_provider:
        request = json.loads(Path("environment.json").read_text())
        acquisition = tnl.NativeAcquisition("github-actions", audience=request["selection"]["environment"]["server"])
    elif rotating_file:
        acquisition = tnl.NativeAcquisition("token-file", token_file=str(Path("assertion").absolute()))
    selected = new_client(token, acquisition=acquisition)
    get_client: tnl.ClientFactory[ssl.SSLSocket] | None = None
    try:
        prepared = await asyncio.gather(*(selected.connect("api") for _ in range(4 if native_provider else 1)))
        first = prepared[0]
        assert all(value.port == first.port and value.expires_at == first.expires_at for value in prepared)
        owner = actual_owner(selected)
        print("cold", flush=True)
        assert await asyncio.to_thread(input) == "warm"
        if native_provider:
            os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "provider-warm"
        for _ in range(10):
            current = await selected.connect("api")
            assert current.port == first.port and current.expires_at == first.expires_at
            assert actual_owner(selected) == owner
        if native_provider:
            del os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
            try:
                await selected.connect("api")
            except tnl.TnlError as error:
                assert error.code == "sdk.workload_assertion_unavailable" and error.__cause__ is None
            else:
                raise AssertionError("native used stale provider credentials")
            os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "provider-warm"
            assert (await selected.connect("api")).port == first.port
            assert actual_owner(selected) == owner
        print("warm", flush=True)
        if rotating_file:
            created, closed = 0, 0

            async def create_socket(connection: tnl.Connection) -> ssl.SSLSocket:
                nonlocal created
                assert isinstance(connection, tnl.HTTPConnection)
                created += 1

                def dial() -> ssl.SSLSocket:
                    raw = socket.create_connection((connection.host, connection.port), timeout=90)
                    return connection.ssl.wrap_socket(raw, server_hostname=connection.server_hostname)

                return await asyncio.to_thread(dial)

            def close_socket(client: ssl.SSLSocket) -> None:
                nonlocal closed
                closed += 1
                client.close()

            previous = os.environ.get("TNL_CONNECTION_HANDLE")
            os.environ["TNL_CONNECTION_HANDLE"] = str(owner)
            get_client = tnl.client("api", create=create_socket, close=close_socket)
            try:
                stream = await get_client()
                for _ in range(3):
                    assert await get_client() is stream
                assert created == 1 and closed == 0

                def open_stream() -> http.client.HTTPResponse:
                    stream.sendall(("GET /refresh-stream HTTP/1.1\r\n" + f"Host: {first.server_hostname}\r\nConnection: close\r\n\r\n").encode())
                    response = http.client.HTTPResponse(stream)
                    response.begin()
                    return response

                response = await asyncio.to_thread(open_stream)
                try:
                    assert await asyncio.to_thread(response.readline) == b"before-proof\n"
                    print("streaming", flush=True)
                    assert await asyncio.to_thread(input) == "refreshed"
                    assert await asyncio.to_thread(response.read) == b"after-proof\n"
                    refreshed = await selected.connect("api")
                    assert refreshed.port == first.port and actual_owner(selected) == owner
                finally:
                    response.close()
                    await get_client.aclose()
                assert closed == 1
            finally:
                if previous is None:
                    del os.environ["TNL_CONNECTION_HANDLE"]
                else:
                    os.environ["TNL_CONNECTION_HANDLE"] = previous
            print("retained", flush=True)
        if "lifecycle" in sys.argv:
            from native_lifecycle import run
            await run(selected, first, lambda: new_client(token))
        assert await asyncio.to_thread(input) == "stop"
    finally:
        try:
            if get_client is not None:
                await get_client.aclose()
        finally:
            await selected.aclose()


asyncio.run(main())
