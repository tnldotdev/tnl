"""exercise actual SDK selection against the integration topology."""

import asyncio
import http.client
import os
import socket
import sys
from pathlib import Path

import tnl
from tnl import _connections

# supply the built binary in place of the wheel's packaged binary only.
_connections.native_binary = lambda: Path(sys.argv[1])
token = Path("assertion").read_text().strip()
native_provider = "provider" in sys.argv
rotating_file = "refresh" in sys.argv
if rotating_file:
    tnl.configure_workload("test", token_file="assertion")
elif not native_provider:
    tnl.configure_workload("test", token=lambda: token)


async def main() -> None:
    handle = tnl.connect("api")
    try:

        async def prepare() -> _connections.Connection:
            return await handle

        first = (await asyncio.gather(*(prepare() for _ in range(4 if native_provider else 1))))[0]
        owner = handle._session.handle
        print("cold", flush=True)
        assert await asyncio.to_thread(input) == "warm"
        if native_provider:
            os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "provider-warm"
        for _ in range(10):
            current = await handle
            assert current.port == first.port
            assert handle._session.handle == owner
            assert current.expires_at == first.expires_at
        if native_provider:
            del os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
            try:
                await handle
            except tnl.TnlError as error:
                assert error.code == "sdk.workload_assertion_unavailable"
                assert error.__cause__ is None
            else:
                raise AssertionError("native used a stale provider credential")
            os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "provider-warm"
            assert (await handle).port == first.port
            assert handle._session.handle == owner
        print("warm", flush=True)
        if rotating_file:
            assert isinstance(first, tnl.HTTPConnection)

            def open_stream() -> tuple[socket.socket, http.client.HTTPResponse]:
                raw = socket.create_connection((first.host, first.port), timeout=90)
                secure = first.ssl.wrap_socket(raw, server_hostname=first.server_hostname)
                secure.sendall(
                    (
                        "GET /refresh-stream HTTP/1.1\r\n"
                        f"Host: {first.server_hostname}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode()
                )
                response = http.client.HTTPResponse(secure)
                response.begin()
                return secure, response

            stream, response = await asyncio.to_thread(open_stream)
            try:
                assert await asyncio.to_thread(response.readline) == b"before-proof\n"
                print("streaming", flush=True)
                assert await asyncio.to_thread(input) == "refreshed"
                assert await asyncio.to_thread(response.read) == b"after-proof\n"
                print("retained", flush=True)
            finally:
                response.close()
                stream.close()
        if "lifecycle" in sys.argv:
            from native_lifecycle import run

            await run(handle, first)
        assert await asyncio.to_thread(input) == "stop"
    finally:
        await handle.aclose()


asyncio.run(main())
