"""bounded native event HTTP requests and safe cursor expiry."""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, TnlError


def test_publication_events_encode_cursors_and_classify_expiry_without_private_details() -> None:
    async def scenario() -> None:
        received: list[str] = []
        failures: list[Exception] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                headers = (await reader.readuntil(b"\r\n\r\n")).decode()
                method, address, _ = headers.split("\r\n", 1)[0].split()
                assert method == "GET" and "Content-Type:" not in headers
                assert f"Authorization: Bearer {'b' * 64}" in headers
                url = urlsplit(address)
                assert url.path == "/v1/events"
                cursor = parse_qs(url.query)["after"][0]
                received.append(cursor)
                body = b"[]" + b" " * 65536
                status = 200
                if cursor == "expired":
                    status = 410
                    body = json.dumps(
                        {"code": "runtime.cursor_expired", "message": "private native details"}
                    ).encode()
                writer.write(
                    (
                        f"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                    ).encode()
                    + body
                )
                await writer.drain()
            except Exception as error:
                failures.append(error)
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        endpoint = Endpoint(
            f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}",
            "b" * 64,
            "a" * 32,
            "app",
            service="web",
        )
        try:
            assert (
                await NativeRuntime().request(endpoint, "events", {"after": "saved#?&cursor"}) == []
            )
            with pytest.raises(TnlError) as caught:
                await NativeRuntime().request(endpoint, "events", {"after": "expired"})
            assert caught.value.code == "sdk.event_cursor_expired"
            assert "private native details" not in str(caught.value)
            assert received == ["saved#?&cursor", "expired"] and not failures
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())
