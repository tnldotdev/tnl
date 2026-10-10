"""verify bounded HTTP/JSON over the private Unix socket."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from tnl._native import NativeRuntime
from tnl._protocol import InvalidResponse, parse_status


def test_native_request_uses_the_bounded_private_socket() -> None:
    async def scenario() -> None:
        with tempfile.TemporaryDirectory(prefix="tnl-python-", dir="/tmp") as directory:
            socket = str(Path(directory) / "runtime.sock")
            received: list[object] = []

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                headers = await reader.readuntil(b"\r\n\r\n")
                assert headers.startswith(b"POST /v1/ad-hoc/status HTTP/1.1\r\n")
                size = next(
                    int(line.split(b":", 1)[1].strip())
                    for line in headers.lower().split(b"\r\n")
                    if line.startswith(b"content-length:")
                )
                received.append(json.loads(await reader.readexactly(size)))
                payload = json.dumps(
                    {
                        "version": 1,
                        "registration_id": "ivk_example",
                        "state": "routable",
                        "public_url_id": "url_example",
                        "public_url": "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test",
                        "publish_run_number": 1,
                    }
                ).encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(payload)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + payload
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_unix_server(handle, path=socket)
            try:
                value = await NativeRuntime().request(
                    socket,
                    "status",
                    {
                        "version": 1,
                        "registration_id": "ivk_example",
                        "owner": "owner",
                    },
                )
                assert parse_status(value, "ivk_example").state == "routable"
                assert received == [
                    {
                        "version": 1,
                        "registration_id": "ivk_example",
                        "owner": "owner",
                    }
                ]
            finally:
                server.close()
                await server.wait_closed()

    asyncio.run(scenario())


def test_native_request_rejects_oversized_socket_response() -> None:
    async def scenario() -> None:
        with tempfile.TemporaryDirectory(prefix="tnl-python-", dir="/tmp") as directory:
            socket = str(Path(directory) / "runtime.sock")

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                await reader.readuntil(b"\r\n\r\n")
                payload = b"x" * (64 * 1024 + 1)
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(payload)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + payload
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_unix_server(handle, path=socket)
            try:
                with pytest.raises(InvalidResponse):
                    await NativeRuntime().request(socket, "status", {"version": 1})
            finally:
                server.close()
                await server.wait_closed()

    asyncio.run(scenario())
