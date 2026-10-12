"""verify bounded HTTP/JSON and local authentication over loopback TCP."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

import pytest

from tnl._native import NativeRuntime
from tnl._protocol import InvalidResponse, parse_status


def test_native_request_uses_the_authenticated_local_endpoint() -> None:
    async def scenario() -> None:
        with tempfile.TemporaryDirectory(prefix="tnl-python-", dir="/tmp") as directory:
            endpoint = Path(directory) / "runtime.sock.endpoint.json"
            credential = "a" * 43
            received: list[object] = []

            async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                headers = await reader.readuntil(b"\r\n\r\n")
                assert headers.startswith(b"POST /v1/ad-hoc/status HTTP/1.1\r\n")
                assert b"authorization: bearer " + credential.encode() in headers.lower()
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

            server = await asyncio.start_server(handle, host="127.0.0.1", port=0)
            address = server.sockets[0].getsockname()
            endpoint.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "url": f"http://127.0.0.1:{address[1]}",
                        "credential": credential,
                    }
                )
            )
            try:
                value = await NativeRuntime().request(
                    str(endpoint),
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


def test_native_request_rejects_oversized_tcp_response() -> None:
    async def scenario() -> None:
        with tempfile.TemporaryDirectory(prefix="tnl-python-", dir="/tmp") as directory:
            endpoint = Path(directory) / "runtime.sock.endpoint.json"

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

            server = await asyncio.start_server(handle, host="127.0.0.1", port=0)
            address = server.sockets[0].getsockname()
            endpoint.write_text(
                json.dumps(
                    {"version": 1, "url": f"http://127.0.0.1:{address[1]}", "credential": "b" * 43}
                )
            )
            try:
                with pytest.raises(InvalidResponse):
                    await NativeRuntime().request(str(endpoint), "status", {"version": 1})
            finally:
                server.close()
                await server.wait_closed()

    asyncio.run(scenario())


def test_native_request_rejects_a_nonlocal_publisher_descriptor() -> None:
    async def scenario() -> None:
        with tempfile.TemporaryDirectory(prefix="tnl-python-", dir="/tmp") as directory:
            endpoint = Path(directory) / "runtime.sock.endpoint.json"
            endpoint.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "url": "http://another-host.example:4312",
                        "credential": "c" * 43,
                    }
                )
            )
            with pytest.raises(InvalidResponse):
                await NativeRuntime().request(str(endpoint), "status", {"version": 1})

    asyncio.run(scenario())


def test_native_request_does_not_keep_a_malformed_endpoint_secret_in_its_error() -> None:
    async def scenario() -> None:
        with tempfile.TemporaryDirectory(prefix="tnl-python-", dir="/tmp") as directory:
            endpoint = Path(directory) / "runtime.sock.endpoint.json"
            endpoint.write_text('{"credential":"private-test-value","url":')
            with pytest.raises(InvalidResponse) as failure:
                await NativeRuntime().request(str(endpoint), "status", {"version": 1})
            assert failure.value.__cause__ is None
            assert failure.value.__context__ is None

    asyncio.run(scenario())
