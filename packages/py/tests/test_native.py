"""verify bounded, authenticated ad-hoc HTTP/JSON on the owner endpoint."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from tnl._app_native import AppRuntime
from tnl._native import NativeRuntime
from tnl._protocol import InvalidResponse, parse_status


def test_native_request_uses_the_owner_credential(tmp_path: Path) -> None:
    async def scenario() -> None:
        received: list[object] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            headers = await reader.readuntil(b"\r\n\r\n")
            assert headers.startswith(b"POST /v1/ad-hoc/status HTTP/1.1\r\n")
            assert b"authorization: bearer " + b"a" * 43 in headers.lower()
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

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        endpoint = tmp_path / "publisher.endpoint.json"
        endpoint.write_text(
            json.dumps({"version": 1, "url": f"http://127.0.0.1:{port}", "credential": "a" * 43})
        )
        try:
            value = await NativeRuntime().request(
                str(endpoint),
                "status",
                {"version": 1, "registration_id": "ivk_example", "owner": "owner"},
            )
            assert parse_status(value, "ivk_example").state == "routable"
            assert received == [{"version": 1, "registration_id": "ivk_example", "owner": "owner"}]
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_compose_app_descriptor_requires_its_mounted_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoint = tmp_path / "app.web.endpoint.json"
    endpoint.write_text(
        json.dumps({"version": 1, "url": "http://publisher:8765", "credential": "a" * 43})
    )
    with pytest.raises(InvalidResponse):
        AppRuntime._endpoint(str(endpoint))
    monkeypatch.setenv("TNL_APP_ENDPOINT", str(endpoint))
    assert AppRuntime._endpoint(str(endpoint)) == ("http://publisher:8765", "a" * 43)
    endpoint.write_text(
        json.dumps({"version": 1, "url": "http://other.example:8765", "credential": "a" * 43})
    )
    with pytest.raises(InvalidResponse):
        AppRuntime._endpoint(str(endpoint))


def test_native_request_rejects_oversized_tcp_response(tmp_path: Path) -> None:
    async def scenario() -> None:
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

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        endpoint = tmp_path / "publisher.endpoint.json"
        endpoint.write_text(
            json.dumps({"version": 1, "url": f"http://127.0.0.1:{port}", "credential": "a" * 43})
        )
        try:
            with pytest.raises(InvalidResponse):
                await NativeRuntime().request(str(endpoint), "status", {"version": 1})
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())
