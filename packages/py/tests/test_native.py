"""real loopback HTTP authentication, bounds, and private descriptor discovery."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

from tnl import _native
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, InvalidResponse, RegistrationLost, TnlError, parse_endpoint


def test_request_uses_exact_authority_bearer_and_no_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        received: list[bytes] = []

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            received.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        endpoint = Endpoint(f"http://127.0.0.1:{port}", "b" * 64, "a" * 32, "app", service="web")
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        try:
            await NativeRuntime().request(endpoint, "health")
            assert received[0].startswith(b"GET /v1/health HTTP/1.1\r\n")
            assert f"Host: 127.0.0.1:{port}\r\n".encode() in received[0]
            assert f"Authorization: Bearer {'b' * 64}\r\n".encode() in received[0]
            assert b"origin:" not in received[0].lower()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "status,payload,error",
    [
        (200, b"x" * (64 * 1024 + 1), InvalidResponse),
        (401, b'{"code":"runtime.unauthorized","message":"stale"}', RegistrationLost),
        (302, b"", InvalidResponse),
    ],
)
def test_requests_bound_responses_and_never_follow_redirects(
    status: int, payload: bytes, error: type[Exception]
) -> None:
    async def scenario() -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                f"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\nLocation: http://127.0.0.1:1\r\n"
                "Connection: close\r\n\r\n".encode()
                + payload
            )
            await writer.drain()
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
            with pytest.raises(error):
                await NativeRuntime().request(endpoint, "status")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "code,hint",
    [
        ("runtime.publisher_setup_required", "tnl publisher setup --namespace"),
        ("runtime.publisher_credential_file_invalid", "publisher file"),
    ],
)
def test_publisher_selection_failure_is_authored_without_private_details(
    code: str, hint: str
) -> None:
    async def scenario() -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n\r\n")
            body = json.dumps({"code": code, "message": "secret provider detail"}).encode()
            writer.write(
                b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        endpoint = Endpoint(
            f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}",
            "b" * 64,
            "a" * 32,
            "invocation",
            invocation_id="ivk_" + "A" * 22,
        )
        try:
            with pytest.raises(TnlError, match=hint) as caught:
                await NativeRuntime().request(endpoint, "ad-hoc/register", {})
            assert caught.value.code == code.replace("runtime.", "sdk.")
            assert "secret provider detail" not in str(caught.value)
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_private_readonly_mounted_descriptor_skips_binary_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        descriptor = {
            "version": 1,
            "url": f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}",
            "capability": "b" * 64,
            "owner_id": "a" * 32,
            "scope": "app",
            "service": "web",
        }
        tmp_path.chmod(0o700)
        path = tmp_path / "endpoint.json"
        monkeypatch.setenv("TNL_APP_ENDPOINT", str(path))

        def no_binary() -> Path:
            pytest.fail("mounted endpoint attempted to select native")

        monkeypatch.setattr(_native, "native_binary", no_binary)
        try:

            async def publish_descriptor() -> None:
                await asyncio.sleep(0.05)
                path.write_text(json.dumps(descriptor))
                path.chmod(0o400)

            publication = asyncio.create_task(publish_descriptor())
            assert (await NativeRuntime().start(str(tmp_path), service="web")).scope == "app"
            await publication
            with pytest.raises(InvalidResponse):
                await NativeRuntime().start(str(tmp_path), service="other")
            path.chmod(0o644)
            with pytest.raises(InvalidResponse):
                await NativeRuntime().start(str(tmp_path), service="web")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_endpoint_validation_has_no_owner_or_unix_compatibility() -> None:
    base = {
        "version": 1,
        "url": "http://127.0.0.1:1234",
        "capability": "b" * 64,
        "owner_id": "a" * 32,
        "scope": "app",
        "service": "web",
    }
    for change in (
        {"scope": "owner"},
        {"url": "http://localhost:1234"},
        {"url": "http://127.0.0.1:1234/"},
        {"socket": "/private/socket"},
        {"capability": "secret"},
    ):
        with pytest.raises(InvalidResponse):
            parse_endpoint({**base, **change}, service="web")


def test_native_discovery_selects_scope_and_reads_fragmented_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            headers = await reader.readuntil(b"\r\n\r\n")
            assert f"Authorization: Bearer {'b' * 64}".encode() in headers
            writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        api = await asyncio.start_server(handle, "127.0.0.1", 0)
        descriptor = {
            "version": 1,
            "url": f"http://127.0.0.1:{api.sockets[0].getsockname()[1]}",
            "capability": "b" * 64,
            "owner_id": "a" * 32,
            "scope": "app",
            "service": "web",
        }
        binary = tmp_path / "tnl"
        binary.write_text(f"""#!{sys.executable}
import sys, time
assert sys.argv[1:4] == ["--no-telemetry", "runtime", "endpoint"]
assert "--state-dir" in sys.argv and "--service" in sys.argv
data = {json.dumps(descriptor)!r}
sys.stdout.write(data[:40]); sys.stdout.flush(); time.sleep(0.01)
sys.stdout.write(data[40:])
""")
        binary.chmod(0o700)
        monkeypatch.delenv("TNL_APP_ENDPOINT", raising=False)
        monkeypatch.setattr(_native, "native_binary", lambda: binary)
        try:
            result = await NativeRuntime().start(str(tmp_path), service="web", state_dir="/state")
            assert result.owner_id == descriptor["owner_id"]
            assert result.service == "web"
        finally:
            api.close()
            await api.wait_closed()

    asyncio.run(scenario())
