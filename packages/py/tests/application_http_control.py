"""qualify Python proofs against the real control API with no personal session."""

import asyncio
import json
import ssl
import sys
from pathlib import Path
from unittest.mock import patch

import httpx

import tnl
from tnl import _connections


async def main() -> None:
    path, resource, expected, mode, ca = sys.argv[1:]
    original = httpx.AsyncHTTPTransport
    context = ssl.create_default_context(cafile=ca)

    def transport(*, trust_env: bool, retries: int) -> httpx.AsyncHTTPTransport:
        assert trust_env is False and retries == 0
        # trust only this test's loopback control certificate, never disable TLS.
        return original(verify=context, trust_env=False, retries=0)

    def native() -> Path:
        raise AssertionError("application HTTP started native authentication")

    _connections.native_binary = native
    with patch.object(httpx, "AsyncHTTPTransport", transport):
        await check(path, resource, expected, mode)


async def check(path: str, resource: str, expected: str, mode: str) -> None:
    raw = Path(path).read_text()
    document: dict[str, object] = json.loads(raw)
    for credential in (raw, document):
        async with tnl.create_tnl(credential=credential) as app:
            selected = app.connect(resource)
            if mode == "denied":
                try:
                    await selected
                except tnl.TnlError as error:
                    assert error.code == "sdk.credential_denied"
                else:
                    raise AssertionError("revoked application retained visit permission")
                continue
            assert mode == "ready"
            prepared = await selected
            assert prepared.url == expected and selected.url == expected
            created: list[object] = []
            closed: list[object] = []

            def create(settings: tnl.HTTPClientSettings, created: list[object] = created) -> object:
                assert settings.url == expected
                value = object()
                created.append(value)
                return value

            get = app.client(resource, create=create, close=closed.append)
            ordinary = await get()
            for _ in range(10):
                assert await get() is ordinary
            assert created == [ordinary] and not closed
            await get.aclose()
            assert closed == [ordinary]


asyncio.run(main())
