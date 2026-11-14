"""prepare across native renewal without taking ownership of the borrowed process."""

import asyncio
import sys
from pathlib import Path

import tnl
from tnl import _connections

_connections.native_binary = lambda: Path(sys.argv[1])


async def main() -> None:
    deployment = tnl.create_client(
        project=sys.argv[2], services={"api": {"protocol": "http"}}
    ).deployment("remote")
    try:
        first = await deployment.connect("api")
        assert isinstance(first, tnl.HTTPConnection)
        print("cold", flush=True)
        assert await asyncio.to_thread(input) == "after"
        for _ in range(2):
            current = await deployment.connect("api")
            assert isinstance(current, tnl.HTTPConnection)
            assert current.port == first.port
            assert current.expires_at > first.expires_at
        latest = await deployment.connect("api")
        assert isinstance(latest, tnl.HTTPConnection) and latest.port == first.port
        print("retained", flush=True)
        assert await asyncio.to_thread(input) == "stop"
    finally:
        await deployment.aclose()


asyncio.run(main())
