"""prepare across native renewal without taking ownership of the borrowed process."""

import asyncio
import sys
from pathlib import Path

import tnl
from tnl import _connections

_connections.native_binary = lambda: Path(sys.argv[1])


async def main() -> None:
    handle = tnl.connect("api")
    try:
        first = await handle
        print("cold", flush=True)
        assert await asyncio.to_thread(input) == "after"
        for _ in range(2):
            current = await handle
            assert current.port == first.port
            assert current.expires_at > first.expires_at
        assert handle.snapshot().port == first.port
        print("retained", flush=True)
        assert await asyncio.to_thread(input) == "stop"
    finally:
        await handle.aclose()


asyncio.run(main())
