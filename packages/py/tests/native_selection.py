"""exercise actual SDK selection against the integration topology."""

import asyncio
import sys
from pathlib import Path

import tnl
from tnl import _connections

# supply the built binary in place of the wheel's packaged binary only.
_connections.native_binary = lambda: Path(sys.argv[1])
token = Path("assertion").read_text().strip()
tnl.configure_workload("test", token=lambda: token)


async def main() -> None:
    handle = tnl.connect("api")
    try:
        first = await handle
        owner = handle._session.handle
        print("cold", flush=True)
        assert await asyncio.to_thread(input) == "warm"
        for _ in range(10):
            current = await handle
            assert current.port == first.port
            assert handle._session.handle == owner
            assert current.expires_at == first.expires_at
        print("warm", flush=True)
        assert await asyncio.to_thread(input) == "stop"
    finally:
        await handle.aclose()


asyncio.run(main())
