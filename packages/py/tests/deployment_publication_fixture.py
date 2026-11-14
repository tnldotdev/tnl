"""real SDK subprocess for the control-backed native publication topology."""

import asyncio
import json
import sys

from starlette.requests import Request
from starlette.responses import PlainTextResponse

import tnl


async def endpoint(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("SDK publication")


async def main() -> None:
    assert not hasattr(tnl, "open")
    client = tnl.create_client(project="acme/sdk-publication")
    async with client.deployment("production") as deployment:
        async with await deployment.publish(
            tnl.handler(endpoint), access="anonymous"
        ) as publication:
            print(json.dumps({"url": publication.url}), flush=True)
            await asyncio.to_thread(sys.stdin.readline)


asyncio.run(main())
