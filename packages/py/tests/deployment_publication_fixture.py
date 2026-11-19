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
        if sys.argv[1] == "python-private":
            async with await deployment.publish("private", tnl.handler(endpoint)) as publication:
                assert publication.url is None
                print(json.dumps({}), flush=True)
                await asyncio.to_thread(sys.stdin.readline)
            return
        if sys.argv[1] == "python-lost-reply":
            try:
                await deployment.publish(tnl.handler(endpoint), access="anonymous")
            except tnl.TnlError as cause:
                assert cause.code == "sdk.dev_unavailable"
            else:
                raise AssertionError("lost registration reply was accepted")
            await deployment.aclose()
            print(json.dumps({"recovered": True}), flush=True)
            return
        async with await deployment.publish(
            tnl.handler(endpoint),
            access="restricted" if sys.argv[1] == "python-restricted" else "anonymous",
            limits=tnl.Limits(
                requests=10, concurrency=2, rate=tnl.RateLimit(requests=100, per="1s")
            ),
        ) as publication:
            print(json.dumps({"url": publication.url}), flush=True)
            await asyncio.to_thread(sys.stdin.readline)


asyncio.run(main())
