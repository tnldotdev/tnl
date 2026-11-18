"""publish over the native relay using a disposable control topology."""

import asyncio
import json
import sys

from starlette.requests import Request
from starlette.responses import PlainTextResponse

import tnl


async def main() -> None:
    origin, _sdk, instance = sys.argv[1:4]
    key = sys.stdin.readline().rstrip("\n")

    def enrollment() -> str:
        if not key:
            raise AssertionError("saved publisher asked for bootstrap")
        return key

    async def handler(_request: Request) -> PlainTextResponse:
        return PlainTextResponse(f"{instance}:{'initial' if key else 'reopened'}")

    async with await tnl.publisher(
        control_url=origin if key else None, instance=instance, enrollment=enrollment
    ) as owner:
        pub = await owner.publish("web", tnl.handler(handler))
        print(
            json.dumps({"identity": owner.publisher_identity_id, "url": pub.publisher_url}),
            flush=True,
        )
        await asyncio.to_thread(sys.stdin.readline)


asyncio.run(main())
