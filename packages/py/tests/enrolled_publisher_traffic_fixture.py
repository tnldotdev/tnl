"""publish over the native relay using a disposable control topology."""

import asyncio
import json
import sys

from starlette.requests import Request
from starlette.responses import PlainTextResponse

import tnl


async def main() -> None:
    origin, _sdk, instance, service = sys.argv[1:5]
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
        pub = await tnl.publish(owner, service, tnl.handler(handler))
        if service == "internal":
            assert pub.url is None and pub.publisher_url is None
        print(
            json.dumps(
                {
                    "identity": owner.publisher_identity_id,
                    "url": pub.url,
                    "publisher_url": pub.publisher_url,
                }
            ),
            flush=True,
        )
        await asyncio.to_thread(sys.stdin.readline)


asyncio.run(main())
