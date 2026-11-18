"""exercise the built native publisher through Python's async owner."""

import asyncio
import sys

from starlette.requests import Request
from starlette.responses import PlainTextResponse

import tnl


async def endpoint(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("unused")


async def main() -> None:
    calls = 0
    bootstrap = sys.stdin.readline().strip()

    async def enrollment() -> str:
        nonlocal calls
        calls += 1
        return bootstrap

    def unexpected() -> str:
        raise AssertionError("a saved publisher must not read bootstrap again")

    async with await tnl.publisher(control_url=sys.argv[1], enrollment=enrollment) as first:
        assert calls == 1
        try:
            await first.publish("unapproved", tnl.handler(endpoint))
        except tnl.TnlError as cause:
            assert cause.code == "sdk.request_rejected"
        else:
            raise AssertionError("an unapproved deployment service started")
    async with await tnl.publisher(enrollment=unexpected) as second:
        assert second.publisher_identity_id == first.publisher_identity_id
        assert second.deployment_id == first.deployment_id
        assert second.control_url == sys.argv[1]


asyncio.run(main())
