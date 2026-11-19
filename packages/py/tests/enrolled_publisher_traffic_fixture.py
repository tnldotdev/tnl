"""publish over the native relay using a disposable control topology."""

import asyncio
import hashlib
import json
import ssl
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
        snapshot = await pub.export_certificate()
        end = "-----END CERTIFICATE-----"
        leaf = snapshot.certificate.certificate_pem.split(end, 1)[0] + end
        print(
            json.dumps(
                {
                    "identity": owner.publisher_identity_id,
                    "url": pub.url,
                    "publisher_url": pub.publisher_url,
                    "certificate_sha256": hashlib.sha256(
                        ssl.PEM_cert_to_DER_cert(leaf)
                    ).hexdigest(),
                }
            ),
            flush=True,
        )
        await asyncio.to_thread(sys.stdin.readline)
        await pub.aclose()
        try:
            await pub.export_certificate()
        except tnl.TnlError as error:
            assert error.code == "sdk.certificate_unavailable"
        else:
            raise AssertionError("a closed publication exported its certificate")


asyncio.run(main())
