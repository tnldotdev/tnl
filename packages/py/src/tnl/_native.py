"""call the owner-scoped local publisher API for ad-hoc ASGI tunnels."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast

import httpx

from ._app_native import AppRuntime
from ._protocol import InvalidResponse, NativeUnavailable, RegistrationLost, TnlError


class NativeRuntime:
    async def start(self, directory: str) -> str:
        binary = Path(__file__).parent / "bin" / "tnl"
        if not binary.is_file():
            raise TnlError(
                "sdk.native_missing", "install a platform wheel containing the tnl binary"
            )
        try:
            address = await asyncio.create_subprocess_exec(
                str(binary),
                "--no-telemetry",
                "runtime",
                "owner-endpoint",
                "--directory",
                directory,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                limit=64 << 10,
            )
            try:
                stdout, _ = await asyncio.wait_for(address.communicate(), 30)
            except TimeoutError as cause:
                address.kill()
                await address.communicate()
                raise NativeUnavailable() from cause
            if address.returncode != 0 or len(stdout) > 64 << 10:
                raise NativeUnavailable()
            result: object = json.loads(stdout)
            if (
                not isinstance(result, dict)
                or set(result) != {"version", "path"}
                or result["version"] != 1
                or not isinstance(result["path"], str)
                or not Path(result["path"]).is_absolute()
                or not result["path"].endswith(".endpoint.json")
                or "\0" in result["path"]
            ):
                raise InvalidResponse()
            endpoint = cast(str, result["path"])
            if not await self.healthy(endpoint):
                await asyncio.create_subprocess_exec(
                    str(binary),
                    "--no-telemetry",
                    "runtime",
                    "serve",
                    "--directory",
                    directory,
                    cwd=directory,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                deadline = asyncio.get_running_loop().time() + 15
                while not await self.healthy(endpoint):
                    if asyncio.get_running_loop().time() >= deadline:
                        raise NativeUnavailable()
                    await asyncio.sleep(0.05)
            return endpoint
        except (OSError, TimeoutError, ValueError) as cause:
            raise NativeUnavailable() from cause

    async def healthy(self, endpoint: str) -> bool:
        try:
            url, credential = AppRuntime._endpoint(endpoint)
            async with httpx.AsyncClient(
                timeout=1,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get(
                    url + "/v1/status", headers={"Authorization": "Bearer " + credential}
                )
                return response.status_code == 200
        except (httpx.HTTPError, InvalidResponse):
            return False

    async def request(self, endpoint: str, operation: str, payload: dict[str, object]) -> object:
        if operation not in {"register", "renew", "status", "unregister"}:
            raise InvalidResponse()
        url, credential = AppRuntime._endpoint(endpoint)
        try:
            async with httpx.AsyncClient(
                timeout=10,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "POST",
                    f"{url}/v1/ad-hoc/{operation}",
                    json=payload,
                    headers={"Authorization": "Bearer " + credential},
                ) as response:
                    data = bytearray()
                    async for chunk in response.aiter_raw():
                        data.extend(chunk)
                        if len(data) > 64 << 10:
                            raise InvalidResponse()
                    if response.status_code == 204:
                        if data:
                            raise InvalidResponse()
                        return None
                    if (
                        response.headers.get("content-type", "").split(";", 1)[0]
                        != "application/json"
                    ):
                        raise InvalidResponse()
                    value: object = json.loads(data)
                    if response.status_code == 200:
                        return value
                    if not isinstance(value, dict) or set(value) != {"code", "message"}:
                        raise InvalidResponse()
                    code = value["code"]
                    if code == "runtime.registration_stale":
                        raise RegistrationLost()
                    if code == "runtime.credential_rejected":
                        raise TnlError(
                            "sdk.credential_rejected", "the ad-hoc credential was rejected"
                        )
                    if code == "runtime.owner_conflict":
                        raise TnlError(
                            "sdk.owner_conflict", "another live app owns this invocation"
                        )
                    raise TnlError(
                        "sdk.request_rejected", "the local publisher rejected the request"
                    )
        except httpx.HTTPError as cause:
            raise NativeUnavailable() from cause
        except (ValueError, UnicodeDecodeError) as cause:
            raise InvalidResponse() from cause
