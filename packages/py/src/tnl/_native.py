"""launch and call the app-owned tnl publisher over bounded loopback TCP."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import httpx

from ._protocol import InvalidResponse, NativeUnavailable, RegistrationLost, TnlError


class NativeRuntime:
    async def start(self, directory: str, service: str | None = None) -> str:
        binary = Path(__file__).parent / "bin" / "tnl"
        if not binary.is_file():
            raise TnlError(
                "sdk.native_missing", "install a platform wheel containing the tnl binary"
            )
        try:
            address = await asyncio.create_subprocess_exec(
                str(binary),
                "runtime",
                "endpoint",
                "--directory",
                directory,
                *(["--ad-hoc"] if service is None else ["--app", "--service", service]),
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
                or set(result) != {"version", "path", "spawn"}
                or result["version"] != 1
                or not isinstance(result["spawn"], bool)
                or not isinstance(result["path"], str)
                or not Path(result["path"]).is_absolute()
                or not result["path"].endswith(".endpoint.json")
                or "\0" in result["path"]
            ):
                raise InvalidResponse()
            endpoint_path = cast(str, result["path"])
            if not await self.healthy(endpoint_path):
                if not result["spawn"]:
                    raise NativeUnavailable()
                await asyncio.create_subprocess_exec(
                    str(binary),
                    "runtime",
                    "serve",
                    "--directory",
                    directory,
                    cwd=directory,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                deadline = asyncio.get_running_loop().time() + 15
                while not await self.healthy(endpoint_path):
                    if asyncio.get_running_loop().time() >= deadline:
                        raise NativeUnavailable()
                    await asyncio.sleep(0.05)
            return endpoint_path
        except (OSError, TimeoutError, ValueError) as cause:
            raise NativeUnavailable() from cause

    @staticmethod
    def _endpoint(path: str) -> tuple[str, str]:
        try:
            with Path(path).open("rb") as file:
                payload = file.read(4097)
        except OSError:
            raise InvalidResponse() from None
        if len(payload) > 4096:
            raise InvalidResponse()
        try:
            value: object = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            value = None
        if not isinstance(value, dict) or set(value) != {"version", "url", "credential"}:
            raise InvalidResponse()
        url = value["url"]
        credential = value["credential"]
        if (
            value["version"] != 1
            or not isinstance(url, str)
            or not isinstance(credential, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{43}", credential) is None
        ):
            raise InvalidResponse()
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError:
            raise InvalidResponse() from None
        if (
            (parsed.scheme != "https" and parsed.scheme != "http")
            or parsed.scheme == "http"
            and (
                parsed.hostname != "127.0.0.1"
                or port is None
                or parsed.netloc != f"127.0.0.1:{port}"
            )
            or parsed.scheme == "https"
            and (
                parsed.hostname is None
                or parsed.username is not None
                or parsed.password is not None
            )
            or parsed.path != ""
            or parsed.query != ""
            or parsed.fragment != ""
        ):
            raise InvalidResponse()
        return url, credential

    async def healthy(self, endpoint_path: str) -> bool:
        try:
            url, credential = self._endpoint(endpoint_path)
            async with httpx.AsyncClient(
                timeout=1, follow_redirects=False, trust_env=False
            ) as client:
                response = await client.get(
                    url + "/v1/status", headers={"Authorization": "Bearer " + credential}
                )
                return response.status_code == 200
        except (httpx.HTTPError, InvalidResponse):
            return False

    async def request(
        self, endpoint_path: str, operation: str, payload: dict[str, object]
    ) -> object:
        if operation not in {"register", "renew", "status", "unregister"}:
            raise InvalidResponse()
        return await self._request(endpoint_path, f"/v1/ad-hoc/{operation}", payload)

    async def app_request(
        self, endpoint_path: str, operation: str, payload: dict[str, object]
    ) -> object:
        if operation not in {"prepare", "register", "renew", "unregister"}:
            raise InvalidResponse()
        return await self._request(endpoint_path, f"/v1/{operation}", payload)

    async def _request(self, endpoint_path: str, route: str, payload: dict[str, object]) -> object:
        try:
            url, credential = self._endpoint(endpoint_path)
            async with httpx.AsyncClient(
                timeout=45 if route.endswith("/unregister") else 10,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "POST",
                    url + route,
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
                        raise TnlError("sdk.owner_conflict", "another live app owns this service")
                    if code == "runtime.authentication_required":
                        raise TnlError(
                            "sdk.authentication_required",
                            "the local publisher rejected this local credential",
                        )
                    raise TnlError(
                        "sdk.request_rejected", "the local publisher rejected the request"
                    )
        except httpx.HTTPError as cause:
            raise NativeUnavailable() from cause
        except (ValueError, UnicodeDecodeError) as cause:
            raise InvalidResponse() from cause
