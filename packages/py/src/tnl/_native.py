"""discover and call the native publisher's private scoped HTTP endpoint."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

import httpx

from ._protocol import (
    Endpoint,
    InvalidResponse,
    NativeUnavailable,
    RegistrationLost,
    TnlError,
    parse_endpoint,
)


def native_binary() -> Path:
    binary = Path(__file__).parent / "bin" / "tnl"
    if not binary.is_file():
        raise TnlError("sdk.native_missing", "install a platform wheel containing the tnl binary")
    return binary


def _read_endpoint(file: str, service: str | None, invocation_id: str | None) -> Endpoint:
    path = Path(file)
    if not path.is_absolute():
        raise InvalidResponse()
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o077 or parent.st_uid != os.getuid():
        raise InvalidResponse()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.getuid()
            or info.st_size > 64 << 10
        ):
            raise InvalidResponse()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read((64 << 10) + 1)
        if len(data) > 64 << 10:
            raise InvalidResponse()
        return parse_endpoint(json.loads(data), service=service, invocation_id=invocation_id)
    finally:
        os.close(descriptor)


class NativeRuntime:
    async def start(
        self,
        directory: str,
        *,
        service: str | None = None,
        invocation_id: str | None = None,
        state_dir: str | None = None,
    ) -> Endpoint:
        try:
            mounted = os.environ.get("TNL_APP_ENDPOINT")
            if mounted is not None:
                # an app can start before its publisher writes the scoped
                # descriptor. only absence is retried; an unsafe or
                # malformed descriptor and an unreachable owner fail closed.
                deadline = asyncio.get_running_loop().time() + 30
                while True:
                    try:
                        endpoint = await asyncio.to_thread(
                            _read_endpoint, mounted, service, invocation_id
                        )
                        await self.request(endpoint, "health")
                        return endpoint
                    except FileNotFoundError:
                        if asyncio.get_running_loop().time() >= deadline:
                            raise NativeUnavailable() from None
                        await asyncio.sleep(0.2)
            else:
                args = [
                    str(native_binary()),
                    "--no-telemetry",
                    "runtime",
                    "endpoint",
                    "--directory",
                    directory,
                ]
                selected_state = (
                    state_dir if state_dir is not None else os.environ.get("TNL_STATE_DIR")
                )
                if selected_state is not None:
                    args.extend(["--state-dir", selected_state])
                if service is not None:
                    args.extend(["--service", service])
                if invocation_id is not None:
                    args.extend(["--invocation-id", invocation_id])
                child = await asyncio.create_subprocess_exec(
                    *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
                )
                assert child.stdout is not None
                try:
                    data = bytearray()
                    async with asyncio.timeout(30):
                        while chunk := await child.stdout.read(8192):
                            data.extend(chunk)
                            if len(data) > 64 << 10:
                                raise InvalidResponse()
                        await child.wait()
                except BaseException:
                    if child.returncode is None:
                        child.kill()
                    await child.wait()
                    raise
                if child.returncode != 0:
                    raise NativeUnavailable()
                endpoint = parse_endpoint(
                    json.loads(data), service=service, invocation_id=invocation_id
                )
            await self.request(endpoint, "health")
            return endpoint
        except (OSError, TimeoutError):
            raise NativeUnavailable() from None
        except (ValueError, UnicodeDecodeError):
            raise InvalidResponse() from None

    async def request(
        self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
    ) -> object:
        if operation not in {
            "health",
            "prepare",
            "register",
            "renew",
            "unregister",
            "status",
            "ad-hoc/register",
        }:
            raise InvalidResponse()
        data = None if payload is None else json.dumps(payload).encode()
        get = operation in {"health", "status"}
        if get and data is not None or data is not None and len(data) > 64 << 10:
            raise InvalidResponse()
        headers = {
            "Host": endpoint.url.removeprefix("http://"),
            "Authorization": f"Bearer {endpoint.capability}",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        try:
            async with httpx.AsyncClient(
                timeout=75 if operation == "unregister" else 30,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    "GET" if get else "POST",
                    endpoint.url + "/v1/" + operation,
                    headers=headers,
                    content=data,
                ) as response:
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        body.extend(chunk)
                        if len(body) > 64 << 10:
                            raise InvalidResponse()
                    if (
                        response.status_code == 401
                        and response.headers.get("content-type", "").split(";", 1)[0]
                        != "application/json"
                    ):
                        raise RegistrationLost()
                    if response.status_code == 204:
                        if body or operation in {"prepare", "status", "ad-hoc/register"}:
                            raise InvalidResponse()
                        return None
                    if (
                        response.headers.get("content-type", "").split(";", 1)[0]
                        != "application/json"
                    ):
                        raise InvalidResponse()
                    value: object = json.loads(body)
                    if response.status_code == 200:
                        if operation not in {"prepare", "status", "ad-hoc/register"}:
                            raise InvalidResponse()
                        return value
                    if (
                        not isinstance(value, dict)
                        or set(value) != {"code", "message"}
                        or not isinstance(value["code"], str)
                        or not isinstance(value["message"], str)
                    ):
                        raise InvalidResponse()
                    if value["code"] in {"runtime.registration_stale", "runtime.unauthorized"}:
                        raise RegistrationLost()
                    code = {
                        "runtime.owner_conflict": "sdk.owner_conflict",
                        "runtime.authentication_required": "sdk.authentication_required",
                        "runtime.publisher_setup_required": "sdk.publisher_setup_required",
                        "runtime.publisher_file_invalid": "sdk.publisher_file_invalid",
                    }.get(value["code"], "sdk.request_rejected")
                    if response.status_code >= 500 and code == "sdk.request_rejected":
                        raise NativeUnavailable()
                    message = {
                        "sdk.publisher_setup_required": (
                            "no namespace publisher is set up; run tnl publisher setup"
                            " --namespace, then try again"
                        ),
                        "sdk.publisher_file_invalid": (
                            "the selected publisher file is invalid; check the file"
                            " and its permissions"
                        ),
                    }.get(code, "the local publisher rejected the request")
                    raise TnlError(code, message)
        except httpx.HTTPError:
            raise NativeUnavailable() from None
        except (ValueError, UnicodeDecodeError):
            raise InvalidResponse() from None
