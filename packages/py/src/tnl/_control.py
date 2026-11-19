"""explicit HTTP control client; never starts the native runtime."""

import asyncio
import json
import re
from dataclasses import dataclass, field

import httpx

from ._management.operations_gen import OPERATIONS
from ._management_client import Deployments, Publishers, _invalid_management, _management_problem
from ._protocol import TnlError
from ._publisher import _valid_control_url

_default_origin = "https://control.tnl.dev"
_max_body = 2 << 20
_operations = {
    "deployments.create": "createDeployment",
    "deployments.list": "listDeployments",
    "deployments.get": "getDeployment",
    "deployments.update": "updateDeployment",
    "deployments.delete": "deleteDeployment",
    "publishers.create_enrollment": "createDeploymentPublisherEnrollment",
    "publishers.list": "listDeploymentPublishers",
    "publishers.get": "getDeploymentPublisher",
    "publishers.revoke": "revokeDeploymentPublisher",
}


@dataclass(frozen=True, slots=True, repr=False)
class _ProjectAPI:
    base_url: str
    team_id: str
    project_key: str
    auth: str | None = field(repr=False)

    async def request(self, operation: str, **inputs: object) -> dict[str, object]:
        if self.auth is None:
            raise TnlError("sdk.authentication_required", "supply an explicit control bearer token")
        method, path, status = OPERATIONS[_operations[operation]]
        parameters: dict[str, object] = {"project_key": self.project_key, **inputs}
        for name in ("project_key", "deployment", "publisher"):
            slot = "{" + name + "}"
            if slot not in path:
                continue
            value = parameters[name]
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= 128
                or value in (".", "..")
                or not re.fullmatch(r"[A-Za-z0-9._~-]+", value)
            ):
                raise TnlError("sdk.configuration_invalid", "select an exact control identifier")
            path = path.replace(slot, value)
        headers = {
            "Authorization": "Bearer " + self.auth,
            "Accept": "application/json, application/problem+json",
            "Accept-Encoding": "identity",
        }
        for key, header in (("idempotency_key", "Idempotency-Key"), ("if_match", "If-Match")):
            if key in inputs:
                value = inputs[key]
                if not isinstance(value, str) or not re.fullmatch(r"[!-~]{1,128}", value):
                    raise TnlError(
                        "sdk.configuration_invalid", "invalid conditional request header"
                    )
                headers[header] = value
        query = {"team_id": self.team_id}
        if inputs.get("after"):
            query["after"] = str(inputs["after"])
        if "limit" in inputs:
            query["limit"] = str(inputs["limit"])
        try:
            async with (
                asyncio.timeout(30),
                httpx.AsyncClient(timeout=30, trust_env=False, follow_redirects=False) as transport,
            ):
                async with transport.stream(
                    method,
                    self.base_url + path,
                    params=query,
                    headers=headers,
                    json=inputs.get("body"),
                ) as response:
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise _invalid_management()
                    failed = 400 <= response.status_code <= 599
                    if not failed and response.status_code != status:
                        raise _invalid_management()
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > _max_body:
                            raise _invalid_management()
                        body.extend(chunk)
                    if not failed and status == 204:
                        if body:
                            raise _invalid_management()
                        return {"schema": 1}
                    media_type = response.headers.get("content-type", "").split(";", 1)[0]
                    if media_type.strip().lower() != (
                        "application/problem+json" if failed else "application/json"
                    ):
                        raise _invalid_management()
                    data: object = json.loads(body)
                    if failed:
                        raise _management_problem(response.status_code, data)
                    result: dict[str, object] = {"schema": 1, "data": data}
                    if "etag" in response.headers:
                        result["etag"] = response.headers["etag"]
                    return result
        except (ValueError, RecursionError):
            raise _invalid_management() from None
        except (httpx.HTTPError, TimeoutError):
            raise TnlError("sdk.dev_unavailable", "the control API is unavailable") from None


@dataclass(frozen=True, slots=True)
class ControlProject:
    deployments: Deployments
    publishers: Publishers


@dataclass(frozen=True, slots=True, repr=False)
class Control:
    base_url: str
    _auth: str | None = field(repr=False)

    def project(self, project_key: str, *, team_id: str) -> ControlProject:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", team_id):
            raise TnlError("sdk.configuration_invalid", "select a control team ID")
        api = _ProjectAPI(self.base_url, team_id, project_key, self._auth)
        return ControlProject(Deployments(api), Publishers(api))


def control(*, auth: str | None = None, base_url: str = _default_origin) -> Control:
    """select a control origin and an explicit bearer token."""
    if (
        not isinstance(base_url, str)
        or not re.fullmatch(r"https?://[a-z0-9.\[\]:-]+", base_url)
        or not _valid_control_url(base_url)
        or auth is not None
        and (not isinstance(auth, str) or not re.fullmatch(r"[!-~]{1,8192}", auth))
    ):
        raise TnlError(
            "sdk.configuration_invalid", "select a valid control origin and bearer token"
        )
    return Control(base_url, auth)
