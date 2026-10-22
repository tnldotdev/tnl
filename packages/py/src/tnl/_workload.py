"""runtime assertion acquisition; only native/control establish workload identity."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ._protocol import TnlError, service_name

type TokenSource = Callable[[], str | Awaitable[str]]
_configuration: tuple[str, TokenSource | None, str | None] | None = None


def configure_workload(
    name: str, *, token: TokenSource | None = None, token_file: str | None = None
) -> None:
    """install a request-scoped token source once in server setup."""
    global _configuration
    service_name(name)
    if (token is None) == (token_file is None):
        raise TnlError("sdk.workload_required", "select exactly one workload token source")
    selected = (name, token, token_file)
    if _configuration is not None and _configuration != selected:
        raise TnlError("sdk.workload_required", "the workload token source is already configured")
    _configuration = selected


def uses_workload() -> bool:
    return os.environ.get("TNL_CONNECTION_HANDLE") is None and (
        _configuration is not None
        or "TNL_WORKLOAD" in os.environ
        or os.environ.get("VERCEL") == "1"
        or bool(os.environ.get("FLY_APP_NAME"))
        or os.environ.get("GITHUB_ACTIONS") == "true"
    )


def _bounded_file(file: Path, maximum: int, *, owned: bool = False) -> str:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | (os.O_NOFOLLOW if owned else 0)
    with os.fdopen(os.open(file, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("not a regular file")
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("file exceeds bound")
    return value.decode("utf-8")


@dataclass(frozen=True, repr=False)
class Selection:
    name: str
    manifest: str
    assertion: str
    policy: str = ""


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(
        self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str
    ) -> None:
        return None


def _github_assertion(audience: str) -> str:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("not an Actions runtime")
    url = urlsplit(os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""))
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.fragment
        or not bearer
        or len(bearer) > 32768
        or any(c.isspace() for c in bearer)
    ):
        raise ValueError("invalid Actions assertion source")
    query = dict(parse_qsl(url.query))
    query["audience"] = audience
    endpoint = urlunsplit((url.scheme, url.netloc, url.path, urlencode(query), ""))
    request = Request(endpoint, headers={"Authorization": "Bearer " + bearer})
    with build_opener(_NoRedirects()).open(request, timeout=10) as response:
        data = response.read((40 << 10) + 1)
    if len(data) > 40 << 10:
        raise ValueError("assertion response exceeds bound")
    payload: object = json.loads(data)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"value"}
        or not isinstance(payload["value"], str)
    ):
        raise ValueError("invalid Actions assertion response")
    return payload["value"]


async def select_workload(directory: str, service: str) -> Selection:
    """read only the generated manifest, never Git or project configuration."""
    try:
        file = Path(directory) / ".tnl/generated/workloads.json"
        if file.resolve(strict=True) != file:
            raise ValueError("manifest is not a direct file")
        manifest_text = _bounded_file(file, 128 << 10, owned=True)
        manifest: object = json.loads(manifest_text)
        if not isinstance(manifest, dict) or manifest.get("schema") != 1:
            raise ValueError("invalid manifest")
        workloads = manifest.get("workloads")
        if not isinstance(workloads, dict):
            raise ValueError("invalid workloads")
        providers = [
            p
            for p, present in (
                ("vercel", os.environ.get("VERCEL") == "1"),
                ("fly", bool(os.environ.get("FLY_APP_NAME"))),
                ("github", os.environ.get("GITHUB_ACTIONS") == "true"),
            )
            if present
        ]
        name = os.environ.get("TNL_WORKLOAD") or (_configuration[0] if _configuration else None)
        if name is None:
            candidates = [
                k
                for k, w in workloads.items()
                if isinstance(w, dict) and providers == [w.get("provider")]
            ]
            if len(candidates) != 1:
                raise ValueError("select one workload")
            name = candidates[0]
        if not isinstance(name, str) or _configuration and _configuration[0] != name:
            raise ValueError("invalid workload selection")
        service_name(name)
        selected = workloads.get(name)
        if not isinstance(selected, dict) or service not in selected.get("services", []):
            raise ValueError("service is not selected")
        acquisition = selected.get("acquisition")
        if not isinstance(acquisition, dict):
            raise ValueError("invalid assertion source")
        raw: object
        if _configuration is not None:
            if acquisition.get("method") not in {"callback", "github-actions"}:
                raise ValueError("invalid assertion source")
            _, source, token_file = _configuration
            if source is not None:
                result = source()
                raw = await result if inspect.isawaitable(result) else result
            else:
                assert token_file is not None
                raw = _bounded_file(Path(directory) / token_file, 32768)
        elif acquisition.get("method") == "token-file":
            token_file = acquisition.get("token_file")
            if not isinstance(token_file, str):
                raise ValueError("missing token file")
            raw = _bounded_file(Path(directory) / token_file, 32768)
        elif acquisition.get("method") == "vercel-oidc":
            token_file = os.environ.get("VERCEL_OIDC_TOKEN_FILE")
            raw = (
                _bounded_file(Path(directory) / token_file, 32768)
                if token_file
                else os.environ.get("VERCEL_OIDC_TOKEN")
            )
        elif acquisition.get("method") == "github-actions":
            audience = acquisition.get("audience")
            if not isinstance(audience, str):
                raise ValueError("missing Actions audience")
            raw = await asyncio.to_thread(_github_assertion, audience)
        else:
            # native acquisition implements Fly's Unix socket and GitHub's
            # runtime token endpoint without Python-specific HTTP credentials.
            raw = ""
        if not isinstance(raw, str):
            raise ValueError("missing assertion")
        assertion = raw.strip()
        if (
            len(assertion.encode()) > 32768
            or "\0" in assertion
            or any(c.isspace() for c in assertion)
        ):
            raise ValueError("invalid assertion")
        return Selection(
            name, str(file), assertion, hashlib.sha256(manifest_text.encode()).hexdigest()
        )
    except Exception:
        pass
    # raise outside the handler so callback secrets are absent even from the
    # exception's programmatically inspectable context chain.
    raise TnlError(
        "sdk.workload_assertion_unavailable", "workload assertion acquisition failed"
    ) from None
