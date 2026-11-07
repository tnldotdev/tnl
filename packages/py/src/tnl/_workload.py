"""request-context callbacks over native workload selection and acquisition."""

from __future__ import annotations

import asyncio
import inspect
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

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
        or bool(os.environ.get("K_SERVICE"))
        or os.environ.get("GITHUB_ACTIONS") == "true"
    )


@dataclass(frozen=True, repr=False)
class Selection:
    name: str
    policy: str
    request: dict[str, object]
    environment: dict[str, str]
    assertion: str | None

    def private_input(self) -> dict[str, object]:
        return {
            "sdk_workload": self.request,
            "sdk_workload_policy": self.policy,
            "sdk_environment": self.environment,
            **({"assertion": self.assertion} if self.assertion is not None else {}),
        }


async def select_workload(
    service: str, preview: Callable[[str, dict[str, object]], object]
) -> Selection:
    configuration = _configuration
    request: dict[str, object] = {
        "runtime": {
            **({"workload": os.environ["TNL_WORKLOAD"]} if "TNL_WORKLOAD" in os.environ else {}),
            "vercel": os.environ.get("VERCEL", ""),
            "fly_app_name": os.environ.get("FLY_APP_NAME", ""),
            "github_actions": os.environ.get("GITHUB_ACTIONS", ""),
            "cloud_run_service": os.environ.get("K_SERVICE", ""),
        }
    }
    if configuration is not None:
        name, callback, token_file = configuration
        request.update({"name": name, "callback": callback is not None})
        if token_file is not None:
            request["token_file"] = token_file
    raw = await asyncio.to_thread(preview, service, request)
    if (
        not isinstance(raw, dict)
        or set(raw) - {"token_env"}
        != {"schema", "name", "directory", "manifest", "policy", "source"}
        or type(raw["schema"]) is not int
        or raw["schema"] != 1
        or not all(
            isinstance(raw[k], str) for k in ("name", "directory", "manifest", "policy", "source")
        )
        or not re.fullmatch(r"[0-9a-f]{64}", raw["policy"])
        or raw["source"] not in {"callback", "vercel", "native"}
    ):
        raise TnlError("sdk.connection_invalid", "the native workload selection is invalid")
    name, policy = str(raw["name"]), str(raw["policy"])
    token_env = raw.get("token_env")
    if token_env is not None and (
        not isinstance(token_env, str)
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", token_env)
    ):
        raise TnlError("sdk.connection_invalid", "the native workload token source is invalid")
    service_name(name)
    assertion = None
    if raw["source"] == "callback":
        assertion = await _callback(name, configuration)
    return Selection(
        name,
        policy,
        request,
        {
            "github_actions": os.environ.get("GITHUB_ACTIONS", ""),
            "github_request_url": os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""),
            "github_request_token": os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", ""),
            "vercel_token_file": os.environ.get("VERCEL_OIDC_TOKEN_FILE", ""),
            "vercel_token": os.environ.get("VERCEL_OIDC_TOKEN", ""),
            **(
                {"token_env": token_env, "token_value": os.environ.get(token_env, "")}
                if isinstance(token_env, str)
                else {}
            ),
        },
        assertion,
    )


async def _callback(
    name: str, configuration: tuple[str, TokenSource | None, str | None] | None
) -> str:
    try:
        if configuration is None or configuration[0] != name or configuration[1] is None:
            raise ValueError("missing callback")
        async with asyncio.timeout(10):
            value = configuration[1]()
            raw = await value if inspect.isawaitable(value) else value
        if not isinstance(raw, str):
            raise ValueError("missing assertion")
        assertion = raw.strip().strip("\ufeff").strip()
        if (
            not assertion
            or len(assertion.encode()) > 32768
            or "\0" in assertion
            or "\ufeff" in assertion
            or any(c.isspace() for c in assertion)
        ):
            raise ValueError("invalid assertion")
        return assertion
    except Exception:
        pass
    # raise outside the handler so callback secrets stay out of context chains.
    raise TnlError(
        "sdk.workload_assertion_unavailable", "workload assertion acquisition failed"
    ) from None
