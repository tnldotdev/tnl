"""explicit sources shared by publication and environment clients."""

from __future__ import annotations

import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from ._identity_models import IdentitySourceSelection
from ._identity_validation import is_source
from ._protocol import TnlError


def _invalid() -> TnlError:
    return TnlError("sdk.configuration_invalid", "select one explicit identity source")


@dataclass(frozen=True, slots=True, repr=False)
class OIDCAssertion:
    token: str
    expires_at: datetime

    def __post_init__(self) -> None:
        now = datetime.now(UTC)
        if (
            not isinstance(self.token, str)
            or not self.token
            or len(self.token) > 32768
            or re.search(r"\s|\0", self.token)
            or not isinstance(self.expires_at, datetime)
            or self.expires_at.tzinfo is None
            or not now + timedelta(seconds=5) < self.expires_at <= now + timedelta(hours=12)
        ):
            raise _invalid()


@dataclass(frozen=True, slots=True)
class NativeAcquisition:
    method: Literal["token-file", "token-env", "github-actions", "vercel-oidc", "fly-machine-api", "google-metadata"]
    token_file: str = ""
    token_env: str = ""
    audience: str = ""

    def _capture(self) -> tuple[dict[str, object], dict[str, object]]:
        hints: dict[str, object] = {"method": self.method}
        environment: dict[str, object] = {}
        if self.method == "token-file":
            if not self.token_file or len(self.token_file) > 4096 or re.search(r"[\0\r\n]", self.token_file) or self.token_env or self.audience:
                raise _invalid()
            hints["token_file"] = str(Path(self.token_file).absolute())
        elif self.method == "token-env":
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", self.token_env) or self.token_file or self.audience:
                raise _invalid()
            hints["token_env"] = self.token_env
            environment = {"token_env": self.token_env, "token_value": os.environ.get(self.token_env, "")}
        elif self.method in {"github-actions", "fly-machine-api", "google-metadata"}:
            if not self.audience or len(self.audience) > 1024 or self.audience.strip() != self.audience or re.search(r"[*?\[\]\0\r\n\t]", self.audience) or self.token_file or self.token_env:
                raise _invalid()
            hints["audience"] = self.audience
            if self.method == "github-actions":
                environment = {"github_actions": os.environ.get("GITHUB_ACTIONS", ""), "github_request_url": os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""), "github_request_token": os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")}
        elif self.method == "vercel-oidc":
            if self.token_file or self.token_env or self.audience:
                raise _invalid()
            environment = {"vercel_token_file": os.environ.get("VERCEL_OIDC_TOKEN_FILE", ""), "vercel_token": os.environ.get("VERCEL_OIDC_TOKEN", "")}
        else:
            raise _invalid()
        return hints, environment


@dataclass(frozen=True, slots=True, repr=False)
class IdentitySource:
    kind: Literal["oidc"]
    machine_id: str
    assertion: Callable[[], Awaitable[OIDCAssertion]] | None = None
    acquisition: NativeAcquisition | None = None
    permission_id: str | None = None

    def __post_init__(self) -> None:
        if not is_source({"kind": self.kind, "machine_id": self.machine_id}) or (self.assertion is None) == (self.acquisition is None):
            raise _invalid()
        if self.assertion is not None and not callable(self.assertion) or self.acquisition is not None and not isinstance(self.acquisition, NativeAcquisition):
            raise _invalid()
        if self.permission_id is not None and not re.fullmatch(r"mwp_[A-Za-z0-9]{22}", self.permission_id):
            raise _invalid()

    def _selector(self) -> IdentitySourceSelection:
        source: IdentitySourceSelection = {"kind": self.kind, "machine_id": self.machine_id}
        return source

    def _startup(self) -> dict[str, object]:
        value: dict[str, object] = {"source": self._selector()}
        if self.acquisition is not None:
            acquisition, environment = self.acquisition._capture()
            value.update(acquisition=acquisition, source_environment=environment)
        return value
