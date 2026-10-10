"""bounded private socket shapes shared with the native runtime."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import urlsplit


class TnlError(Exception):
    """an authored failure from the Python binding or native publisher."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CredentialRequired(TnlError):
    def __init__(self) -> None:
        super().__init__(
            "sdk.credential_required", "set TNL_CREDENTIAL or pass an ad-hoc credential"
        )


class RegistrationLost(TnlError):
    def __init__(self) -> None:
        super().__init__("sdk.registration_stale", "the app-owned tnl registration was lost")


class NativeUnavailable(TnlError):
    def __init__(self) -> None:
        super().__init__("sdk.dev_unavailable", "the local tnl publisher is unavailable")


class InvalidResponse(TnlError):
    def __init__(self) -> None:
        super().__init__(
            "sdk.response_invalid", "the local tnl publisher returned an invalid response"
        )


State = Literal["starting", "publishing", "routable", "draining", "stopped", "failed"]


@dataclass(frozen=True, slots=True)
class Status:
    registration_id: str
    state: State
    public_url_id: str | None = None
    public_url: str | None = None
    publish_run_number: int | None = None
    failure_code: str | None = None


_states: set[str] = {"starting", "publishing", "routable", "draining", "stopped", "failed"}
_label = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_id = re.compile(r"url_[A-Za-z0-9_-]{1,128}")
_code = re.compile(r"[A-Za-z0-9_.-]{1,128}")


def parse_status(value: object, registration_id: str) -> Status:
    if not isinstance(value, dict) or set(value) - {
        "protocol",
        "registration_id",
        "state",
        "public_url_id",
        "public_url",
        "publish_run_number",
        "failure_code",
    }:
        raise InvalidResponse()
    if value.get("protocol") != 1 or value.get("registration_id") != registration_id:
        raise InvalidResponse()
    state: object = value.get("state")
    if not isinstance(state, str) or state not in _states:
        raise InvalidResponse()
    public_url_id: object = value.get("public_url_id")
    if public_url_id is not None and (
        not isinstance(public_url_id, str) or _id.fullmatch(public_url_id) is None
    ):
        raise InvalidResponse()
    public_url: object = value.get("public_url")
    if public_url is not None:
        if not isinstance(public_url, str):
            raise InvalidResponse()
        try:
            parts = urlsplit(public_url)
        except ValueError as cause:
            raise InvalidResponse() from cause
        if (
            parts.scheme != "https"
            or not parts.hostname
            or parts.hostname != parts.netloc
            or parts.path
            or parts.query
            or parts.fragment
            or parts.username
            or len(parts.hostname) > 253
            or any(
                len(label) > 63 or _label.fullmatch(label) is None
                for label in parts.hostname.split(".")
            )
        ):
            raise InvalidResponse()
    publish_run_number: object = value.get("publish_run_number")
    if publish_run_number is not None and (
        type(publish_run_number) is not int
        or publish_run_number < 1
        or publish_run_number > 2**53 - 1
    ):
        raise InvalidResponse()
    failure_code: object = value.get("failure_code")
    if failure_code is not None and (
        not isinstance(failure_code, str) or _code.fullmatch(failure_code) is None
    ):
        raise InvalidResponse()
    if state == "routable" and (
        public_url_id is None or public_url is None or publish_run_number is None
    ):
        raise InvalidResponse()
    return Status(
        registration_id=registration_id,
        state=cast(State, state),
        public_url_id=public_url_id,
        public_url=public_url,
        publish_run_number=publish_run_number,
        failure_code=failure_code,
    )
