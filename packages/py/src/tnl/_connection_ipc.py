"""bounded async-worker IPC to a private connector connection capability."""

from __future__ import annotations

import http.client
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from ._protocol import TnlError


def _failure() -> TnlError:
    return TnlError("sdk.connection_unavailable", "the connector owner is unavailable")


class OwnerIPC:
    key: str
    expires: datetime
    port: int

    def __init__(self, filename: str) -> None:
        self.creator_pid = os.getpid()
        self.connection: http.client.HTTPConnection | None = None
        self.closed = False
        try:
            file = Path(filename)
            if not file.is_absolute() or "\0" in filename or len(filename) > 4096:
                raise ValueError("invalid handle path")
            for directory in (file.parent, *file.parent.parents):
                info = directory.lstat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_mode & 0o022
                    and not info.st_mode & stat.S_ISVTX
                ):
                    raise ValueError("unsafe ancestor")
                if directory == file.parent and (
                    stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()
                ):
                    raise ValueError("unowned directory")
            with os.fdopen(
                os.open(file, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb"
            ) as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid()
                    or info.st_size > 128 << 10
                ):
                    raise ValueError("unowned handle")
                data = stream.read((128 << 10) + 1)
            if len(data) > 128 << 10:
                raise ValueError("oversized handle")
            raw: object = json.loads(data)
            if not isinstance(raw, dict) or set(raw) - {
                "schema",
                "url",
                "key",
                "directory",
                "config_digest",
                "expires_at",
                "executable",
                "workload",
                "team_id",
            }:
                raise ValueError("invalid handle")
            url, key, scope_directory, digest, expiry = (
                raw.get(k) for k in ("url", "key", "directory", "config_digest", "expires_at")
            )
            if (
                raw.get("schema") != 1
                or not isinstance(url, str)
                or not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", url)
                or not isinstance(key, str)
                or not re.fullmatch(r"[0-9a-f]{64}", key)
                or not isinstance(scope_directory, str)
                or not Path(scope_directory).is_absolute()
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not isinstance(expiry, str)
            ):
                raise ValueError("invalid handle scope")
            endpoint = urlsplit(url)
            if endpoint.port is None or not 1 <= endpoint.port <= 65535:
                raise ValueError("invalid local port")
            self.expires = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if self.expires.tzinfo is None or self.expires <= datetime.now(UTC):
                raise ValueError("expired capability")
            self.key = key
            self.port = endpoint.port
            self.scope: dict[str, object] = {
                "schema": 1,
                "directory": scope_directory,
                "config_digest": digest,
            }
            self.connection = http.client.HTTPConnection("127.0.0.1", endpoint.port, timeout=35)
            return
        except Exception:
            self.close()
        raise _failure() from None

    def __repr__(self) -> str:
        return "<tnl native IPC (private)>"

    def prepare(self, service: str, assertion: str | None = None) -> object:
        if self.creator_pid != os.getpid():
            self.discard_inherited()
            raise _failure()
        try:
            if self.closed or self.expires <= datetime.now(UTC):
                raise ValueError("closed capability")
            if self.connection is None:
                self.connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=35)
            body: dict[str, object] = {**self.scope, "service": service}
            if assertion == "":
                body["acquire_assertion"] = True
            elif assertion is not None:
                body["assertion"] = assertion
            encoded = json.dumps(body).encode()
            self.connection.request(
                "POST",
                "/v1/connections/prepare",
                encoded,
                {"Authorization": "Bearer " + self.key, "Content-Type": "application/json"},
            )
            response = self.connection.getresponse()
            data = response.read((128 << 10) + 1)
            if (
                len(data) > 128 << 10
                or response.status != 200
                or response.getheader("Content-Type", "").split(";")[0] != "application/json"
            ):
                raise ValueError("invalid owner response")
            result: object = json.loads(data)
            return result
        except Exception:
            if self.connection is not None:
                self.connection.close()
                self.connection = None
        raise _failure() from None

    def close(self) -> None:
        if self.creator_pid != os.getpid():
            self.discard_inherited()
            return
        self.closed = True
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def discard_inherited(self) -> None:
        # HTTPConnection.close can acquire an inherited buffered-reader lock
        # during a response. detach only this child's socket, without shutdown
        # or touching a response another parent thread may have been reading.
        if self.creator_pid == os.getpid():
            return
        self.closed = True
        if self.connection is not None and self.connection.sock is not None:
            descriptor = self.connection.sock.detach()
            if descriptor >= 0:
                os.close(descriptor)
