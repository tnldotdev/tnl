"""exact application visit-grant exchange, separate from ordinary-client bindings."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

import httpx

from ._credential import (
    ApplicationDocument,
    ApplicationGrant,
    dns_hostname,
    https_origin,
    json_object,
    opaque_id,
    timestamp,
    visitor_token,
)
from ._protocol import TnlError


def _error(code: str) -> TnlError:
    return TnlError(
        "sdk.credential_" + code,
        {
            "invalid": "the application credential is invalid",
            "denied": "the selected application grant is not authorized",
            "unavailable": "application credential acquisition failed; check control availability",
            "response_invalid": "control returned an invalid application credential response",
        }[code],
    )


def _object(
    value: object, required: set[str], optional: set[str] | None = None
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not required <= set(value) <= required | (
        optional or set()
    ):
        raise ValueError("response fields")
    return value


def _integer(value: object, minimum: int, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or maximum is not None and value > maximum:
        raise ValueError("response integer")
    return value


def _base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


@dataclass(frozen=True, slots=True, repr=False)
class Selection:
    key: tuple[str, str, str, str, str, int]
    url: str
    credential: str
    expires: float


class ApplicationHTTP:
    def __init__(self, document: ApplicationDocument, check: Callable[[], None]) -> None:
        self._document, self._check = document, check
        self._current: dict[str, Selection] = {}
        self._pending: dict[str, asyncio.Task[Selection]] = {}
        self._client: httpx.AsyncClient | None = None
        self._transport: httpx.AsyncHTTPTransport | None = None
        self._closed = False

    def __repr__(self) -> str:
        return "<tnl application HTTP authority (private)>"

    def _active(self) -> None:
        self._check()
        if self._closed:
            raise TnlError("sdk.client_closed", "the runtime instance is closed")

    def resource(self, resource: str) -> None:
        try:
            if not isinstance(resource, str):
                raise ValueError("resource")
            opaque_id(resource, "url_" if resource.startswith("url_") else "svc_")
            return
        except ValueError:
            pass
        raise _error("denied") from None

    async def resolve(self, resource: str) -> Selection:
        self._active()
        self.resource(resource)
        grant = self._document.visit(resource)
        cached = self._current.get(resource)
        if cached is not None and cached.expires - time.time() > 30:
            return cached
        pending = self._pending.get(resource)
        if pending is None:
            pending = asyncio.create_task(self._acquire(resource, grant))
            self._pending[resource] = pending

            def finished(task: asyncio.Task[Selection]) -> None:
                if self._pending.get(resource) is task:
                    del self._pending[resource]
                if not task.cancelled():
                    task.exception()

            pending.add_done_callback(finished)
        try:
            selected = await asyncio.shield(pending)
        except asyncio.CancelledError:
            self._active()
            raise
        self._active()
        return selected

    async def _json(self, path: str, body: object) -> object:
        self._active()
        if self._client is None:
            self._transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0)
            self._client = httpx.AsyncClient(transport=self._transport, trust_env=False, timeout=15)
        code = "response_invalid"
        try:
            async with asyncio.timeout(15):
                request = self._client.build_request(
                    "POST", self._document.control_url + path, json=body
                )
                request.headers.pop("cookie", None)
                request.headers["Accept-Encoding"] = "identity"
                response = await self._client.send(request, stream=True, follow_redirects=False)
                try:
                    if not 200 <= response.status_code < 300:
                        code = (
                            "denied"
                            if response.status_code in {401, 403, 404, 409, 410}
                            else "unavailable"
                            if response.status_code == 429 or response.status_code >= 500
                            else "response_invalid"
                        )
                        raise _error(code)
                    if response.headers.get("content-encoding", "identity") != "identity":
                        raise _error("response_invalid")
                    data = bytearray()
                    async for chunk in response.aiter_raw():
                        if len(data) + len(chunk) > 65536:
                            raise _error("response_invalid")
                        data.extend(chunk)
                    return json.loads(data.decode("utf-8"), object_pairs_hook=json_object)
                finally:
                    await response.aclose()
        except (httpx.HTTPError, TimeoutError):
            code = "unavailable"
        except TnlError as error:
            code = error.code.removeprefix("sdk.credential_")
        except Exception:
            pass
        raise _error(code) from None

    async def _acquire(self, resource: str, grant: ApplicationGrant) -> Selection:
        try:
            selected = await self._exchange(resource, grant)
            self._active()
            self._current[resource] = selected
            return selected
        except TnlError as error:
            if error.code.startswith("sdk.credential_") or error.code in {
                "sdk.client_closed",
                "sdk.protocol_unsupported",
                "sdk.client_context_invalid",
            }:
                raise
        except Exception:
            pass
        raise _error("response_invalid") from None

    async def _exchange(self, resource: str, grant: ApplicationGrant) -> Selection:
        document = self._document
        started = time.time()
        now = int(started)

        def encoded(value: object) -> str:
            return _base64(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())

        header = encoded({"alg": "EdDSA", "typ": "JWT", "kid": document.key_id})
        claims = encoded(
            {
                "iss": document.client_id,
                "sub": document.client_id,
                "aud": document.control_url + "/v1/publisher-token",
                "jti": _base64(secrets.token_bytes(24)),
                "grant_id": grant.id,
                "iat": now,
                "exp": now + 60,
            }
        )
        message = header + "." + claims
        signature = document.key.sign(message.encode())
        access = _object(
            await self._json(
                "/v1/publisher-token",
                {
                    "grant_type": "client_credentials",
                    "client_id": document.client_id,
                    "grant_id": grant.id,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": message + "." + _base64(signature),
                },
            ),
            {"access_token", "token_type", "expires_in", "grant_id"},
        )
        token = access["access_token"]
        if (
            not isinstance(token, str)
            or re.fullmatch(r"pta_[A-Za-z0-9_-]{43}", token) is None
            or access["token_type"] != "Bearer"
            or opaque_id(access["grant_id"], "pgrant_") != grant.id
        ):
            raise ValueError("access response")
        duration = _integer(access["expires_in"], 1, 300)
        kind = "public_url" if grant.kind == "saved_public_url" else "service"
        permission = _object(
            await self._json(
                "/v1/visitor-tokens",
                {
                    "resource": {"kind": kind, "id": resource},
                    "source": {"kind": "application", "credential": token},
                },
            ),
            {
                "resource",
                "hostname",
                "port",
                "visitor_token",
                "visitor_policy_revision",
                "expires_at",
            },
            {"service_trust_revision", "service_protocol", "service_endpoint"},
        )
        if permission["resource"] != {"kind": kind, "id": resource}:
            raise ValueError("resource binding")
        host = dns_hostname(permission["hostname"])
        port = _integer(permission["port"], 1, 65535)
        _integer(permission["visitor_policy_revision"], 1)
        credential = visitor_token(permission["visitor_token"])
        trust = 0
        if kind == "public_url":
            if port != 443 or {
                "service_protocol",
                "service_trust_revision",
                "service_endpoint",
            } & set(permission):
                raise ValueError("public URL response")
        else:
            trust = _integer(permission.get("service_trust_revision"), 1)
            endpoint = _object(permission.get("service_endpoint"), {"hostname", "port", "public"})
            if (
                dns_hostname(endpoint["hostname"]) != host
                or _integer(endpoint["port"], 1024, 65535) != port
                or type(endpoint["public"]) is not bool
            ):
                raise ValueError("service endpoint binding")
            protocol = permission.get("service_protocol")
            if protocol not in {"http", "tcp", "mysql", "postgres", "kubernetes"}:
                raise ValueError("service protocol")
            if protocol != "http":
                raise TnlError(
                    "sdk.protocol_unsupported", "this application resource needs another transport"
                )
            if not endpoint["public"]:
                raise _error("denied")
        url = "https://" + host + ("" if port == 443 else ":" + str(port))
        https_origin(url)
        expires = min(timestamp(permission["expires_at"]), started + duration, grant.expires)
        if expires <= time.time():
            raise _error("denied")
        return Selection(
            (document.control_url, document.client_id, document.key_id, grant.id, url, trust),
            url,
            credential,
            expires,
        )

    def fence(self) -> None:
        self._closed = True
        for pending in tuple(self._pending.values()):
            pending.cancel()

    async def close(self) -> None:
        self.fence()
        await asyncio.gather(*tuple(self._pending.values()), return_exceptions=True)
        if self._client is not None:
            try:
                if self._client.is_closed and self._transport is not None:
                    await self._transport.aclose()
                else:
                    await self._client.aclose()
            except Exception:
                pass
            else:
                self._client, self._transport = None, None
                self._current.clear()
                return
            raise _error("unavailable") from None
        self._current.clear()
