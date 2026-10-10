"""explicit HTTP-request adapter for Python functions that are not ASGI apps."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ._protocol import TnlError


def handler(endpoint: Callable[[Request], Response | Awaitable[Response]]) -> Starlette:
    """wrap a single Starlette request handler in an HTTP-only ASGI app."""
    if not callable(endpoint):
        raise TnlError("sdk.configuration_invalid", "a request handler is required")

    async def respond(request: Request) -> Response:
        result = endpoint(request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, Response):
            raise TnlError("sdk.response_invalid", "a request handler must return a response")
        return result

    return Starlette(
        routes=[
            Route(
                "/{path:path}",
                endpoint=respond,
                methods=[
                    "GET",
                    "HEAD",
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE",
                    "OPTIONS",
                ],
            )
        ]
    )
