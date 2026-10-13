"""check configured Python service registration at Uvicorn's listener boundary."""

from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path

import httpx
import pytest
import uvicorn
from starlette.types import ASGIApp, Receive, Scope, Send

from tnl import uvicorn as tnl_uvicorn
from tnl._native import NativeRuntime


class FakeNative(NativeRuntime):
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []
        self.targets: dict[str, str] = {}

    async def start(self, directory: str, service: str | None = None) -> str:
        assert service == "web"
        self.events.append(("endpoint", directory))
        return directory + "/endpoint.json"

    async def app_request(
        self, endpoint_path: str, operation: str, payload: dict[str, object]
    ) -> object:
        self.events.append((operation, endpoint_path))
        if operation == "prepare":
            service = str(payload["service"])
            assert payload["framework"] == "python"
            assert payload["pid"] == os.getpid()
            return {
                "version": 1,
                "registration_id": "reg_" + "0" * 32,
                "service": service,
                "hostname": service + ".example.test",
                "public_url": "https://" + service + ".example.test",
                "project": {},
            }
        if operation == "register":
            self.targets[endpoint_path] = str(payload["target"])
        return None


def test_two_worktrees_register_their_actual_sockets_and_unpublish_before_shutdown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def scenario() -> None:
        native = FakeNative()
        monkeypatch.setattr(tnl_uvicorn, "_native", native)

        def app_for(root: str) -> ASGIApp:
            async def app(scope: Scope, receive: Receive, send: Send) -> None:
                if scope["type"] == "lifespan":
                    while True:
                        message = await receive()
                        if message["type"] == "lifespan.startup":
                            native.events.append(("startup", root + "/endpoint.json"))
                            await send({"type": "lifespan.startup.complete"})
                        elif message["type"] == "lifespan.shutdown":
                            native.events.append(("shutdown", root + "/endpoint.json"))
                            await send({"type": "lifespan.shutdown.complete"})
                            return
                elif scope["type"] == "http":
                    await send({"type": "http.response.start", "status": 200, "headers": []})
                    await send({"type": "http.response.body", "body": b"ready"})

            return app

        roots = [str(tmp_path / name) for name in ("one", "two")]
        servers = [
            tnl_uvicorn.Server(
                uvicorn.Config(
                    app_for(root), host="127.0.0.1", port=0, lifespan="on", log_level="critical"
                ),
                "web",
                root,
            )
            for root in roots
        ]
        tasks = [asyncio.create_task(server.serve()) for server in servers]
        try:
            async with asyncio.timeout(5):
                while not all(server.started for server in servers) or len(native.targets) != 2:
                    await asyncio.sleep(0.01)
            targets = [native.targets[root + "/endpoint.json"] for root in roots]
            assert targets[0] != targets[1]
            async with httpx.AsyncClient(trust_env=False) as client:
                for target in targets:
                    response = await client.get(target)
                    assert response.status_code == 200 and response.text == "ready"
        finally:
            for server in servers:
                server.should_exit = True
            await asyncio.gather(*tasks)
        for root in roots:
            endpoint = root + "/endpoint.json"
            assert [event[0] for event in native.events if event[1] in (endpoint, root)] == [
                "endpoint",
                "prepare",
                "startup",
                "register",
                "unregister",
                "shutdown",
            ]

    asyncio.run(scenario())


def test_reload_parent_only_binds_the_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    native = FakeNative()
    monkeypatch.setattr(tnl_uvicorn, "_native", native)
    observed: list[int] = []

    class Supervisor:
        def __init__(
            self, config: uvicorn.Config, target: object, sockets: list[socket.socket]
        ) -> None:
            assert config.should_reload
            assert callable(target)
            observed.append(sockets[0].getsockname()[1])

        def run(self) -> None:
            assert native.events == []

    monkeypatch.setattr(tnl_uvicorn, "ChangeReload", Supervisor)
    tnl_uvicorn.run("test_uvicorn:app", service="web", reload=True, log_level="critical")
    assert observed[0] > 0
