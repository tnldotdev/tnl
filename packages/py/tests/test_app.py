"""real configured Uvicorn workers, including their reload supervisor boundary."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

import httpx
import pytest


@pytest.mark.parametrize("reload", [False, True])
@pytest.mark.parametrize("private_service", [False, True])
def test_worker_registers_after_bind_and_joins_before_lifespan_stop(
    tmp_path: Path, reload: bool, private_service: bool
) -> None:
    async def scenario() -> None:
        tmp_path.chmod(0o700)
        events = tmp_path / "events.jsonl"
        requests: list[tuple[str, dict[str, object]]] = []
        failures: list[BaseException] = []
        active: dict[str, object] = {}

        def log(value: dict[str, object]) -> None:
            with events.open("a") as file:
                file.write(json.dumps(value) + "\n")

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                headers = (await reader.readuntil(b"\r\n\r\n")).decode()
                lines = headers.split("\r\n")
                assert f"Authorization: Bearer {'b' * 64}" in lines
                assert not any(line.lower().startswith("origin:") for line in lines)
                path = lines[0].split()[1]
                length = next(
                    (
                        int(line.split(":", 1)[1])
                        for line in lines
                        if line.lower().startswith("content-length:")
                    ),
                    0,
                )
                payload: object = json.loads(await reader.readexactly(length)) if length else {}
                assert isinstance(payload, dict)
                requests.append((path, payload))
                body = b""
                status = 204
                if path == "/v1/prepare":
                    active.update(payload)
                    active["registration_id"] = "reg_" + str(len(requests) % 10) * 32
                    assert payload["framework"] == "python"
                    body = json.dumps(
                        {
                            "version": 1,
                            "registration_id": active["registration_id"],
                            "service": "web",
                            "hostname": "" if private_service else "web.member.example",
                            "public_url": "" if private_service else "https://web.member.example",
                            "project": {
                                "namespace": "" if private_service else "member.example",
                                "dev": True,
                                "services": {}
                                if private_service
                                else {
                                    "web": {
                                        "protocol": "http",
                                        "namespace": "member.example",
                                        "hostname": "web.member.example",
                                        "url": "https://web.member.example",
                                    }
                                },
                            },
                        }
                    ).encode()
                    status = 200
                    log({"event": "prepare", "pid": payload["pid"]})
                elif path == "/v1/register":
                    assert payload["registration_id"] == active["registration_id"]
                    active["target"] = payload["target"]
                    assert str(payload["target"]).startswith("http://127.0.0.1:")
                    # a real request verifies registration happens after bind and lifespan.
                    async with httpx.AsyncClient(trust_env=False) as client:
                        result = await client.get(str(payload["target"]))
                        assert result.status_code == 200 and result.text == "worker"
                    log({"event": "register", "pid": active["pid"]})
                elif path == "/v1/unregister":
                    assert payload["registration_id"] == active["registration_id"]
                    assert payload["target"] == active["target"]
                    await asyncio.sleep(0.05)
                    log({"event": "unregister", "pid": active["pid"]})
                elif path == "/v1/renew":
                    assert payload["target"] == active["target"]
                else:
                    assert path == "/v1/health"
                writer.write(
                    f"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
            except BaseException as cause:
                failures.append(cause)
            finally:
                writer.close()
                await writer.wait_closed()

        api = await asyncio.start_server(handle, "127.0.0.1", 0)
        descriptor = tmp_path / "endpoint.json"
        descriptor.write_text(
            json.dumps(
                {
                    "version": 1,
                    "url": f"http://127.0.0.1:{api.sockets[0].getsockname()[1]}",
                    "capability": "b" * 64,
                    "owner_id": "a" * 32,
                    "scope": "app",
                    "service": "web",
                }
            )
        )
        descriptor.chmod(0o400)
        source = tmp_path / "application.py"
        source.write_text(f"""
import json, os
from pathlib import Path
def log(event):
    with Path({str(events)!r}).open("a") as file:
        file.write(json.dumps({{"event": event, "pid": os.getpid()}}) + "\\n")
async def app(scope, receive, send):
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                log("startup")
                await send({{"type": "lifespan.startup.complete"}})
            elif message["type"] == "lifespan.shutdown":
                log("shutdown")
                await send({{"type": "lifespan.shutdown.complete"}})
                return
    elif scope["type"] == "http":
        await send({{"type": "http.response.start", "status": 200, "headers": []}})
        await send({{"type": "http.response.body", "body": b"worker"}})
""")
        runner = tmp_path / "run.py"
        runner.write_text(f"""
import tnl
if __name__ == "__main__":
    tnl.run("application:app", host="0.0.0.0", port=0, reload={reload!r},
            directory={str(tmp_path)!r}, service="web", reload_dirs=[{str(tmp_path)!r}])
""")
        environment = {**os.environ, "TNL_APP_ENDPOINT": str(descriptor)}
        environment["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
        child = await asyncio.create_subprocess_exec(
            sys.executable,
            str(runner),
            cwd=tmp_path,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )

        async def await_registrations(count: int) -> None:
            async with asyncio.timeout(15):
                while sum(path == "/v1/register" for path, _ in requests) < count:
                    assert child.returncode is None
                    assert not failures
                    await asyncio.sleep(0.02)

        try:
            await await_registrations(1)
            first_pid = active["pid"]
            if reload:
                assert first_pid != child.pid
                # StatReload establishes its first mtime on its first poll.
                await asyncio.sleep(1)
                source.write_text(source.read_text() + "\n# reload the serving worker\n")
                await await_registrations(2)
                assert active["pid"] != first_pid
                assert active["pid"] != child.pid
            child.terminate()
            output, _ = await asyncio.wait_for(child.communicate(), 15)
            assert child.returncode in {0, -signal.SIGTERM}, output.decode()
            assert not failures
            records = [json.loads(line) for line in events.read_text().splitlines()]
            pids = {record["pid"] for record in records}
            for pid in pids:
                order = [record["event"] for record in records if record["pid"] == pid]
                assert order == ["startup", "prepare", "register", "unregister", "shutdown"]
        finally:
            if child.returncode is None:
                os.killpg(child.pid, signal.SIGKILL)
                await asyncio.wait_for(child.communicate(), 5)
            api.close()
            await api.wait_closed()

    asyncio.run(scenario())
