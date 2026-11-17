"""real native helper interruption joins both the process and its SDK worker."""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

import tnl
from tnl import _connections, _deployments


def test_shutdown_interrupts_and_joins_native_helper(tmp_path: Path) -> None:
    with socket.socket() as ready:
        ready.bind(("127.0.0.1", 0))
        ready.listen(1)
        ready.settimeout(3)
        executable = tmp_path / "native-helper"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import os, signal, socket\n"
            f"with socket.create_connection({ready.getsockname()!r}) as ready:\n"
            "    ready.sendall(str(os.getpid()).encode())\n"
            "signal.pause()\n"
        )
        executable.chmod(0o700)
        interrupted = threading.Event()
        failures: list[BaseException] = []

        def command() -> None:
            try:
                _connections._command(executable, "hold", interrupted=interrupted.is_set)
            except BaseException as cause:
                failures.append(cause)

        worker = threading.Thread(target=command)
        worker.start()
        try:
            peer, _ = ready.accept()
            with peer:
                peer.settimeout(3)
                pid = int(peer.recv(32))
            interrupted.set()
            worker.join(3)
            assert not worker.is_alive(), "tnl left its native command worker running"
            assert len(failures) == 1 and isinstance(failures[0], _connections._InterruptedError)
            assert failures[0].code == "sdk.connection_closed"
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            interrupted.set()
            worker.join(3)


@pytest.mark.parametrize("cancel_getter", [False, True])
def test_local_deployment_shutdown_interrupts_and_joins_native_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cancel_getter: bool
) -> None:
    with socket.socket() as ready:
        ready.bind(("127.0.0.1", 0))
        ready.listen(1)
        ready.settimeout(3)
        executable = tmp_path / "native-local"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import os, signal, socket\n"
            f"with socket.create_connection({ready.getsockname()!r}) as ready:\n"
            "    ready.sendall(str(os.getpid()).encode())\n"
            "signal.pause()\n"
        )
        executable.chmod(0o700)
        emergency, joined = threading.Event(), threading.Event()
        interruptions: list[Callable[[], bool] | None] = []

        def command(
            binary: Path,
            *arguments: str,
            input_value: object = None,
            deadline: float | None = None,
            interrupted: Callable[[], bool] | None = None,
        ) -> object:
            interruptions.append(interrupted)
            try:
                return _connections._command(
                    binary,
                    *arguments,
                    input_value=input_value,
                    deadline=deadline,
                    interrupted=lambda: (
                        emergency.is_set() or interrupted is not None and interrupted()
                    ),
                )
            finally:
                joined.set()

        monkeypatch.setattr(_connections._Scope, "binary", lambda _: executable)
        monkeypatch.setattr(_connections._Scope, "stop", lambda _, _until=None: None)
        monkeypatch.setattr(_deployments, "_command", command)

        async def scenario() -> None:
            local = tnl.create_client(
                project="team/project", services={"db": {"protocol": "postgres"}}
            ).deployment("local")
            getter = asyncio.create_task(local.connect("db"))
            closing: asyncio.Task[None] | None = None
            try:
                peer, _ = await asyncio.to_thread(ready.accept)
                with peer:
                    peer.settimeout(3)
                    pid = int(peer.recv(32))
                if cancel_getter:
                    getter.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await getter
                until = asyncio.get_running_loop().time() + 0.15
                local._shutdown_until = until
                closing = asyncio.create_task(local.aclose())
                done, _ = await asyncio.wait((closing,), timeout=0.7)
                assert done, "deployment shutdown ignored its budget and left the helper running"
                await closing
                assert joined.is_set(), "canceling a to_thread waiter did not join its worker"
                assert interruptions[0] is not None and interruptions[0]()
                with pytest.raises(ProcessLookupError):
                    os.kill(pid, 0)
                if not cancel_getter:
                    with pytest.raises(tnl.TnlError) as caught:
                        await getter
                    assert caught.value.code == "sdk.connection_closed"
                assert not local._pending
                await local.aclose()
                assert local._shutdown_until == until
            finally:
                emergency.set()
                await asyncio.gather(getter, return_exceptions=True)
                if closing is not None:
                    await asyncio.gather(closing, return_exceptions=True)
                await local.aclose()

        asyncio.run(scenario())


def test_queued_local_acquisition_gets_original_native_shutdown_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered, release, joined = threading.Event(), threading.Event(), threading.Event()
    stopped: list[float] = []
    budgets: list[float | None] = []

    def binary(_scope: _connections._Scope) -> Path:
        entered.set()
        assert release.wait(3)
        return Path("/unused/native")

    def stop(_scope: _connections._Scope, until: float) -> None:
        stopped.append(until)
        release.set()

    def command(
        binary: Path,
        *arguments: str,
        input_value: object = None,
        deadline: float | None = None,
        interrupted: Callable[[], bool] | None = None,
    ) -> object:
        budgets.append(deadline)
        try:
            return _connections._command(
                binary, *arguments, deadline=deadline, interrupted=interrupted
            )
        finally:
            joined.set()

    monkeypatch.setattr(_connections._Scope, "binary", binary)
    monkeypatch.setattr(_connections._Scope, "stop", stop)
    monkeypatch.setattr(_deployments, "_command", command)

    async def scenario() -> None:
        local = tnl.create_client(
            project="team/project", services={"db": {"protocol": "postgres"}}
        ).deployment("local")
        getter = asyncio.create_task(local.connect("db"))
        try:
            assert await asyncio.to_thread(entered.wait, 3)
            until = asyncio.get_running_loop().time() + 0.15
            local._shutdown_until = until
            await asyncio.wait_for(local.aclose(), 1)
            with pytest.raises(tnl.TnlError) as caught:
                await getter
            assert caught.value.code == "sdk.connection_closed"
            assert joined.is_set()
            assert budgets == [stopped[0]] and budgets[0] is not None
            await local.aclose()
            assert stopped == [budgets[0], budgets[0]]
            assert local._shutdown_until == until
        finally:
            release.set()
            await asyncio.gather(getter, return_exceptions=True)
            await local.aclose()

    asyncio.run(scenario())


def test_shutdown_interrupts_native_helper_after_pipes_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with socket.socket() as ready:
        ready.bind(("127.0.0.1", 0))
        ready.listen(1)
        ready.settimeout(3)
        executable = tmp_path / "native-exit"
        executable.write_text(
            f"#!{sys.executable}\n"
            "import os, signal, socket\n"
            "os.close(1)\n"
            "os.close(2)\n"
            f"with socket.create_connection({ready.getsockname()!r}) as ready:\n"
            "    ready.sendall(str(os.getpid()).encode())\n"
            "signal.pause()\n"
        )
        executable.chmod(0o700)
        interrupted, waiting = threading.Event(), threading.Event()
        failures: list[BaseException] = []

        class WaitingProcess(subprocess.Popen[bytes]):
            def wait(self, timeout: float | None = None) -> int:
                waiting.set()
                return super().wait(timeout=timeout)

        monkeypatch.setattr(subprocess, "Popen", WaitingProcess)

        def command() -> None:
            try:
                _connections._command(executable, "hold", interrupted=interrupted.is_set)
            except BaseException as cause:
                failures.append(cause)

        worker = threading.Thread(target=command)
        pid: int | None = None
        worker.start()
        try:
            peer, _ = ready.accept()
            with peer:
                peer.settimeout(3)
                pid = int(peer.recv(32))
            assert waiting.wait(3), "native helper never reached its exit wait"
            interrupted.set()
            worker.join(0.7)
            assert not worker.is_alive(), "native exit wait ignored shutdown after pipe EOF"
            assert len(failures) == 1 and isinstance(failures[0], _connections._InterruptedError)
            assert failures[0].code == "sdk.connection_closed"
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            interrupted.set()
            if worker.is_alive() and pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            worker.join(3)
