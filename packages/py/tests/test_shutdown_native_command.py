"""real native helper interruption joins both the process and its SDK worker."""

from __future__ import annotations

import os
import socket
import sys
import threading
from pathlib import Path

import pytest

from tnl import _connections


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
