"""real FIFO, fork, and subprocess backpressure regressions with outer watchdogs."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest


def probe(mode: str, root: Path, *args: Path) -> None:
    child = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("lifecycle_probe.py")),
            mode,
            str(root),
            *(str(arg) for arg in args),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        output, errors = child.communicate(timeout=8)
        assert child.returncode == 0, (output + errors).decode()
    except subprocess.TimeoutExpired:
        pytest.fail(f"{mode} did not finish within the outer process deadline")
    finally:
        # contain hung pre-fix workers, their native children, and forked children.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.communicate(timeout=5)


@pytest.mark.parametrize("mode", ["blocked-input", "duplex", "exit", "flood"])
def test_entire_native_exchange_is_bounded_and_reaped(mode: str, tmp_path: Path) -> None:
    probe(mode, tmp_path)


def test_endpoint_fifo_is_rejected_before_a_blocking_open(tmp_path: Path) -> None:
    probe("fifo", tmp_path)


@pytest.mark.parametrize("mode", ["fork-unlocked", "fork-locked"])
def test_forked_exit_and_inherited_handles_cannot_stop_parent_owner(
    tmp_path: Path, native_connections: tuple[Path, Path], mode: str
) -> None:
    probe(mode, tmp_path, *native_connections)
