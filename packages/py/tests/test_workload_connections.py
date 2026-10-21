"""provider acquisition and verified native-owner selection without JWT decoding."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import tnl
from tnl import _connections, _workload


@pytest.mark.parametrize("denied", [False, True])
def test_inactive_manifest_policies_do_not_exhaust_the_process_lifetime_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, denied: bool
) -> None:
    for cache in ("_sessions", "_contexts", "_identities", "_policy_locks"):
        monkeypatch.setattr(_connections, cache, {})
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    contexts = 0

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        nonlocal contexts
        if args[0] == "context":
            contexts += 1
            return {"schema": 1, "config_digest": f"{contexts:064x}"}
        assert args[0] == "identity"
        if denied:
            raise tnl.TnlError("sdk.workload_denied", "assertion rejected")
        return {
            "schema": 1,
            "binding": "a" * 64,
            "assertion_expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        }

    monkeypatch.setattr(_connections, "_command", command)
    for index in range(40):
        selection = _workload.Selection("job", str(tmp_path / "manifest"), "assertion", str(index))
        if denied:
            with pytest.raises(tnl.TnlError) as error:
                _connections._workload_session(str(tmp_path), selection)
            assert error.value.code == "sdk.workload_denied"
        else:
            session = _connections._workload_session(str(tmp_path), selection)
            # a live policy still reuses only its control-verified identity.
            assert _connections._workload_session(str(tmp_path), selection) is session
            session.close()
    assert contexts == 40
    assert not _connections._contexts
    assert not _connections._identities
    assert not _connections._policy_locks


def test_rotating_assertions_and_services_share_only_control_verified_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_connections, "_sessions", {})
    monkeypatch.setattr(_connections, "_contexts", {})
    monkeypatch.setattr(_connections, "_identities", {})
    monkeypatch.setattr(_connections, "_policy_locks", {})
    monkeypatch.setattr(_workload, "_configuration", None)
    monkeypatch.setattr(_connections, "native_binary", lambda: Path(sys.executable))
    monkeypatch.delenv("TNL_CONNECTION_HANDLE", raising=False)
    monkeypatch.setenv("TNL_WORKLOAD", "job")
    manifest = tmp_path / ".tnl/generated/workloads.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "schema": 1,
                "workloads": {
                    "job": {
                        "provider": "oidc",
                        "services": ["db", "mysql"],
                        "acquisition": {"method": "callback"},
                    }
                },
            }
        )
    )
    current = "first"

    async def token() -> str:
        return current

    tnl.configure_workload("job", token=token)
    owners: dict[str, str] = {}
    calls: list[tuple[str, ...]] = []
    denied: set[str] = set()
    deadline = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        calls.append(args)
        assert "first" not in args and "rotated" not in args
        assertion = input_value.get("assertion") if isinstance(input_value, dict) else None
        binding = (
            "a" * 64
            if assertion in {"first", "rotated"}
            else "b" * 64
            if assertion == "other"
            else None
        )
        if args[0] == "context":
            return {"schema": 1, "config_digest": "c" * 64}
        if args[0] == "identity":
            if binding is None:
                raise tnl.TnlError("sdk.workload_denied", "assertion rejected")
            return {"schema": 1, "binding": binding, "assertion_expires_at": deadline}
        if args[0] == "start":
            assert binding is not None and "--service" not in args
            file = str(tmp_path / f"owner-{len(owners)}")
            owners[file] = binding
            return {
                "schema": 1,
                "state": "ready",
                "pid": 1,
                "expires_at": deadline,
                "private_handle": file,
                "executable": str(binary),
                "public_runtime": {},
            }
        if args[0] == "attach":
            assert binding == owners[args[2]]
            return {"schema": 1, "state": "attached"}
        if args[0] == "recover":
            raise tnl.TnlError("sdk.connection_unavailable", "owner is still alive")
        if args[0] == "stop":
            return {"schema": 1, "state": "stopped"}
        assert args[0] in {"read", "prepare"}
        if args[0] == "prepare":
            assert binding == owners[args[2]]
        name = args[-1]
        if name in denied:
            raise tnl.TnlError("sdk.workload_denied", "service denied")
        protocol = "postgres" if name == "db" else "mysql"
        return {
            "schema": 1,
            "public_runtime": {
                "dev": False,
                "namespace": "example.test",
                "services": {
                    name: {
                        "protocol": protocol,
                        "hostname": f"{name}.example.test",
                        "namespace": "example.test",
                        "public": False,
                        "port": 15443,
                    }
                },
            },
            "connection": {
                "schema": 1,
                "protocol": protocol,
                "host": "127.0.0.1",
                "port": 34567,
                "expires_at": deadline,
                "ssl": {"servername": f"{name}.example.test", "rejectUnauthorized": True},
            },
        }

    monkeypatch.setattr(_connections, "_command", command)

    class IPC:
        def __init__(self, file: str) -> None:
            self.file = file

        def prepare(self, name: str, assertion: str | None = None) -> object:
            return command(
                Path(sys.executable),
                "prepare",
                "--handle",
                self.file,
                "--service",
                name,
                input_value={"schema": 1, "assertion": assertion},
            )

        def close(self) -> None:
            pass

    monkeypatch.setattr(_connections, "OwnerIPC", IPC)

    async def scenario() -> None:
        nonlocal current
        first = tnl.connect("db", directory=tmp_path)
        with pytest.raises(tnl.TnlError):
            first.snapshot()
        await first
        cold_helpers = [args for args in calls if args[0] != "prepare"]
        assert [args[0] for args in cold_helpers] == ["context", "identity", "start"]
        for _ in range(10):
            await first
        assert [args for args in calls if args[0] != "prepare"] == cold_helpers
        await tnl.connect("mysql", directory=tmp_path)
        current = "rotated"
        await tnl.connect("db", directory=tmp_path)
        assert len(owners) == 1
        denied.add("mysql")
        with pytest.raises(tnl.TnlError):
            await tnl.connect("mysql", directory=tmp_path)
        await first
        current = "forged"
        before = sum(args[0] == "prepare" for args in calls)
        with pytest.raises(tnl.TnlError):
            await tnl.connect("db", directory=tmp_path)
        assert sum(args[0] == "prepare" for args in calls) == before
        current = "other"
        other = tnl.connect("db", directory=tmp_path)
        await other
        assert len(owners) == 2
        await first.aclose()
        with pytest.raises(tnl.TnlError, match="closed"):
            await first
        await other.aclose()

    asyncio.run(scenario())


def test_callback_failures_do_not_expose_private_cause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_workload, "_configuration", None)
    monkeypatch.setenv("TNL_WORKLOAD", "job")
    manifest = tmp_path / ".tnl/generated/workloads.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "schema": 1,
                "workloads": {
                    "job": {
                        "provider": "oidc",
                        "services": ["db"],
                        "acquisition": {"method": "callback"},
                    }
                },
            }
        )
    )

    def token() -> str:
        raise RuntimeError("private-assertion")

    tnl.configure_workload("job", token=token)
    with pytest.raises(tnl.TnlError) as caught:
        asyncio.run(_workload.select_workload(str(tmp_path), "db"))
    assert "private-assertion" not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
