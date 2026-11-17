"""binding-owned capture, stopping, and acknowledgment bookkeeping."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from copy import deepcopy

import pytest

from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, NativeUnavailable, RegistrationLost, TnlError
from tnl._registration import NativeRegistration


def test_cleanup_replays_captured_invocation_and_discovery_inputs() -> None:
    async def scenario() -> None:
        payload: dict[str, object] = {
            "version": 1,
            "owner": "owner",
            "target": "http://127.0.0.1:3000",
            "deployment": {"credential": "original", "service": "web"},
            "limits": {"total": 7},
        }
        original = deepcopy(payload)
        environment = {"TNL_NO_TELEMETRY": "1"}
        requests: list[object] = []
        discoveries: list[object] = []
        cleanups: list[object] = []

        class Runtime(NativeRuntime):
            async def start(
                self,
                directory: str,
                *,
                service: str | None = None,
                invocation_id: str | None = None,
                state_dir: str | None = None,
                publications: bool = False,
                environment: Mapping[str, str] | None = None,
            ) -> Endpoint:
                discoveries.append(deepcopy(environment))
                return Endpoint("http://127.0.0.1:12345", "b" * 64, "a" * 32, "invocation")

            async def request(
                self,
                endpoint: Endpoint,
                operation: str,
                payload: dict[str, object] | None = None,
            ) -> object:
                if operation == "publications/register":
                    requests.append(deepcopy(payload))
                    if len(requests) == 1:
                        raise NativeUnavailable()
                    return {
                        "version": 1,
                        "registration_id": "reg_" + "a" * 32,
                        "owner": "owner",
                        "target": "http://127.0.0.1:3000",
                    }
                cleanups.append(deepcopy(payload))
                if len(cleanups) <= 3:
                    raise NativeUnavailable()
                return None

        registration = NativeRegistration(
            Runtime(),
            "/project",
            None,
            payload,
            invocation_id="ivk_" + "A" * 22,
            environment=environment,
            target="http://127.0.0.1:3000",
        )
        payload["deployment"] = {"credential": "changed"}
        payload["limits"] = {"total": 99}
        environment["TNL_NO_TELEMETRY"] = "changed"
        await registration.discover()
        with pytest.raises(NativeUnavailable):
            await registration.acquire_invocation()
        await registration.stop()
        until = asyncio.get_running_loop().time() + 10
        with pytest.raises(NativeUnavailable):
            await registration.unregister(until, attempts=3)
        await registration.unregister(until + 60, attempts=3)
        assert requests == [original, original]
        assert discoveries == [{"TNL_NO_TELEMETRY": "1"}]
        assert len(cleanups) == 4 and all(value == cleanups[0] for value in cleanups)
        assert registration.complete
        with pytest.raises(RegistrationLost):
            await registration.acquire_invocation()
        with pytest.raises(RegistrationLost):
            await registration.discover()

    asyncio.run(scenario())


def test_stop_joins_independent_request_failure_before_cleanup() -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        failure = RuntimeError("independent native request failure")

        class Runtime(NativeRuntime):
            async def request(
                self,
                endpoint: Endpoint,
                operation: str,
                payload: dict[str, object] | None = None,
            ) -> object:
                entered.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    raise failure from None
                raise AssertionError("request was not canceled")

        registration = NativeRegistration(
            Runtime(), "/project", None, {"owner": "owner"}, service="web"
        )
        registration.endpoint = Endpoint("http://127.0.0.1:12345", "b" * 64, "a" * 32, "app", "web")
        acquiring = asyncio.create_task(registration.prepare())
        await entered.wait()
        assert await registration.stop() == [failure]
        with pytest.raises(RuntimeError) as caught:
            await acquiring
        assert caught.value is failure
        with pytest.raises(TnlError) as unconfirmed:
            await registration.unregister(asyncio.get_running_loop().time() + 10)
        assert unconfirmed.value.code == "sdk.dev_unavailable"
        assert not registration.complete

    asyncio.run(scenario())
