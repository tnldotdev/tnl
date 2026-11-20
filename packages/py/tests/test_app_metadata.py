"""native-produced configured-app metadata and scoped registration lifecycle."""

from __future__ import annotations

import asyncio
import json
import selectors
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

import tnl
from tnl import _app, _protocol
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, InvalidResponse, parse_endpoint


class AssignmentRuntime(NativeRuntime):
    def __init__(self, assignment: dict[str, object], service: str = "web") -> None:
        self.assignment = assignment
        self.endpoint = Endpoint("http://127.0.0.1:1234", "b" * 64, "a" * 32, "app", service)
        self.operations: list[str] = []
        self.preparations: list[dict[str, object]] = []

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
        return self.endpoint

    async def request(
        self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
    ) -> object:
        self.operations.append(operation)
        assert endpoint == self.endpoint
        assert payload is not None
        if operation == "prepare":
            self.preparations.append(dict(payload))
            return self.assignment
        assert payload["registration_id"] == self.assignment["registration_id"]
        return None


def test_publication_telemetry_opt_out_survives_reprepare_and_keeps_siblings_separate(
    native_app_assignment: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TNL_NO_TELEMETRY", raising=False)

    async def scenario() -> None:
        disabled_runtime = AssignmentRuntime(native_app_assignment)
        enabled_runtime = AssignmentRuntime(native_app_assignment)
        disabled = tnl.PreparedService("/project", "web", None, disabled_runtime, telemetry=False)
        enabled = tnl.PreparedService("/project", "web", None, enabled_runtime)
        await disabled.start()
        await enabled.start()
        await disabled._prepare()
        try:
            assert [p["telemetry_disabled"] for p in disabled_runtime.preparations] == [True, True]
            assert [p["telemetry_disabled"] for p in enabled_runtime.preparations] == [False]
        finally:
            await disabled.close()
            await enabled.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("protocol", ["http", "postgres", "mysql", "tcp", "kubernetes"])
def test_private_service_metadata_needs_no_ingress_reservation(protocol: str) -> None:
    service: dict[str, object] = {
        "protocol": protocol,
        "hostname": "private.member.example",
        "namespace": "member.example",
        "port": 443 if protocol == "http" else 0,
        "public": False,
    }
    if protocol in ("http", "kubernetes"):
        service["url"] = "https://private.member.example"
    assert _protocol._service_metadata("private", service) == service
    exposed = {**service, "public": True}
    if protocol == "http":
        assert _protocol._service_metadata("private", exposed) == exposed
    else:
        with pytest.raises(InvalidResponse):
            _protocol._service_metadata("private", exposed)


def private_assignment() -> dict[str, object]:
    return {
        "version": 1,
        "registration_id": "reg_" + "a" * 32,
        "service": "web",
        "hostname": "web.member.example",
        "public_url": "",
        "project": {
            "namespace": "member.example",
            "dev": True,
            "services": {
                "web": {
                    "protocol": "http",
                    "namespace": "member.example",
                    "hostname": "web.member.example",
                    "port": 443,
                    "public": False,
                    "url": "https://web.member.example",
                }
            },
        },
    }


@pytest.mark.parametrize("gate_at", ["start", "prepare"])
@pytest.mark.parametrize("independent_failure", ["none", "error", "joined"])
def test_close_joins_full_rediscovery_and_compensates_late_reservation(
    gate_at: str, independent_failure: str
) -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        canceled = asyncio.Event()
        release = asyncio.Event()
        cleanup_entered = asyncio.Event()
        failure: BaseException = InvalidResponse()
        if independent_failure == "joined":
            failure = BaseExceptionGroup(
                "cancellation and independent failure", [asyncio.CancelledError(), failure]
            )

        class Runtime(AssignmentRuntime):
            def __init__(self) -> None:
                super().__init__(private_assignment())
                self.starts = 0
                self.active: set[str] = set()
                self.registrations: list[dict[str, object]] = []
                self.cleanups: list[dict[str, object]] = []

            async def wait(self) -> None:
                entered.set()
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    canceled.set()
                    await release.wait()
                if independent_failure != "none":
                    raise failure

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
                self.starts += 1
                if self.starts == 2 and gate_at == "start":
                    await self.wait()
                return self.endpoint

            async def request(
                self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
            ) -> object:
                assert payload is not None
                if operation == "register":
                    self.registrations.append(dict(payload))
                    raise _protocol.NativeUnavailable()
                if operation == "prepare":
                    if self.starts == 2 and gate_at == "prepare":
                        await self.wait()
                        self.assignment = {
                            **self.assignment,
                            "registration_id": "reg_" + "b" * 32,
                        }
                    self.active.add(str(self.assignment["registration_id"]))
                elif operation == "unregister":
                    cleanup_entered.set()
                    self.cleanups.append(dict(payload))
                    self.active.discard(str(payload["registration_id"]))
                    return None
                return await super().request(endpoint, operation, payload)

        native = Runtime()
        prepared = tnl.PreparedService("/project", "web", None, native)
        await prepared.start()
        registering = asyncio.create_task(prepared.register("http://127.0.0.1:8000"))
        await entered.wait()
        closing = asyncio.create_task(prepared.close())
        # baseline unregisters before joining rediscovery; fixed code first cancels
        # and joins it. either observable event releases the same deterministic gate.
        observers = [
            asyncio.create_task(canceled.wait()),
            asyncio.create_task(cleanup_entered.wait()),
        ]
        await asyncio.wait(observers, return_when=asyncio.FIRST_COMPLETED)
        release.set()
        results = await asyncio.gather(registering, closing, return_exceptions=True)
        for observer in observers:
            observer.cancel()
        await asyncio.gather(*observers, return_exceptions=True)
        if independent_failure != "none":
            assert results[0] is failure
            cleanup_failure = results[1]
            if gate_at == "prepare":
                assert isinstance(cleanup_failure, BaseExceptionGroup)
                assert failure in cleanup_failure.exceptions
            else:
                assert cleanup_failure is failure
        else:
            assert isinstance(results[0], (asyncio.CancelledError, _protocol.RegistrationLost))
            assert results[1] is None
            await prepared.close()
        assert not native.active
        assert len(native.registrations) == 1
        expected_ids = ["reg_" + "a" * 32]
        if gate_at == "prepare" and independent_failure == "none":
            expected_ids.append("reg_" + "b" * 32)
        assert [item["registration_id"] for item in native.cleanups] == expected_ids
        for cleanup in native.cleanups:
            assert cleanup["owner"] == native.preparations[0]["owner"]
            assert cleanup["target"] == "http://127.0.0.1:8000"

    asyncio.run(asyncio.wait_for(scenario(), 5))


def test_close_bounds_initial_discovery_and_fences_late_preparation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        native = AssignmentRuntime(private_assignment())
        entered = asyncio.Event()
        release = asyncio.Event()
        canceled = asyncio.Event()

        async def discover(*args: object, **kwargs: object) -> Endpoint:
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                canceled.set()
                await release.wait()
            return native.endpoint

        monkeypatch.setattr(native, "start", discover)
        prepared = tnl.PreparedService("/project", "web", None, native)
        starting = asyncio.create_task(prepared.start())
        await entered.wait()
        until = asyncio.get_running_loop().time()
        with pytest.raises(TimeoutError) as failure:
            await prepared.close(until)
        await canceled.wait()
        assert prepared._shutdown_until == until
        with pytest.raises(TimeoutError) as repeated:
            await prepared.close()
        assert repeated.value is failure.value
        release.set()
        with pytest.raises(_protocol.RegistrationLost):
            await starting
        assert not native.operations
        assert not prepared._preparations
        assert prepared._renewal is None

    asyncio.run(asyncio.wait_for(scenario(), 5))


@pytest.mark.parametrize("outcome", ["prepared", "error", "joined"])
def test_close_after_preparation_completes_before_register_resumes(outcome: str) -> None:
    async def scenario() -> None:
        failure: BaseException = InvalidResponse()
        if outcome == "joined":
            failure = BaseExceptionGroup(
                "preparation and cancellation failed", [asyncio.CancelledError(), failure]
            )
        closing: list[asyncio.Task[None]] = []
        close_saw_completed_preparation = asyncio.Event()

        class Runtime(AssignmentRuntime):
            def __init__(self) -> None:
                super().__init__(private_assignment())
                self.prepare_count = 0
                self.register_count = 0
                self.active = False
                self.cleanups: list[dict[str, object]] = []

            async def request(
                self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
            ) -> object:
                if operation == "register":
                    self.register_count += 1
                    raise _protocol.NativeUnavailable()
                result = await super().request(endpoint, operation, payload)
                if operation == "prepare":
                    self.active = True
                    self.prepare_count += 1
                    if self.prepare_count == 2:
                        # queue close before the request wakes preparation. its
                        # cleanup then runs after preparation finishes but before
                        # the register caller resumes from joining that task.
                        closing.append(asyncio.create_task(prepared.close()))
                        if outcome != "prepared":
                            raise failure
                elif operation == "unregister":
                    assert payload is not None
                    self.cleanups.append(dict(payload))
                    self.active = False
                return result

        class Prepared(tnl.PreparedService):
            async def _close(self, until: float) -> None:
                assert self._preparations
                assert all(task.done() for task in self._preparations)
                close_saw_completed_preparation.set()
                await super()._close(until)

        native = Runtime()
        prepared = Prepared("/project", "web", None, native)
        await prepared.start()
        result = (
            await asyncio.gather(prepared.register("http://127.0.0.1:8000"), return_exceptions=True)
        )[0]
        assert close_saw_completed_preparation.is_set()
        assert len(closing) == 1
        cleanup = (await asyncio.gather(*closing, return_exceptions=True))[0]
        if outcome == "prepared":
            assert result is prepared._closed_error
            assert cleanup is None
            await prepared.close()
        else:
            assert result is failure
            assert isinstance(cleanup, BaseExceptionGroup)
            assert failure in cleanup.exceptions
            repeated = (await asyncio.gather(prepared.close(), return_exceptions=True))[0]
            assert repeated is cleanup
        assert native.prepare_count == 2
        assert native.register_count == 1
        assert not native.active
        assert not prepared._preparations
        assert len(native.cleanups) == 1
        assert native.cleanups[0]["registration_id"] == native.assignment["registration_id"]
        assert native.cleanups[0]["owner"] == native.preparations[0]["owner"]
        assert native.cleanups[0]["target"] == "http://127.0.0.1:8000"
        assert prepared._registration.closed

    asyncio.run(asyncio.wait_for(scenario(), 5))


def test_changed_registration_compensation_does_not_start_owner_shutdown_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        original = private_assignment()
        changed = private_assignment()
        changed["registration_id"] = "reg_" + "b" * 32
        changed["public_url"] = "https://web.member.example"
        project = cast(dict[str, object], changed["project"])
        services = cast(dict[str, dict[str, object]], project["services"])
        services["web"]["public"] = True
        cleanups: list[dict[str, object]] = []
        deadlines: list[float] = []

        class Runtime(AssignmentRuntime):
            async def request(
                self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
            ) -> object:
                if operation == "unregister":
                    assert payload is not None
                    cleanups.append(dict(payload))
                return await super().request(endpoint, operation, payload)

        def deadline() -> float:
            until = asyncio.get_running_loop().time() + 0.03
            deadlines.append(until)
            return until

        monkeypatch.setattr(_app, "_shutdown_deadline", deadline)
        native = Runtime(original)
        prepared = tnl.PreparedService("/project", "web", None, native)
        await prepared.start()
        native.assignment = changed
        try:
            with pytest.raises(InvalidResponse):
                await prepared._prepare()
            assert prepared._registration.current is not None
            assert prepared._registration.current.registration_id == original["registration_id"]
            assert prepared.public_url == ""
            expired = asyncio.Event()
            asyncio.get_running_loop().call_at(deadlines[0] + 0.001, expired.set)
            await asyncio.wait_for(expired.wait(), 1)
            native.assignment = original
            await prepared.close()
            assert len(deadlines) == 2 and deadlines[1] > deadlines[0]
            assert [value["registration_id"] for value in cleanups] == [
                changed["registration_id"],
                original["registration_id"],
            ]
            assert all("shutdown_deadline" in value for value in cleanups)
        finally:
            native.assignment = original
            await asyncio.gather(prepared.close(), return_exceptions=True)

    asyncio.run(scenario())


def test_deferred_assignment_is_valid_only_at_acquisition() -> None:
    value = private_assignment()
    value["hostname"] = ""
    value["project"] = {"namespace": "", "services": {}, "dev": True}
    endpoint = Endpoint("http://127.0.0.1:1234", "b" * 64, "a" * 32, "app", "web")
    assigned = _protocol.parse_assignment(value, endpoint)
    assert assigned.hostname == "" and assigned.public_url == ""

    async def scenario() -> None:
        native = AssignmentRuntime(value)
        prepared = tnl.PreparedService("/project", "web", None, native)
        with pytest.raises(InvalidResponse):
            await prepared.start()
        assert native.operations == ["prepare"]
        await prepared.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("public", [False, True])
def test_selected_http_assignment_separates_hostname_from_public_url(public: bool) -> None:
    value = private_assignment()
    project = cast(dict[str, object], value["project"])
    services = cast(dict[str, dict[str, object]], project["services"])
    services["web"]["public"] = public
    value["public_url"] = "https://web.member.example" if public else ""
    endpoint = Endpoint("http://127.0.0.1:1234", "b" * 64, "a" * 32, "app", "web")
    assigned = _protocol.parse_assignment(value, endpoint)
    assert assigned.hostname == "web.member.example"
    assert assigned.public_url == value["public_url"]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("hostname",), ""),
        (("hostname",), "other.member.example"),
        (("public_url",), "https://web.member.example"),
        (("access_token",), "private-secret"),
        (("project", "services"), {}),
        (("project", "services", "web", "url"), "https://other.member.example"),
        (("project", "services", "web", "target"), "http://private-secret:3000"),
        (("project", "services", "web", "port"), 0),
        (("project", "services", "web", "public"), True),
    ],
)
def test_rejects_mismatched_or_secret_private_assignment(
    path: tuple[str, ...], value: object
) -> None:
    assignment = private_assignment()
    item = assignment
    for key in path[:-1]:
        item = cast(dict[str, object], item[key])
    item[path[-1]] = value
    endpoint = Endpoint("http://127.0.0.1:1234", "b" * 64, "a" * 32, "app", "web")
    with pytest.raises(InvalidResponse) as caught:
        _protocol.parse_assignment(assignment, endpoint)
    assert "private-secret" not in str(caught.value)


def test_native_assignment_is_http_only_for_selected_app(
    native_app_assignment: dict[str, object],
) -> None:
    project = cast(dict[str, object], native_app_assignment["project"])
    services = cast(dict[str, dict[str, object]], project["services"])
    assert {item["protocol"] for item in services.values()} == {
        "http",
        "tcp",
        "mysql",
        "postgres",
        "kubernetes",
    }
    assert services["web"]["port"] == 443
    assert services["api"]["public"] is False
    assert services["mysql"]["public"] is True

    async def scenario() -> None:
        native = AssignmentRuntime(native_app_assignment)
        publication = tnl.PreparedService("/project", "web", None, native)
        assert publication._registration.current is None
        assert not publication._registration.closed
        await publication.start()
        try:
            assert publication._registration.current is not None
            assert publication.public_url == "https://web.member.example"
            await publication.register("http://127.0.0.1:8000")
        finally:
            await publication.close()
        assert publication._registration.closed and publication._registration.complete
        with pytest.raises(_app.RegistrationLost):
            await publication.register("http://127.0.0.1:8000")
        assert native.operations == ["prepare", "register", "unregister"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("project", "services", "database", "port"), -1),
        (("project", "services", "database", "port"), 65536),
        (("project", "services", "database", "port"), True),
        (("project", "services", "database", "port"), "15443"),
        (("project", "services", "database", "public"), 1),
        (("project", "services", "database", "public"), "false"),
        (("project", "services", "database", "protocol"), "ssh"),
        (("project", "services", "database", "url"), "https://database.member.example:15443"),
        (("project", "services", "database", "target"), "private target"),
        (("project", "services", "api", "url"), "https://api.member.example:1234"),
        (("project", "services", "web", "url"), "https://web.member.example:25443"),
        (("project", "services", "web", "port"), 0),
        (("project", "services", "web", "port"), 25443),
        (("project", "services", "cluster", "url"), "https://cluster.member.example"),
        (("project", "services", "web", "namespace"), "INVALID.example"),
        (("project", "services", "web", "hostname"), "web.member.example."),
        (("project", "services", "web", "paths", "/api", "target"), "private target"),
        (("project", "services", "web", "paths", "/api", "stripPrefix"), 1),
        (("project", "services", "web", "paths", "/api", "service"), "web"),
        (("project", "services", "web", "paths", "/api", "url"), "https://other.example/api"),
        (("project", "services", "database", "paths"), {"/api": {}}),
        (("project", "dev"), False),
        (("project", "namespace"), ""),
        (("project", "secret"), "private target"),
        (("service",), "api"),
        (("service",), "invalid name"),
        (("hostname",), "other.member.example"),
        (("public_url",), "https://web.member.example:25443"),
        (("public_url",), "https://web.member.example:25443/path"),
        (("registration_id",), "reg_bad"),
        (("version",), True),
    ],
)
def test_rejects_invalid_native_assignment(
    native_app_assignment: dict[str, object], path: tuple[str, ...], value: object
) -> None:
    item = native_app_assignment
    for key in path[:-1]:
        item = cast(dict[str, object], item[key])
    item[path[-1]] = value

    async def scenario() -> None:
        native = AssignmentRuntime(native_app_assignment)
        publication = tnl.PreparedService("/project", "web", None, native)
        with pytest.raises(InvalidResponse) as caught:
            await publication.start()
        assert caught.value.code == "sdk.response_invalid"
        assert str(caught.value) == "the local publisher returned an invalid response"
        assert native.operations == ["prepare"]
        with pytest.raises(tnl.TnlError, match="cleanup could not be confirmed") as cleanup:
            await publication.close()
        assert cleanup.value.code == "sdk.dev_unavailable"
        assert native.operations == ["prepare"]

    asyncio.run(scenario())


@pytest.mark.parametrize("field", ["protocol", "namespace", "hostname", "port", "public", "url"])
def test_rejects_missing_native_service_fields(
    native_app_assignment: dict[str, object], field: str
) -> None:
    project = cast(dict[str, object], native_app_assignment["project"])
    services = cast(dict[str, dict[str, object]], project["services"])
    del services["web"][field]

    async def scenario() -> None:
        publication = tnl.PreparedService(
            "/project", "web", None, AssignmentRuntime(native_app_assignment)
        )
        with pytest.raises(InvalidResponse):
            await publication.start()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "case", ["invalid-name", "wrong-scope", "non-http-app", "missing-own", "hidden-own"]
)
def test_rejects_invalid_service_set_or_scope(
    native_app_assignment: dict[str, object], case: str
) -> None:
    project = cast(dict[str, object], native_app_assignment["project"])
    services = cast(dict[str, dict[str, object]], project["services"])
    if case == "invalid-name":
        services["invalid name"] = services.pop("database")
    elif case == "non-http-app":
        native_app_assignment["service"] = "cluster"
        native_app_assignment["hostname"] = services["cluster"]["hostname"]
        native_app_assignment["public_url"] = services["cluster"]["url"]
    elif case == "missing-own":
        del services["web"]
    elif case == "hidden-own":
        native_app_assignment["hostname"] = ""
        native_app_assignment["public_url"] = ""
    selected = "api" if case == "wrong-scope" else str(native_app_assignment["service"])

    async def scenario() -> None:
        native = AssignmentRuntime(native_app_assignment, selected)
        publication = tnl.PreparedService("/project", selected, None, native)
        with pytest.raises(InvalidResponse):
            await publication.start()
        assert native.operations == ["prepare"]

    asyncio.run(scenario())


def test_accepts_large_native_service_set(native_app_assignment: dict[str, object]) -> None:
    project = cast(dict[str, object], native_app_assignment["project"])
    services = cast(dict[str, dict[str, object]], project["services"])
    services.update({f"service-{index}": services["database"] for index in range(33)})
    endpoint = Endpoint("http://127.0.0.1:1234", "b" * 64, "a" * 32, "app", "web")
    assignment = _protocol.parse_assignment(native_app_assignment, endpoint)
    assert assignment.service == "web"
    assert assignment.hostname == "web.member.example"


@pytest.mark.parametrize(
    ("port", "public", "omit_service"),
    [
        (443, True, False),
        (443, False, False),
        (443, False, True),
    ],
)
def test_native_metadata_registration_and_cleanup(
    tmp_path: Path,
    native_app_owner: Path,
    monkeypatch: pytest.MonkeyPatch,
    port: int,
    public: bool,
    omit_service: bool,
) -> None:
    tmp_path.chmod(0o700)
    with subprocess.Popen(
        [
            str(native_app_owner),
            f"-tnl-port={port}",
            f"-tnl-public={str(public).lower()}",
            f"-tnl-omit-service={str(omit_service).lower()}",
            str(tmp_path.resolve()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        assert process.stdout is not None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(10), "native app owner did not become ready"
            descriptor = process.stdout.readline()
            endpoint = parse_endpoint(json.loads(descriptor), service="web")
            path = tmp_path / "endpoint.json"
            path.write_bytes(descriptor)
            path.chmod(0o400)
            monkeypatch.setenv("TNL_APP_ENDPOINT", str(path))

            async def scenario() -> None:
                if omit_service:
                    with pytest.raises(InvalidResponse):
                        await tnl.prepare(directory=tmp_path, service="web")
                    status = await NativeRuntime().request(endpoint, "status")
                    assert isinstance(status, dict)
                    assert status["services"][0]["registered"] is False
                    assert not status["services"][0].get("registration_id")
                    return
                publication = await tnl.prepare(directory=tmp_path, service="web")
                try:
                    assert publication.service == "web"
                    assert publication.hostname == "web.member.example"
                    assert publication.public_url == (
                        "https://web.member.example" if public else ""
                    )
                    await publication.register("http://127.0.0.1:8000")
                    native = NativeRuntime()
                    status = await native.request(endpoint, "status")
                    assert isinstance(status, dict)
                    assert status["services"][0]["registered"] is True
                    assert status["services"][0]["target"] == "http://127.0.0.1:8000"
                    await native.request(endpoint, "renew", publication._registration.payload())
                finally:
                    await publication.close()
                await publication.close()
                status = await NativeRuntime().request(endpoint, "status")
                assert isinstance(status, dict)
                assert status["services"][0]["registered"] is False
                assert not status["services"][0].get("registration_id")

            asyncio.run(scenario())
        finally:
            process.terminate()
            _, errors = process.communicate(timeout=10)
            assert process.returncode == 0, errors.decode()
