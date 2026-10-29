"""native-produced configured-app metadata and scoped registration lifecycle."""

from __future__ import annotations

import asyncio
import json
import selectors
import subprocess
from pathlib import Path
from typing import cast

import pytest

import tnl
from tnl._app import _read_telemetry_disabled
from tnl._native import NativeRuntime
from tnl._protocol import Endpoint, InvalidResponse, RegistrationLost, TnlError, parse_endpoint


class AssignmentRuntime(NativeRuntime):
    def __init__(self, assignment: dict[str, object], service: str = "web") -> None:
        self.assignment = assignment
        self.endpoint = Endpoint("http://127.0.0.1:1234", "b" * 64, "a" * 32, "app", service)
        self.operations: list[str] = []
        self.starts = 0
        self.preparations: list[dict[str, object]] = []

    async def start(
        self,
        directory: str,
        *,
        service: str | None = None,
        invocation_id: str | None = None,
        state_dir: str | None = None,
    ) -> Endpoint:
        self.starts += 1
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


@pytest.mark.parametrize(
    ("value", "disabled"),
    [
        (None, False),
        ("1", True),
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("TrUe", True),
        ("yes", True),
        ("YES", True),
        ("YeS", True),
        ("0", False),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("FaLsE", False),
        ("no", False),
        ("NO", False),
        ("nO", False),
    ],
)
def test_telemetry_setting_matches_kong(value: str | None, disabled: bool) -> None:
    assert _read_telemetry_disabled(value) is disabled


@pytest.mark.parametrize(("value", "disabled"), [("true", True), ("YeS", True), ("false", False)])
def test_telemetry_setting_reaches_prepare(
    native_app_assignment: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    value: str,
    disabled: bool,
) -> None:
    monkeypatch.setenv("TNL_NO_TELEMETRY", value)
    native = AssignmentRuntime(native_app_assignment)
    monkeypatch.setattr("tnl._app.NativeRuntime", lambda: native)

    async def scenario() -> None:
        publication = await tnl.prepare(directory="/project", service="web")
        try:
            assert native.preparations[0]["telemetry_disabled"] is disabled
        finally:
            await publication.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "value", ["", "t", "T", "f", "F", "private-invalid-setting", " true", "true "]
)
def test_invalid_telemetry_setting_fails_safely_before_native_start(
    native_app_assignment: dict[str, object], monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("TNL_NO_TELEMETRY", value)
    native = AssignmentRuntime(native_app_assignment)
    monkeypatch.setattr("tnl._app.NativeRuntime", lambda: native)

    async def scenario() -> None:
        publication = None
        try:
            with pytest.raises(TnlError) as caught:
                publication = await tnl.prepare(directory="/project", service="web")
            assert caught.value.code == "sdk.configuration_invalid"
            assert str(caught.value) == "TNL_NO_TELEMETRY must be a boolean"
            assert native.starts == 0
            assert native.operations == []
        finally:
            if publication is not None:
                await publication.close()

    asyncio.run(scenario())


def test_telemetry_snapshot_survives_async_start_and_registration_recovery(
    native_app_assignment: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TNL_NO_TELEMETRY", "1")

    class RestartingRuntime(AssignmentRuntime):
        failed = False

        async def start(
            self,
            directory: str,
            *,
            service: str | None = None,
            invocation_id: str | None = None,
            state_dir: str | None = None,
        ) -> Endpoint:
            await asyncio.sleep(0)
            monkeypatch.setenv("TNL_NO_TELEMETRY", "false")
            return await super().start(
                directory, service=service, invocation_id=invocation_id, state_dir=state_dir
            )

        async def request(
            self, endpoint: Endpoint, operation: str, payload: dict[str, object] | None = None
        ) -> object:
            if operation == "register" and not self.failed:
                self.failed = True
                raise RegistrationLost()
            return await super().request(endpoint, operation, payload)

    native = RestartingRuntime(native_app_assignment)
    monkeypatch.setattr("tnl._app.NativeRuntime", lambda: native)

    async def scenario() -> None:
        publication = await tnl.prepare(directory="/project", service="web")
        try:
            await publication.register("http://127.0.0.1:8000")
            assert native.starts == 2
            assert [item["telemetry_disabled"] for item in native.preparations] == [True, True]
        finally:
            await publication.close()

    asyncio.run(scenario())


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
    assert services["web"]["port"] == 25443
    assert services["api"]["public"] is False
    assert services["mysql"]["public"] is True

    async def scenario() -> None:
        native = AssignmentRuntime(native_app_assignment)
        publication = tnl.PreparedService("/project", "web", None, native)
        await publication.start()
        try:
            assert publication.public_url == "https://web.member.example:25443"
            await publication.register("http://127.0.0.1:8000")
        finally:
            await publication.close()
        assert native.operations == ["prepare", "register", "unregister"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("project", "services", "database", "port"), 0),
        (("project", "services", "database", "port"), 65536),
        (("project", "services", "database", "port"), True),
        (("project", "services", "database", "port"), "15443"),
        (("project", "services", "database", "public"), 1),
        (("project", "services", "database", "public"), "false"),
        (("project", "services", "database", "protocol"), "ssh"),
        (("project", "services", "database", "url"), "https://database.member.example:15443"),
        (("project", "services", "database", "target"), "private target"),
        (("project", "services", "api", "url"), "https://api.member.example:1234"),
        (("project", "services", "web", "url"), "https://web.member.example"),
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
        (("public_url",), "https://web.member.example"),
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
        await publication.close()

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
    "case", ["invalid-name", "too-many", "wrong-scope", "non-http-app", "missing-own", "hidden-own"]
)
def test_rejects_invalid_service_set_or_scope(
    native_app_assignment: dict[str, object], case: str
) -> None:
    project = cast(dict[str, object], native_app_assignment["project"])
    services = cast(dict[str, dict[str, object]], project["services"])
    if case == "invalid-name":
        services["invalid name"] = services.pop("database")
    elif case == "too-many":
        services.update({f"service-{index}": services["database"] for index in range(33)})
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


@pytest.mark.parametrize(
    ("port", "public", "omit_service"),
    [
        (443, True, False),
        (25443, True, False),
        (25443, False, False),
        (25443, False, True),
        (1, False, False),
        (65535, True, False),
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
                publication = await tnl.prepare(directory=tmp_path, service="web")
                try:
                    assert publication.service == "web"
                    assert publication.hostname == ("" if omit_service else "web.member.example")
                    assert publication.public_url == (
                        ""
                        if omit_service
                        else "https://web.member.example" + (f":{port}" if port != 443 else "")
                    )
                    await publication.register("http://127.0.0.1:8000")
                    native = NativeRuntime()
                    status = await native.request(endpoint, "status")
                    assert isinstance(status, dict)
                    assert status["services"][0]["registered"] is True
                    assert status["services"][0]["target"] == "http://127.0.0.1:8000"
                    await native.request(endpoint, "renew", publication._registration())
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
