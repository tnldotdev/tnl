"""generated management models, explicit request intent, and joined native calls."""

import asyncio
import copy
import threading
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

import tnl
from tnl import _control, _management_client, models


def http_control(
    monkeypatch: pytest.MonkeyPatch, reply: Callable[[httpx.Request], httpx.Response]
) -> None:
    real_client = httpx.AsyncClient

    def client(*, timeout: int, trust_env: bool, follow_redirects: bool) -> httpx.AsyncClient:
        assert timeout == 30 and not trust_env and not follow_redirects
        return real_client(transport=httpx.MockTransport(reply))

    monkeypatch.setattr(_control.httpx, "AsyncClient", client)


def test_explicit_control_wire_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    base = "/v1/projects/shop/deployments"
    selected = base + "/production"
    assert tnl.control().base_url == "https://control.tnl.dev"

    def reply(request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        calls.append((method, path))
        assert request.url.host == "control.example"
        assert request.headers["authorization"] == "Bearer explicit"
        assert request.url.params["team_id"] == "tm_selected"
        if path == base and method == "GET":
            assert dict(request.url.params) == {
                "team_id": "tm_selected",
                "after": "cursor",
                "limit": "1",
            }
            return httpx.Response(200, json={"deployments": [deployment()]})
        if path == base and method == "POST":
            assert request.headers["idempotency-key"] == "create-1"
            assert request.headers["content-type"] == "application/json"
            return httpx.Response(201, headers={"ETag": '"3"'}, json=deployment())
        if path == selected and method == "PATCH":
            assert request.headers["if-match"] == '"3"'
            conflict = problem(412)["problem"]
            return httpx.Response(
                412, headers={"Content-Type": "application/problem+json"}, json=conflict
            )
        if path == selected and method == "GET":
            return httpx.Response(200, headers={"ETag": '"3"'}, json=deployment())
        if path == selected + "/publishers" and method == "GET":
            return httpx.Response(200, json={"publishers": [publisher()]})
        if path == selected + "/publishers/pub_selected" and method == "DELETE":
            return httpx.Response(204)
        assert path == selected and method == "DELETE"
        assert request.headers["if-match"] == '"3"'
        return httpx.Response(204)

    http_control(monkeypatch, reply)
    monkeypatch.setenv("TNL_TOKEN", "not-used")
    control = tnl.control(auth="explicit", base_url="https://control.example")
    assert "explicit" not in repr(control)
    project = control.project("shop", team_id="tm_selected")

    async def run() -> None:
        result = await project.deployments.create(
            {"name": "production", "targets": {"db": {"address": "db.internal:5432"}}},
            idempotency_key="create-1",
        )
        assert result.etag == '"3"'
        assert await project.deployments.get("production") == result
        page = await project.deployments.list(after="cursor", limit=1)
        assert page.deployments == [result.data]
        with pytest.raises(tnl.ManagementError) as stale:
            await project.deployments.update(
                "production",
                {"targets": {"db": {"address": "db.internal:5432"}}},
                if_match=result.etag,
            )
        assert stale.value.status == 412
        publishers = await project.publishers.list("production")
        assert publishers.publishers[0].publisher_identity_id == "pub_selected"
        await project.publishers.revoke("production", "pub_selected")
        await project.deployments.delete("production", if_match=result.etag)

    asyncio.run(run())
    assert len(calls) == 7


@pytest.mark.parametrize("case", ["redirect", "wrong status", "wrong ETag", "gzip", "large"])
def test_explicit_control_rejects_unexpected_responses(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    calls: list[httpx.Request] = []

    def reply(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if case == "redirect":
            return httpx.Response(302, headers={"Location": "https://different.example/"})
        if case == "wrong status":
            return httpx.Response(201, headers={"ETag": '"3"'}, json=deployment())
        if case == "wrong ETag":
            return httpx.Response(200, headers={"ETag": '"4"'}, json=deployment())
        if case == "gzip":
            return httpx.Response(
                200, headers={"Content-Encoding": "gzip"}, stream=httpx.ByteStream(b"data")
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=httpx.ByteStream(b" " * ((2 << 20) + 1)),
        )

    http_control(monkeypatch, reply)
    project = tnl.control(auth="explicit").project("shop", team_id="tm_selected")
    with pytest.raises(tnl.InvalidResponse):
        asyncio.run(project.deployments.get("production"))
    assert len(calls) == 1


def deployment() -> dict[str, object]:
    return {
        "id": "dpl_0123456789ABCDEFGHIJKL",
        "team_id": "tm_selected",
        "project_key": "shop",
        "name": "production",
        "revision": 3,
        "targets": {"db": {"address": "db.internal:5432", "tls": {"ca": "aws-rds"}}},
        "services": {"db": {"id": "svc_" + "a" * 22, "protocol": "postgres", "trust_revision": 1}},
    }


def publisher() -> dict[str, object]:
    return {
        "team_id": "tm_selected",
        "project_key": "shop",
        "deployment_id": "dpl_0123456789ABCDEFGHIJKL",
        "deployment_name": "production",
        "publisher_identity_id": "pub_selected",
        "key_id": "pkey_selected",
        "observed_revision": "3",
        "current_revision": "3",
        "snapshot_at": "2026-11-13T10:00:00Z",
        "healthy": False,
        "services": {"db": "postgres"},
    }


def problem(status: int) -> dict[str, object]:
    return {
        "schema": 1,
        "status": status,
        "problem": {
            "type": "https://tnl.dev/problems/conflict",
            "title": "deployment changed",
            "status": status,
            "code": "conflict",
            "request_id": "request-selected",
            "detail": "read the current ETag",
        },
    }


def native(
    monkeypatch: pytest.MonkeyPatch, reply: Callable[[dict[str, object]], object]
) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []
    monkeypatch.setattr(_management_client, "native_binary", lambda: Path("/fixture/tnl"))

    def command(binary: Path, *args: str, input_value: object = None) -> object:
        assert binary == Path("/fixture/tnl")
        assert args == ("management",)
        assert isinstance(input_value, dict)
        requests.append(copy.deepcopy(input_value))
        return reply(input_value)

    monkeypatch.setattr(_management_client, "_command", command)
    return requests


def test_generated_inputs_keep_required_fields_and_tagged_json() -> None:
    for value in [{}, {"name": "customer"}, {"targets": {}}]:
        with pytest.raises(ValidationError):
            models.CreateDeploymentRequest.model_validate(value)
    with pytest.raises(ValidationError):
        models.CreateDeploymentPublisherEnrollmentRequest.model_validate({})
    body = models.CreateDeploymentRequest(
        name="customer",
        targets=models.DeploymentTargets(
            {
                "db": models.DeploymentTarget(
                    address="orders.abc.us-east-1.rds.amazonaws.com:5432",
                    tls=models.DeploymentTargetTls(ca="aws-rds"),
                )
            }
        ),
    )
    assert body.model_dump(mode="json", exclude_unset=True) == {
        "name": "customer",
        "targets": {
            "db": {
                "address": "orders.abc.us-east-1.rds.amazonaws.com:5432",
                "tls": {"ca": "aws-rds"},
            }
        },
    }
    parsed = models.Deployment.model_validate(deployment())
    assert parsed.services["db"].protocol == "postgres"
    assert models.Deployment.model_validate_json(parsed.model_dump_json()) == parsed


def test_project_management_preserves_original_keys_conditions_and_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reply(request: dict[str, object]) -> object:
        operation = request["operation"]
        if operation == "deployments.list":
            return {
                "schema": 1,
                "data": {
                    "deployments": [deployment()],
                    "next_cursor": "dpl_0123456789ABCDEFGHIJKM",
                },
            }
        if operation == "deployments.delete":
            return {"schema": 1}
        return {"schema": 1, "etag": '"3"', "data": deployment()}

    requests = native(monkeypatch, reply)

    async def run() -> None:
        client = tnl.create_client(project="acme/shop", token="tnc_private")
        assert not hasattr(client, "credentials")
        body = {"name": "customer", "targets": {"db": {"address": "db.internal:5432"}}}
        created = await client.deployments.create(body, idempotency_key="original")
        recovered = await client.deployments.create(body, idempotency_key="original")
        assert created == recovered
        assert created.data.id == "dpl_0123456789ABCDEFGHIJKL" and created.etag == '"3"'
        assert (await client.deployments.get(created.data.id)) == created
        page = await client.deployments.list(after="dpl_0123456789ABCDEFGHIJKK", limit=1)
        assert (
            page.deployments == [created.data] and page.next_cursor == "dpl_0123456789ABCDEFGHIJKM"
        )
        await client.deployments.update(
            created.data.id, {"targets": {"db": {"address": "changed:5432"}}}, if_match=created.etag
        )
        await client.deployments.delete(created.data.id, if_match=created.etag)

    asyncio.run(run())
    assert requests[0] == requests[1]
    assert requests[0]["idempotency_key"] == "original"
    assert requests[3]["after"] == "dpl_0123456789ABCDEFGHIJKK" and requests[3]["limit"] == 1
    assert requests[4]["if_match"] == requests[5]["if_match"] == '"3"'
    assert all(r["project"] == "acme/shop" and r["token"] == "tnc_private" for r in requests)


def test_publisher_management_returns_real_generated_models(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enrollment = {
        "enrollment_key": "private_setup",
        "enrollment_id": "enrollment-original",
        "deployment_id": "dpl_0123456789ABCDEFGHIJKL",
        "expires_at": "2026-11-13T10:10:00Z",
        "max_members": 1,
        "services": {"db": "postgres"},
    }

    def reply(request: dict[str, object]) -> object:
        match request["operation"]:
            case "publishers.create_enrollment":
                return {"schema": 1, "data": enrollment}
            case "publishers.list":
                return {
                    "schema": 1,
                    "data": {"publishers": [publisher()], "next_cursor": "pub_next"},
                }
            case "publishers.get":
                return {"schema": 1, "data": publisher()}
            case "publishers.revoke":
                return {"schema": 1}
        raise AssertionError("unapproved operation")

    requests = native(monkeypatch, reply)

    async def run() -> None:
        client = tnl.create_client(project="acme/shop", token="tnc_private")
        setup = await client.publishers.create_enrollment(
            "dpl_0123456789ABCDEFGHIJKL", {"services": ["db"]}, idempotency_key="setup-original"
        )
        assert isinstance(setup, models.DeploymentPublisherEnrollment)
        assert setup.enrollment_key == "private_setup" and setup.services == {"db": "postgres"}
        page = await client.publishers.list(
            "dpl_0123456789ABCDEFGHIJKL", after="pub_previous", limit=1
        )
        item = await client.publishers.get("dpl_0123456789ABCDEFGHIJKL", "pub_selected")
        assert isinstance(item, models.DeploymentPublisher) and item == page.publishers[0]
        assert item.healthy is False
        await client.publishers.revoke("dpl_0123456789ABCDEFGHIJKL", "pub_selected")

    asyncio.run(run())
    assert requests[0]["idempotency_key"] == "setup-original"
    assert requests[0]["body"] == {"services": ["db"]}
    assert requests[1]["after"] == "pub_previous"
    assert requests[2]["publisher"] == requests[3]["publisher"] == "pub_selected"


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(revision="3"),
        lambda value: value.update(revision=True),
        lambda value: value.update(unexpected="private"),
        lambda value: value.pop("services"),
        lambda value: value.update(
            services={"db": {"id": "svc_" + "a" * 22, "protocol": "future", "trust_revision": 1}}
        ),
    ],
)
def test_successful_response_is_strict(
    monkeypatch: pytest.MonkeyPatch, change: Callable[[dict[str, object]], object]
) -> None:
    value = deployment()
    change(value)
    native(monkeypatch, lambda _request: {"schema": 1, "etag": '"3"', "data": value})
    with pytest.raises(tnl.TnlError, match="response is invalid"):
        asyncio.run(
            tnl.create_client(project="acme/shop", token="private").deployments.get("production")
        )


@pytest.mark.parametrize("etag", [None, "3", 'W/"3"', '"0"', '"4"'])
def test_saved_deployment_requires_matching_strong_etag(
    monkeypatch: pytest.MonkeyPatch, etag: object
) -> None:
    native(monkeypatch, lambda _request: {"schema": 1, "etag": etag, "data": deployment()})
    with pytest.raises(tnl.TnlError):
        asyncio.run(
            tnl.create_client(project="acme/shop", token="private").deployments.get("production")
        )


@pytest.mark.parametrize("status", [401, 403, 404, 409, 412, 428, 429, 503])
def test_management_preserves_http_problem_without_retry(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    requests = native(monkeypatch, lambda _request: problem(status))
    with pytest.raises(tnl.ManagementError) as failure:
        asyncio.run(
            tnl.create_client(project="acme/shop", token="private").deployments.get("production")
        )
    assert failure.value.status == failure.value.problem.status == status
    assert failure.value.problem.request_id == "request-selected"
    assert len(requests) == 1


@pytest.mark.parametrize("fails", [False, True])
def test_cancellation_joins_worker_and_retains_racing_http_failure(
    monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    async def run() -> None:
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        release = threading.Event()

        def reply(_request: dict[str, object]) -> object:
            loop.call_soon_threadsafe(started.set)
            assert release.wait(5)
            return problem(412) if fails else {"schema": 1, "etag": '"3"', "data": deployment()}

        native(monkeypatch, reply)
        client = tnl.create_client(project="acme/shop", token="private")
        task = asyncio.create_task(client.deployments.get("production"))
        try:
            await asyncio.wait_for(started.wait(), 5)
            for _ in range(2):
                task.cancel()
                observed = loop.create_future()
                loop.call_soon(observed.set_result, None)
                await observed
                assert not task.done(), "cancellation abandoned the native mutation"
        finally:
            release.set()
        if fails:
            with pytest.raises(BaseExceptionGroup) as failure:
                await task
            assert any(
                isinstance(error, asyncio.CancelledError) for error in failure.value.exceptions
            )
            assert any(
                isinstance(error, tnl.ManagementError) and error.status == 412
                for error in failure.value.exceptions
            )
        else:
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(run())
