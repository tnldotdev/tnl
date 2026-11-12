"""generated service facts remain detached from caller state and selection."""

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import assert_type

import pytest

from tnl import PostgresConnection, ServiceFacts, TnlError
from tnl._connections import _decode_snapshot


def test_service_facts_capture_independent_immutable_data() -> None:
    original = {"db": {"protocol": "postgres"}, "api": {"protocol": "http"}}
    services = ServiceFacts(original)
    original["db"]["protocol"] = "http"
    assert services["db"]["protocol"] == "postgres"
    assert list(services) == ["db", "api"]
    with pytest.raises(TypeError):
        services["db"]["protocol"] = "http"  # type: ignore[index]
    with pytest.raises(TypeError):
        services["db"] = {"protocol": "http"}  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        services._services = {}  # type: ignore[misc]


@pytest.mark.parametrize(
    "value",
    [
        None,
        {"db": {"protocol": "unknown"}},
        {"bad/name": {"protocol": "postgres"}},
        {"db": {"protocol": "postgres", "target": "private"}},
        {f"service-{i}": {"protocol": "tcp"} for i in range(129)},
    ],
)
def test_service_facts_reject_invalid_runtime_data(value: object) -> None:
    with pytest.raises(TnlError):
        ServiceFacts(value)  # type: ignore[arg-type]


def wire(protocol: str) -> dict[str, object]:
    return {
        "schema": 1,
        "protocol": protocol,
        "host": "127.0.0.1",
        "port": 15432,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        "transport_id": "ctg_" + "a" * 22,
        **(
            {}
            if protocol == "tcp"
            else {"ssl": {"servername": "service.example", "rejectUnauthorized": True}}
        ),
        **({"url": "https://service.example"} if protocol in {"http", "kubernetes"} else {}),
        **(
            {"kubeconfig": "/private/fixture/kubeconfig", "context": "tnl:cluster"}
            if protocol == "kubernetes"
            else {}
        ),
    }


def test_captured_postgres_facts_reject_internally_valid_http_native_settings() -> None:
    services = ServiceFacts({"db": {"protocol": "postgres"}})
    with pytest.raises(TnlError):
        _decode_snapshot(services["db"]["protocol"], wire("http"))
    db = _decode_snapshot("postgres", wire("postgres"))
    assert_type(db, PostgresConnection)
    assert db.host == "127.0.0.1"
    assert db.port == 15432
    assert db.ssl.check_hostname


@pytest.mark.parametrize("protocol", ["http", "postgres", "mysql", "tcp", "kubernetes"])
def test_each_protocol_decoder_validates_input_and_constructs_matching_settings(
    protocol: str,
) -> None:
    settings = _decode_snapshot(protocol, wire(protocol))
    assert settings.protocol == protocol
    with pytest.raises(TnlError):
        _decode_snapshot(protocol, {**wire(protocol), "password": "application-owned"})
    with pytest.raises(TnlError):
        _decode_snapshot(
            protocol, {**wire(protocol), "expires_at": datetime(2000, 1, 1, tzinfo=UTC).isoformat()}
        )


@pytest.mark.parametrize(
    "changes",
    [{"kubeconfig": "relative"}, {"context": "other"}, {"context": "tnl:" + "a" * 1021}],
)
def test_kubernetes_settings_reject_unbound_local_paths_and_contexts(
    changes: dict[str, object],
) -> None:
    with pytest.raises(TnlError):
        _decode_snapshot("kubernetes", {**wire("kubernetes"), **changes})
