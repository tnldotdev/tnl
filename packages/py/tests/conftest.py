"""optional real-native boundary fixtures."""

import json
import subprocess
from pathlib import Path
from typing import cast

import pytest


@pytest.fixture(autouse=True)
def isolated_provider_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """provider tests select their own context instead of inheriting the runner."""
    for name in (
        "TNL_CONNECTION_HANDLE",
        "TNL_WORKLOAD",
        "GITHUB_ACTIONS",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "VERCEL",
        "VERCEL_OIDC_TOKEN",
        "VERCEL_OIDC_TOKEN_FILE",
        "FLY_APP_NAME",
    ):
        monkeypatch.delenv(name, raising=False)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--tnl-binary", help="built native tnl for connection contract checks")
    parser.addoption("--tnl-connection-owner", help="built connector owner test fixture")
    parser.addoption("--tnl-app-owner", help="built native configured-app test fixture")


@pytest.fixture(scope="session")
def native_app_owner(request: pytest.FixtureRequest) -> Path:
    owner = request.config.getoption("--tnl-app-owner")
    if not isinstance(owner, str):
        pytest.skip("pass --tnl-app-owner for native configured-app metadata checks")
    return Path(owner).resolve(strict=True)


@pytest.fixture(scope="session")
def native_app_metadata(native_app_owner: Path) -> bytes:
    result = subprocess.run(
        [str(native_app_owner), "-tnl-metadata"], capture_output=True, check=True, timeout=10
    )
    return result.stdout


@pytest.fixture
def native_app_assignment(native_app_metadata: bytes) -> dict[str, object]:
    value: object = json.loads(native_app_metadata)
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


@pytest.fixture
def native_connections(request: pytest.FixtureRequest) -> tuple[Path, Path]:
    binary = request.config.getoption("--tnl-binary")
    owner = request.config.getoption("--tnl-connection-owner")
    if not isinstance(binary, str) or not isinstance(owner, str):
        pytest.skip("pass --tnl-binary and --tnl-connection-owner for the real native CLI boundary")
    return Path(binary).resolve(strict=True), Path(owner).resolve(strict=True)
