"""optional real-native connection boundary fixtures."""

from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--tnl-binary", help="built native tnl for connection contract checks")
    parser.addoption("--tnl-connection-owner", help="built native connection owner test fixture")


@pytest.fixture
def native_connections(request: pytest.FixtureRequest) -> tuple[Path, Path]:
    binary = request.config.getoption("--tnl-binary")
    owner = request.config.getoption("--tnl-connection-owner")
    if not isinstance(binary, str) or not isinstance(owner, str):
        pytest.skip("pass --tnl-binary and --tnl-connection-owner for the real native CLI boundary")
    return Path(binary).resolve(strict=True), Path(owner).resolve(strict=True)
