"""compose publication with an explicit deployment or publisher owner."""

from typing import Literal, overload

from starlette.types import ASGIApp

from ._asgi import AccessPolicy, Limits, Publication
from ._certificate import ServiceCertificateSource
from ._deployments import Deployment
from ._protocol import TnlError
from ._publisher import Publisher


@overload
async def publish(
    owner: Deployment | Publisher,
    name: str,
    app: ASGIApp,
    *,
    telemetry: bool = True,
    certificate: ServiceCertificateSource | None = None,
) -> Publication: ...


@overload
async def publish(
    owner: Deployment,
    name: ASGIApp,
    *,
    access: Literal["restricted", "anonymous"] | AccessPolicy | None = None,
    limits: Limits | None = None,
    require_post_quantum: bool | None = None,
    public: bool | None = None,
    telemetry: bool = True,
    certificate: ServiceCertificateSource | None = None,
) -> Publication: ...


async def publish(
    owner: Deployment | Publisher,
    name: str | ASGIApp,
    app: ASGIApp | None = None,
    *,
    access: Literal["restricted", "anonymous"] | AccessPolicy | None = None,
    limits: Limits | None = None,
    require_post_quantum: bool | None = None,
    public: bool | None = None,
    telemetry: bool = True,
    certificate: ServiceCertificateSource | None = None,
) -> Publication:
    """publish a named service, or an approved temporary service on a deployment."""
    if isinstance(owner, Publisher):
        if (
            not isinstance(name, str)
            or app is None
            or any(value is not None for value in (access, limits, require_post_quantum, public))
        ):
            raise TnlError("sdk.configuration_invalid", "an enrolled publisher needs a named app")
        return await owner.publish(name, app, telemetry=telemetry, certificate=certificate)
    return await owner.publish(
        name,
        app,
        access=access,
        limits=limits,
        require_post_quantum=require_post_quantum,
        public=public,
        telemetry=telemetry,
        certificate=certificate,
    )
