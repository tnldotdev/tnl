"""private visitor TLS material shared by the publication handles."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ._protocol import InvalidResponse, TnlError, object_value


@dataclass(frozen=True, slots=True)
class ServiceCertificate:
    certificate_pem: str = field(repr=False)
    private_key_pem: str = field(repr=False)


type ServiceCertificateSource = (
    ServiceCertificate | Callable[[], ServiceCertificate | Awaitable[ServiceCertificate]]
)


@dataclass(frozen=True, slots=True)
class ExportedCertificate:
    certificate: ServiceCertificate
    expires_at: int  # installed certificate deadline in Unix milliseconds


def certificate_unavailable() -> TnlError:
    return TnlError(
        "sdk.certificate_unavailable", "the publication has no valid installed certificate"
    )


def _valid(certificate: ServiceCertificate) -> bool:
    return (
        isinstance(certificate.certificate_pem, str)
        and 0 < len(certificate.certificate_pem.encode()) <= 128 << 10
        and isinstance(certificate.private_key_pem, str)
        and 0 < len(certificate.private_key_pem.encode()) <= 16 << 10
    )


async def resolve_certificate(source: ServiceCertificateSource) -> ServiceCertificate:
    try:
        result = source() if callable(source) else source
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, ServiceCertificate) and _valid(result):
            return result
    except Exception:
        # a supplier's error can contain private key material.
        pass
    raise TnlError("sdk.certificate_invalid", "the supplied certificate and key are invalid")


def certificate_payload(certificate: ServiceCertificate) -> dict[str, str]:
    return {
        "certificate_pem": certificate.certificate_pem,
        "private_key_pem": certificate.private_key_pem,
    }


def parse_installed_certificate(value: object) -> ExportedCertificate:
    result = object_value(value, {"certificate", "expires_at"})
    body = object_value(result.get("certificate"), {"certificate_pem", "private_key_pem"})
    chain, key, deadline = (
        body.get("certificate_pem"),
        body.get("private_key_pem"),
        result.get("expires_at"),
    )
    if not isinstance(chain, str) or not isinstance(key, str) or type(deadline) is not int:
        raise InvalidResponse()
    certificate = ServiceCertificate(chain, key)
    try:
        if not 0 < deadline <= (1 << 53) - 1 or not _valid(certificate):
            raise InvalidResponse()
    except UnicodeError:
        raise InvalidResponse() from None
    return ExportedCertificate(certificate, deadline)
