"""bind generated Python models to native's existing generated Go HTTP client."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass

from pydantic import BaseModel

from . import models
from ._connections import _command, _error, _object
from ._native import native_binary
from ._protocol import TnlError


class ManagementError(TnlError):
    def __init__(self, status: int, problem: models.Problem) -> None:
        super().__init__(
            "sdk.management_rejected", "control rejected the deployment management request"
        )
        self.status = status
        self.problem = problem


@dataclass(frozen=True, slots=True, repr=False)
class SavedDeployment:
    data: models.Deployment
    etag: str


def _validated[M: BaseModel](model: type[M], value: object) -> M:
    try:
        return model.model_validate_json(json.dumps(value), strict=True)
    except (ValueError, TypeError):
        raise _error("invalid") from None


def _body[M: BaseModel](model: type[M], value: M | Mapping[str, object]) -> dict[str, object]:
    parsed = _validated(
        model,
        value.model_dump(mode="json", by_alias=True, exclude_unset=True)
        if isinstance(value, model)
        else value,
    )
    return parsed.model_dump(mode="json", by_alias=True, exclude_unset=True)


class Management:
    def __init__(self, project: str, token: str | None) -> None:
        self._project, self._token = project, token

    async def request(self, operation: str, **inputs: object) -> dict[str, object]:
        if self._token is None:
            raise TnlError("sdk.configuration_invalid", "supply an approved deployment credential")

        async def invoke() -> dict[str, object]:
            raw = await asyncio.to_thread(
                _command,
                native_binary(),
                "management",
                input_value={
                    "schema": 1,
                    "project": self._project,
                    "token": self._token,
                    "operation": operation,
                    **inputs,
                },
            )
            return self._response(raw)

        work = asyncio.create_task(invoke())
        canceled = None
        # cancellation does not abandon a mutation or its bounded native worker.
        # join even after repeated cancellation and retain an independent failure.
        while not work.done():
            try:
                await asyncio.shield(work)
            except asyncio.CancelledError as error:
                canceled = canceled or error
            except BaseException:
                break
        try:
            result = work.result()
        except BaseException as failure:
            if canceled is not None:
                raise BaseExceptionGroup(
                    "management cancellation and operation failed", [canceled, failure]
                ) from None
            raise
        if canceled is not None:
            raise canceled
        return result

    @staticmethod
    def _response(raw: object) -> dict[str, object]:
        result = _object(raw, {"schema", "data", "etag", "status", "problem"})
        if type(result.get("schema")) is not int or result["schema"] != 1:
            raise _error("invalid")
        if "status" in result:
            status = result["status"]
            if type(status) is not int or not 400 <= status <= 599:
                raise _error("invalid")
            problem = _validated(models.Problem, result.get("problem"))
            if problem.status != status or "data" in result or "etag" in result:
                raise _error("invalid")
            raise ManagementError(status, problem)
        if "problem" in result:
            raise _error("invalid")
        return result

    @staticmethod
    def saved(result: dict[str, object]) -> SavedDeployment:
        etag = result.get("etag")
        if not isinstance(etag, str) or re.fullmatch(r'"[1-9][0-9]*"', etag) is None:
            raise _error("invalid")
        deployment = _validated(models.Deployment, result.get("data"))
        if etag != f'"{deployment.revision}"':
            raise _error("invalid")
        return SavedDeployment(deployment, etag)


class Deployments:
    def __init__(self, management: Management) -> None:
        self._management = management

    async def create(
        self, body: models.CreateDeploymentRequest | Mapping[str, object], *, idempotency_key: str
    ) -> SavedDeployment:
        return self._management.saved(
            await self._management.request(
                "deployments.create",
                body=_body(models.CreateDeploymentRequest, body),
                idempotency_key=idempotency_key,
            )
        )

    async def list(self, *, after: str = "", limit: int = 50) -> models.DeploymentPage:
        result = await self._management.request("deployments.list", after=after, limit=limit)
        return _validated(models.DeploymentPage, result.get("data"))

    async def get(self, deployment: str) -> SavedDeployment:
        return self._management.saved(
            await self._management.request("deployments.get", deployment=deployment)
        )

    async def update(
        self,
        deployment: str,
        body: models.UpdateDeploymentRequest | Mapping[str, object],
        *,
        if_match: str,
    ) -> SavedDeployment:
        return self._management.saved(
            await self._management.request(
                "deployments.update",
                deployment=deployment,
                body=_body(models.UpdateDeploymentRequest, body),
                if_match=if_match,
            )
        )

    async def delete(self, deployment: str, *, if_match: str) -> None:
        await self._management.request(
            "deployments.delete", deployment=deployment, if_match=if_match
        )


class Publishers:
    def __init__(self, management: Management) -> None:
        self._management = management

    async def create_enrollment(
        self,
        deployment: str,
        body: models.CreateDeploymentPublisherEnrollmentRequest | Mapping[str, object],
        *,
        idempotency_key: str,
    ) -> models.DeploymentPublisherEnrollment:
        result = await self._management.request(
            "publishers.create_enrollment",
            deployment=deployment,
            body=_body(models.CreateDeploymentPublisherEnrollmentRequest, body),
            idempotency_key=idempotency_key,
        )
        return _validated(models.DeploymentPublisherEnrollment, result.get("data"))

    async def list(
        self, deployment: str, *, after: str = "", limit: int = 50
    ) -> models.DeploymentPublisherPage:
        result = await self._management.request(
            "publishers.list", deployment=deployment, after=after, limit=limit
        )
        return _validated(models.DeploymentPublisherPage, result.get("data"))

    async def get(self, deployment: str, publisher: str) -> models.DeploymentPublisher:
        result = await self._management.request(
            "publishers.get", deployment=deployment, publisher=publisher
        )
        return _validated(models.DeploymentPublisher, result.get("data"))

    async def revoke(self, deployment: str, publisher: str) -> None:
        await self._management.request(
            "publishers.revoke", deployment=deployment, publisher=publisher
        )
