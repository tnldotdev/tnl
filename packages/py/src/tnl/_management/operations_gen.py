# generated from the public control contract; do not edit.

OPERATIONS: dict[str, tuple[str, str, int]] = {
    "createDeployment": ("POST", "/v1/projects/{project_key}/deployments", 201),
    "createDeploymentPublisherEnrollment": (
        "POST",
        "/v1/projects/{project_key}/deployments/{deployment}/publisher-enrollments",
        201,
    ),
    "deleteDeployment": ("DELETE", "/v1/projects/{project_key}/deployments/{deployment}", 204),
    "getDeployment": ("GET", "/v1/projects/{project_key}/deployments/{deployment}", 200),
    "getDeploymentPublisher": (
        "GET",
        "/v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}",
        200,
    ),
    "listDeploymentPublishers": (
        "GET",
        "/v1/projects/{project_key}/deployments/{deployment}/publishers",
        200,
    ),
    "listDeployments": ("GET", "/v1/projects/{project_key}/deployments", 200),
    "revokeDeploymentPublisher": (
        "DELETE",
        "/v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}",
        204,
    ),
    "updateDeployment": ("PATCH", "/v1/projects/{project_key}/deployments/{deployment}", 200),
}
