import { assertType, test } from "vitest";
import {
  createControlClient,
  createDeployment,
  deleteDeployment,
  getDeployment,
  listDeployments,
  updateDeployment,
  createPublisherEnrollment,
  getPublisher,
  listPublishers,
  revokePublisher,
  type Deployment,
  type DeploymentPublisher,
  type DeploymentPublisherEnrollment,
} from "@tnldotdev/tnl/control";

test("HTTP operations retain canonical inputs and typed results", async () => {
  const client = createControlClient({
    baseUrl: "https://control.example.test",
    auth: "scoped-token",
  });
  const options = {
    client,
    path: { project_key: "shop", deployment: "customer" },
    query: { team_id: "team-shop" },
    throwOnError: true as const,
  };
  assertType<Deployment>((await getDeployment(options)).data);
  assertType<Deployment>(
    (
      await createDeployment({
        ...options,
        headers: { "Idempotency-Key": "original" },
        body: { name: "customer", targets: { db: { address: "db:5432" } } },
      })
    ).data,
  );
  assertType<Deployment>(
    (
      await updateDeployment({
        ...options,
        headers: { "If-Match": '"1"' },
        body: { targets: { db: { address: "changed:5432" } } },
      })
    ).data,
  );
  assertType<DeploymentPublisherEnrollment>(
    (
      await createPublisherEnrollment({
        ...options,
        headers: { "Idempotency-Key": "setup" },
        body: { services: ["db"] },
      })
    ).data,
  );
  assertType<DeploymentPublisher>(
    (await getPublisher({ ...options, path: { ...options.path, publisher: "pub_selected" } })).data,
  );
  for (const headers of [
    new Headers({
      Authorization: "Bearer request-token",
      "Idempotency-Key": "original",
      "If-Match": '"9007199254740993"',
    }),
    [
      ["Authorization", "Bearer request-token"],
      ["Idempotency-Key", "original"],
      ["If-Match", '"9007199254740993"'],
    ] satisfies [string, string][],
  ]) {
    assertType<Deployment>(
      (
        await createDeployment({
          ...options,
          headers,
          body: { name: "customer", targets: { db: { address: "db:5432" } } },
        })
      ).data,
    );
    assertType<DeploymentPublisherEnrollment>(
      (await createPublisherEnrollment({ ...options, headers, body: { services: ["db"] } })).data,
    );
    assertType<Deployment>((await getDeployment({ ...options, headers })).data);
    assertType<Deployment[]>((await listDeployments({ ...options, headers })).data.deployments);
    assertType<Deployment>(
      (
        await updateDeployment({
          ...options,
          headers,
          body: { targets: { db: { address: "changed:5432" } } },
        })
      ).data,
    );
    assertType<DeploymentPublisher[]>(
      (await listPublishers({ ...options, headers })).data.publishers,
    );
    const publisherPath = { ...options.path, publisher: "pub_selected" };
    assertType<DeploymentPublisher>(
      (await getPublisher({ ...options, path: publisherPath, headers })).data,
    );
    assertType<Response>(
      (await revokePublisher({ ...options, path: publisherPath, headers })).response,
    );
    assertType<Response>((await deleteDeployment({ ...options, headers })).response);
  }
  // @ts-expect-error creation requires the caller's original retry key.
  createDeployment({
    ...options,
    body: { name: "customer", targets: { db: { address: "db:5432" } } },
  });
  createDeployment({
    ...options,
    headers: { "Idempotency-Key": "original" },
    // @ts-expect-error creation requires explicit targets.
    body: { name: "customer" },
  });
  createDeployment({
    ...options,
    // @ts-expect-error a header record must still contain the original retry key.
    headers: { Authorization: "Bearer request-token" },
    body: { name: "customer", targets: { db: { address: "db:5432" } } },
  });
  // @ts-expect-error publisher setup requires an explicit service allowlist.
  createPublisherEnrollment({ ...options, headers: { "Idempotency-Key": "setup" }, body: {} });
  // @ts-expect-error credentials are administered outside this runtime SDK.
  registerCredential(options);
  // @ts-expect-error operations require an explicit isolated transport client.
  getDeployment({ path: options.path, query: options.query });
  updateDeployment({
    ...options,
    // @ts-expect-error deployment updates cannot replace project declarations.
    body: { targets: {}, services: { db: { protocol: "mysql" } } },
  });
});
