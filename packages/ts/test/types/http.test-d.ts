import { assertType, test } from "vitest";
import {
  createClient,
  deployments,
  publishers,
  type Deployment,
  type DeploymentPublisher,
  type DeploymentPublisherEnrollment,
} from "@tnldotdev/tnl/http";

test("HTTP operations retain canonical inputs and typed results", async () => {
  const client = createClient({ baseUrl: "https://control.example.test", auth: "scoped-token" });
  const options = {
    client,
    path: { project_key: "shop", deployment: "customer" },
    query: { team_id: "team-shop" },
    throwOnError: true as const,
  };
  assertType<Deployment>((await deployments.get(options)).data);
  assertType<Deployment>(
    (
      await deployments.create({
        ...options,
        headers: { "Idempotency-Key": "original" },
        body: { name: "customer", targets: { db: { address: "db:5432" } } },
      })
    ).data,
  );
  assertType<Deployment>(
    (
      await deployments.update({
        ...options,
        headers: { "If-Match": '"1"' },
        body: { targets: { db: { address: "changed:5432" } } },
      })
    ).data,
  );
  assertType<DeploymentPublisherEnrollment>(
    (
      await publishers.createEnrollment({
        ...options,
        headers: { "Idempotency-Key": "setup" },
        body: { services: ["db"] },
      })
    ).data,
  );
  assertType<DeploymentPublisher>(
    (await publishers.get({ ...options, path: { ...options.path, publisher: "pub_selected" } }))
      .data,
  );
  // @ts-expect-error creation requires the caller's original retry key.
  deployments.create({
    ...options,
    body: { name: "customer", targets: { db: { address: "db:5432" } } },
  });
  deployments.create({
    ...options,
    headers: { "Idempotency-Key": "original" },
    // @ts-expect-error creation requires explicit targets.
    body: { name: "customer" },
  });
  // @ts-expect-error publisher setup requires an explicit service allowlist.
  publishers.createEnrollment({ ...options, headers: { "Idempotency-Key": "setup" }, body: {} });
  // @ts-expect-error credentials are administered outside this runtime SDK.
  publishers.registerCredential(options);
  // @ts-expect-error operations require an explicit isolated transport client.
  deployments.get({ path: options.path, query: options.query });
  deployments.update({
    ...options,
    // @ts-expect-error deployment updates cannot replace project declarations.
    body: { targets: {}, services: { db: { protocol: "mysql" } } },
  });
});
