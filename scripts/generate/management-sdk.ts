import { createClient } from "@hey-api/openapi-ts";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { operationInventory, record, repositoryGraph, root } from "./api-contracts.ts";

// this is the public runtime management boundary, not a second control contract.
// the stock generator owns schema parsing, dependency pruning, and runtime code.
export const managementOperations: Readonly<Record<string, readonly [string, string]>> = {
  createDeployment: ["deployments", "create"],
  listDeployments: ["deployments", "list"],
  getDeployment: ["deployments", "get"],
  updateDeployment: ["deployments", "update"],
  deleteDeployment: ["deployments", "delete"],
  createDeploymentPublisherEnrollment: ["publishers", "createEnrollment"],
  listDeploymentPublishers: ["publishers", "list"],
  getDeploymentPublisher: ["publishers", "get"],
  revokeDeploymentPublisher: ["publishers", "revoke"],
};

export async function generateManagementSDK(): Promise<void> {
  const graph = await repositoryGraph();
  const document = graph.browserBundle("controlv1", []);
  const operations = operationInventory(document).filter((operation) =>
    Object.hasOwn(managementOperations, operation.operationId),
  );
  if (operations.length !== Object.keys(managementOperations).length) {
    throw new Error("the management SDK allowlist does not match the canonical operations");
  }
  // select canonical operations without changing their schemas. Hey API parses
  // path-level parameters before applying its operation filter, so retaining
  // unrelated empty paths leaves references to deliberately pruned components.
  const paths: Record<string, Record<string, unknown>> = {};
  for (const { method, path } of operations) {
    const item = record(record(document.paths)[path]);
    paths[path] ??= item.parameters === undefined ? {} : { parameters: item.parameters };
    paths[path][method] = item[method];
  }
  const output = resolve(root, "packages/ts/src/internal/management");
  const jobs = await createClient({
    input: { ...document, paths },
    output: {
      path: output,
      module: { extension: ".js" },
      header: [
        "// generated from contracts/control/public/v1 with @hey-api/openapi-ts; do not edit.",
      ],
    },
    parser: {
      filters: {
        operations: {
          include: operations.map(({ method, path }) => `${method.toUpperCase()} ${path}`),
        },
        parameters: { include: ["TeamIDQuery"] },
        orphans: false,
      },
    },
    plugins: [
      "@hey-api/typescript",
      {
        name: "zod",
        definitions: { name: "{{name}}Schema", case: "camelCase" },
        requests: false,
        responses: { name: "{{name}}ResponseSchema" },
        dates: { offset: true },
        $resolvers: {
          number(ctx) {
            if (ctx.schema.format === "int64" || ctx.schema.format === "uint64") {
              ctx.schema = { ...ctx.schema, format: undefined };
            }
          },
          object(ctx) {
            const additional = ctx.schema.additionalProperties;
            if (additional && additional.type === "never") {
              return ctx.$(ctx.plugin.imports.z).attr("strictObject").call(ctx.nodes.shape(ctx));
            }
            return undefined;
          },
        },
      },
      {
        name: "@hey-api/sdk",
        client: false,
        validator: { request: false, response: true },
        operations: {
          methods: "static",
          containerName: { casing: "camelCase" },
          segmentName: { casing: "camelCase" },
          strategy(operation) {
            const location = managementOperations[operation.operationId ?? ""];
            if (location === undefined) throw new Error("unapproved management SDK operation");
            return [location];
          },
        },
      },
      { name: "@hey-api/client-fetch", baseUrl: false },
    ],
  });
  if (jobs.length !== 1) throw new Error("expected one management SDK generation result");
  execFileSync("pnpm", ["exec", "oxfmt", "--write", output], { cwd: root, stdio: "inherit" });
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await generateManagementSDK();
}
