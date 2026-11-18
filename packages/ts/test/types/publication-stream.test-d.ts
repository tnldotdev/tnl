import { deployment, publish, response, type Publication } from "@tnldotdev/tnl/browser";
import {
  publisher,
  publish as publishWorker,
  type WorkerPublication,
} from "@tnldotdev/tnl/cloudflare";
import { expectTypeOf, test } from "vitest";

test("browser publications retain the existing handle and exact HTTP service names", async () => {
  const selectedDeployment = deployment("production", {
    project: "acme/shop",
    token: "private",
    services: { web: { protocol: "http" }, database: { protocol: "postgres" } },
  });
  const handler = (request: Request) => response(request.url);
  expectTypeOf(await publish(selectedDeployment, "web", handler)).toEqualTypeOf<Publication>();
  expectTypeOf(
    await publish(selectedDeployment, handler, {
      access: "anonymous",
      limits: { concurrency: 3 },
    }),
  ).toEqualTypeOf<Publication>();
  // @ts-expect-error a fetch handler cannot publish a postgres declaration.
  publish(selectedDeployment, "database", handler);
  // @ts-expect-error service facts still constrain named publication selections.
  publish(selectedDeployment, "missing", handler);
  // @ts-expect-error a temporary visitor policy cannot replace a named policy.
  publish(selectedDeployment, "web", handler, { access: "anonymous" });
  await selectedDeployment.close();
});

test("worker publication selects a named target without a custom runtime factory", async () => {
  const owner = await publisher({ exports: {} }, { enrollment: () => "enrollment" });
  expectTypeOf(await publishWorker(owner, "web")).toEqualTypeOf<WorkerPublication>();
  expectTypeOf(
    await publishWorker(owner, "admin", { entrypoint: "Admin" }),
  ).toEqualTypeOf<WorkerPublication>();
  // @ts-expect-error a worker publication selects a durable target, not a callback.
  publishWorker(owner, "web", () => new Response());
  // @ts-expect-error select exactly one target.
  publishWorker(owner, "web", { entrypoint: "Admin", binding: "API" });
  expectTypeOf(response("body")).toEqualTypeOf<Response>();
});
