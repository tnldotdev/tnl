import { deployment, publish, response, type Publication } from "@tnldotdev/tnl/browser";
import { durablePublisher } from "@tnldotdev/tnl/cloudflare";
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

test("durable convenience construction requires no fake deployment factory", () => {
  expectTypeOf<Parameters<typeof durablePublisher>[1]>().not.toHaveProperty("createDeployment");
  expectTypeOf<Parameters<typeof durablePublisher>[1]>().toHaveProperty("identity");
  expectTypeOf(response("body")).toEqualTypeOf<Response>();
});
