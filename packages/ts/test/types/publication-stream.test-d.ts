import { createClient, response, type Publication } from "../../dist/index.browser.js";
import { createDurableObjectPublisher } from "../../dist/durable-object.js";
import { expectTypeOf, test } from "vitest";

test("browser publications retain the existing handle and exact HTTP service names", async () => {
  const deployment = createClient({
    project: "acme/shop",
    token: "private",
    services: { web: { protocol: "http" }, database: { protocol: "postgres" } },
  }).deployment("production");
  const handler = (request: Request) => response(request.url);
  expectTypeOf(await deployment.publish("web", handler)).toEqualTypeOf<Publication>();
  expectTypeOf(
    await deployment.publish(handler, {
      access: "anonymous",
      limits: { concurrency: 3 },
    }),
  ).toEqualTypeOf<Publication>();
  // @ts-expect-error a fetch handler cannot publish a postgres declaration.
  deployment.publish("database", handler);
  // @ts-expect-error service facts still constrain named publication selections.
  deployment.publish("missing", handler);
  // @ts-expect-error a temporary visitor policy cannot replace a named policy.
  deployment.publish("web", handler, { access: "anonymous" });
  await deployment.close();
});

test("durable convenience construction requires no fake deployment factory", () => {
  expectTypeOf<Parameters<typeof createDurableObjectPublisher>[1]>().not.toHaveProperty(
    "createDeployment",
  );
  expectTypeOf<Parameters<typeof createDurableObjectPublisher>[1]>().toHaveProperty("identity");
  expectTypeOf(response("body")).toEqualTypeOf<Response>();
});
