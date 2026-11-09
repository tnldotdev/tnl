import { createTnl, type TnlApplicationCredential, type TnlHTTPConnection } from "@tnldotdev/tnl";
import { expectTypeOf, test } from "vitest";

test("native instances select explicit HTTP resources with the same helper types", async () => {
  const app = createTnl({ credential: "supplied by the environment" });
  expectTypeOf(app.connect("https://app.example")).toEqualTypeOf<TnlHTTPConnection>();
  const get = app.client("https://app.example", {
    create(connection) {
      expectTypeOf(connection).toEqualTypeOf<TnlHTTPConnection>();
      return connection.fetch;
    },
    close: async () => {},
  });
  expectTypeOf(await get()).toEqualTypeOf<TnlHTTPConnection["fetch"]>();
  await app.close();
});

declare const credential: TnlApplicationCredential;
test("native application documents select the same exact async HTTP boundary", async () => {
  const app = createTnl({ credential });
  expectTypeOf(app.connect("url_selected")).toEqualTypeOf<Promise<TnlHTTPConnection>>();
  const get = app.client("svc_selected", {
    create: (settings) => {
      expectTypeOf(settings).toEqualTypeOf<TnlHTTPConnection>();
      return settings.fetch;
    },
    close: async () => {},
  });
  expectTypeOf(await get()).toEqualTypeOf<TnlHTTPConnection["fetch"]>();
  // @ts-expect-error exact application grants cannot select personal project state.
  app.connect("database");
  // @ts-expect-error application grants cannot select origins without a resource ID.
  app.connect("https://app.example");
  expectTypeOf(app.publish(() => new Response("app"), { resource: "url_selected" })).toEqualTypeOf<
    Promise<import("@tnldotdev/tnl").Publication>
  >();
  // @ts-expect-error this publication path selects saved HTTP public URLs, not services.
  app.publish(() => new Response("app"), { resource: "svc_selected" });
  await app.close();
});
