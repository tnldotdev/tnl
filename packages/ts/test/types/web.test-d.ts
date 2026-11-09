import { createTnl, type TnlHTTPConnection, type TnlClientFactory } from "@tnldotdev/tnl/web";
import { expectTypeOf, test } from "vitest";

test("web uses ordinary client callbacks without native APIs", async () => {
  const app = createTnl({ credential: "supplied by the environment" });
  const connection = await app.connect("https://app.example");
  expectTypeOf(connection).toEqualTypeOf<TnlHTTPConnection>();
  const get = app.client("https://app.example", {
    create: (settings) => ({ fetch: settings.fetch }),
    close: async () => {},
  });
  expectTypeOf(get).toEqualTypeOf<TnlClientFactory<{ fetch: TnlHTTPConnection["fetch"] }>>();
  // @ts-expect-error native publishing is not a web runtime operation.
  app.publish(() => new Response("app"));
  // @ts-expect-error this layer requires an explicit HTTPS origin.
  app.connect("database");
  await app.close();
});
