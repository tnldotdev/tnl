import {
  createTnl,
  type TnlApplicationCredential,
  type TnlHTTPConnection,
  type TnlClientFactory,
} from "@tnldotdev/tnl/web";
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

declare const credential: TnlApplicationCredential;
test("application documents select async exact-resource HTTP settings", async () => {
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
  // @ts-expect-error application credentials require an exact resource ID, not a hostname.
  app.connect("https://app.example");
  // @ts-expect-error resource names do not select application grants.
  app.connect("database");
  // @ts-expect-error token instances require explicit origins, not resource IDs.
  createTnl({ credential: "visitor-token" }).connect("url_selected");
  await app.close();
});
