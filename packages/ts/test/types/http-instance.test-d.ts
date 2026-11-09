import { createTnl, type TnlHTTPConnection } from "@tnldotdev/tnl";
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
