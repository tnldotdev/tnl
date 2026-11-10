import type * as Runtime from "@tnldotdev/tnl";
import type * as Vitest from "vitest";
declare const test: typeof Vitest.test;

declare const runtime: typeof Runtime;

test("CommonJS workload consumers use the same source-only API", () => {
  runtime.createTnl({
    credential: { workload: "worker", token: async () => "request-scoped-assertion" },
  });
  runtime.createTnl({
    credential: {
      workload: "worker",
      token: async () => "token",
      // @ts-expect-error CommonJS cannot configure provider policy either.
      services: ["inventory"],
    },
  });
});
