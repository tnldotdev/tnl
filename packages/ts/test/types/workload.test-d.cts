import type * as Workload from "@tnldotdev/tnl/workload";
import type * as Vitest from "vitest";
declare const test: typeof Vitest.test;

declare const workload: typeof Workload;

test("CommonJS workload consumers use the same source-only API", () => {
  workload.configureWorkload({ name: "worker", token: async () => "request-scoped-assertion" });
  workload.configureWorkload({
    name: "worker",
    token: async () => "token",
    // @ts-expect-error CommonJS cannot configure provider policy either.
    services: ["inventory"],
  });
});
