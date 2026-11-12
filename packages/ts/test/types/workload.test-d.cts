// @ts-expect-error the retired source registry is not a CommonJS alias either.
import type * as RetiredWorkload from "@tnldotdev/tnl/workload";
import type { IdentitySource } from "@tnldotdev/tnl";
import type * as Vitest from "vitest";
declare const test: typeof Vitest.test;

test("CommonJS environment clients use the same explicit source-only identity", () => {
  const accepts = (_source: IdentitySource) => {};
  accepts({ kind: "oidc", permission_id: "permission", assertion: async () => "assertion" });
  accepts({
    kind: "registered-key",
    permission_id: "permission",
    assertion: async () => "token",
    // @ts-expect-error CommonJS cannot configure provider policy either.
    services: ["inventory"],
  });
});
