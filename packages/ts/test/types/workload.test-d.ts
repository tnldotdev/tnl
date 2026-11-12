// @ts-expect-error workload configuration is retired, not an alias for a client.
import type * as RetiredWorkload from "@tnldotdev/tnl/workload";
import type { IdentitySource } from "@tnldotdev/tnl";
import { assertType, expectTypeOf, test } from "vitest";
import type { ServiceID, WorkloadSessionID, TransportID } from "../../src/internal/values.js";

declare const serviceID: ServiceID;

test("explicit identity sources are readonly and do not carry authority policy", () => {
  const options: IdentitySource = {
    kind: "oidc",
    permission_id: `mwp_${"a".repeat(22)}`,
    assertion: async () => "request-scoped-assertion",
  };
  expectTypeOf(options.assertion).toBeFunction();
  // @ts-expect-error callback setup is readonly.
  options.permission_id = "another";
  // @ts-expect-error static tokens are not a runtime source.
  options.assertion = "global-token";
  const accepts = (_source: IdentitySource) => {};
  // @ts-expect-error a file is acquired inside the explicit callback, not a second source.
  accepts({ ...options, tokenFile: "token" });
  // @ts-expect-error saved policy owns issuer and permissions.
  accepts({ ...options, issuer: "https://untrusted" });
});

test("validated identifiers preserve their prefixes and cannot be interchanged", () => {
  assertType<`svc_${string}`>(serviceID);
  expectTypeOf<string>().not.toExtend<ServiceID>();
  expectTypeOf<`svc_${string}`>().not.toExtend<ServiceID>();
  expectTypeOf<ServiceID>().not.toExtend<WorkloadSessionID>();
  expectTypeOf<TransportID>().not.toExtend<WorkloadSessionID>();
});
