import { createTnl, type TnlWorkloadCredential } from "@tnldotdev/tnl";
import { assertType, expectTypeOf, test } from "vitest";
import type { ServiceID, WorkloadSessionID, TransportID } from "../../src/internal/values.js";

declare const serviceID: ServiceID;

test("workload credentials select a readonly instance-owned request source", () => {
  const credential: TnlWorkloadCredential = {
    workload: "worker",
    token: async () => "request-scoped-assertion",
  };
  expectTypeOf(createTnl({ credential }).close()).toEqualTypeOf<Promise<void>>();
  createTnl({ credential: { workload: "job", tokenFile: "/run/current-job.jwt" } });
  createTnl({ credential: { workload: "job" } });
  // @ts-expect-error callback setup is readonly.
  credential.workload = "another";
  // @ts-expect-error static tokens are not a runtime source.
  createTnl({ credential: { workload: "worker", token: "global-token" } });
  // @ts-expect-error select one acquisition source.
  createTnl({ credential: { workload: "worker", token: async () => "token", tokenFile: "token" } });
  createTnl({
    // @ts-expect-error saved policy owns issuer and permissions.
    credential: { workload: "worker", token: async () => "token", issuer: "https://untrusted" },
  });
  // @ts-expect-error no top-level workload configuration alias.
  createTnl({ workload: { name: "worker", token: async () => "token" } });
});

test("validated identifiers preserve their prefixes and cannot be interchanged", () => {
  assertType<`svc_${string}`>(serviceID);
  expectTypeOf<string>().not.toExtend<ServiceID>();
  expectTypeOf<`svc_${string}`>().not.toExtend<ServiceID>();
  expectTypeOf<ServiceID>().not.toExtend<WorkloadSessionID>();
  expectTypeOf<TransportID>().not.toExtend<WorkloadSessionID>();
});
