import { configureWorkload, type WorkloadOptions } from "@tnldotdev/tnl/workload";
import { assertType, expectTypeOf, test } from "vitest";
import type { ServiceID, WorkloadSessionID, TransportID } from "../../src/internal/values.js";

declare const serviceID: ServiceID;

test("workload configuration selects a readonly request-scoped source", () => {
  const options: WorkloadOptions = {
    name: "worker",
    token: async () => "request-scoped-assertion",
  };
  expectTypeOf(configureWorkload(options)).toBeVoid();
  configureWorkload({ name: "job", tokenFile: "/run/current-job.jwt" });
  // @ts-expect-error callback setup is readonly.
  options.name = "another";
  // @ts-expect-error static tokens are not a runtime source.
  configureWorkload({ name: "worker", token: "global-token" });
  // @ts-expect-error select one acquisition source.
  configureWorkload({ name: "worker", token: async () => "token", tokenFile: "token" });
  // @ts-expect-error saved policy owns issuer and permissions.
  configureWorkload({ name: "worker", token: async () => "token", issuer: "https://untrusted" });
});

test("validated identifiers preserve their prefixes and cannot be interchanged", () => {
  assertType<`svc_${string}`>(serviceID);
  expectTypeOf<string>().not.toExtend<ServiceID>();
  expectTypeOf<`svc_${string}`>().not.toExtend<ServiceID>();
  expectTypeOf<ServiceID>().not.toExtend<WorkloadSessionID>();
  expectTypeOf<TransportID>().not.toExtend<WorkloadSessionID>();
});
