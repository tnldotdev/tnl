import { configureWorkload, type WorkloadOptions } from "@tnldotdev/tnl/workload";
import { assert, assertType, expectTypeOf, test } from "vitest";
import type { Workload, WorkloadSession } from "../../src/internal/connector/workload/contract.js";
import type { ServiceID, WorkloadSessionID, TransportID } from "../../src/internal/values.js";

declare const workload: Workload;
declare const session: WorkloadSession;
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

test("GitHub acquisition carries its audience without optional-field checks", () => {
  assert(workload.provider === "github");
  expectTypeOf(workload.acquisition.method).toEqualTypeOf<"github-actions">();
  expectTypeOf(workload.acquisition.audience).toEqualTypeOf<string>();
  expectTypeOf(workload.acquisition).not.toHaveProperty("token_file");
});

test("OIDC acquisition narrows the token file independently of the provider", () => {
  assert(workload.provider === "oidc");
  assert(workload.acquisition.method === "token-file");
  expectTypeOf(workload.acquisition.token_file).toEqualTypeOf<string>();
  expectTypeOf(workload.acquisition.audience).toEqualTypeOf<string>();
});

test("Vercel acquisition carries no token file or audience", () => {
  assert(workload.provider === "vercel");
  expectTypeOf(workload.acquisition.method).toEqualTypeOf<"vercel-oidc">();
  expectTypeOf(workload.acquisition).not.toHaveProperty("audience");
  expectTypeOf(workload.acquisition).not.toHaveProperty("token_file");
});

test("only GitHub sessions contain verified execution claims", () => {
  assert(session.provider === "github");
  expectTypeOf(session.github.run_id).toEqualTypeOf<string>();
  // @ts-expect-error verified claims cannot be replaced after validation.
  session.github.run_id = "123";
});

test("validated identifiers preserve their prefixes and cannot be interchanged", () => {
  assertType<`svc_${string}`>(serviceID);
  expectTypeOf<string>().not.toExtend<ServiceID>();
  expectTypeOf<`svc_${string}`>().not.toExtend<ServiceID>();
  expectTypeOf<ServiceID>().not.toExtend<WorkloadSessionID>();
  expectTypeOf<TransportID>().not.toExtend<WorkloadSessionID>();
});
