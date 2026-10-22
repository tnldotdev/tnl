import type * as Workload from "@tnldotdev/tnl/workload";

declare const workload: typeof Workload;

workload.configureWorkload({ name: "worker", token: async () => "request-scoped-assertion" });
// @ts-expect-error CommonJS cannot configure provider policy either.
workload.configureWorkload({ name: "worker", token: async () => "token", services: ["inventory"] });
