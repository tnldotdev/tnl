import { configureWorkload, type WorkloadOptions } from "@tnldotdev/tnl/workload";

const options: WorkloadOptions = { name: "worker", token: async () => "request-scoped-assertion" };
configureWorkload(options);
configureWorkload({ name: "job", tokenFile: "/run/current-job.jwt" });
// @ts-expect-error callback setup is readonly.
options.name = "another";
// @ts-expect-error static tokens are not a runtime source.
configureWorkload({ name: "worker", token: "global-token" });
// @ts-expect-error select one acquisition source.
configureWorkload({ name: "worker", token: async () => "token", tokenFile: "token" });
// @ts-expect-error saved policy owns issuer and permissions.
configureWorkload({ name: "worker", token: async () => "token", issuer: "https://untrusted" });
