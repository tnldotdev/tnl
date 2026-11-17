import { deployment, publish, tnl, type Publication } from "@tnldotdev/tnl/node";
import { assertType, test } from "vitest";

test("deployment publication keeps saved policy and captured authority separate", () => {
  const production = deployment("production", {
    project: "shop/checkout",
    services: { web: { protocol: "http" }, db: { protocol: "postgres" } },
  });
  const handler = () => new Response("app");
  assertType<Promise<Publication>>(publish(production, "web", handler));
  assertType<Promise<Publication>>(publish(production, handler, { access: { ip: ["127.0.0.1"] } }));
  void tnl.prepare({ service: "web", directory: "/project", stateDir: "/private/client" });
  // @ts-expect-error the unscoped publication surface was removed.
  void tnl.open(handler);
  // @ts-expect-error only HTTP services can be published.
  void publish(production, "db", handler);
  // @ts-expect-error named publication uses saved visitor policy.
  void publish(production, "web", handler, { access: "anonymous" });
  // @ts-expect-error authority is captured by the deployment.
  void publish(production, handler, { token: "other" });
  // @ts-expect-error the working directory is captured by the deployment.
  void publish(production, handler, { directory: "/other" });
  // @ts-expect-error publication identities are not per-call options.
  void publish(production, handler, { publisherCredentialFile: "/private/file" });
  void publish(deployment("production", { project: "shop/checkout" }), "web", handler);
});
