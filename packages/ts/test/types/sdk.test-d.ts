import { createClient, tnl, type Publication } from "@tnldotdev/tnl";
import { assertType, test } from "vitest";

test("deployment publication keeps saved policy and captured authority separate", () => {
  const client = createClient({
    project: "shop/checkout",
    services: { web: { protocol: "http" }, db: { protocol: "postgres" } },
  });
  const production = client.deployment("production");
  const handler = () => new Response("app");
  assertType<Promise<Publication>>(production.publish("web", handler));
  assertType<Promise<Publication>>(production.publish(handler, { access: { ip: ["127.0.0.1"] } }));
  void tnl.prepare({ service: "web", directory: "/project", stateDir: "/private/client" });
  // @ts-expect-error the unscoped publication surface was removed.
  void tnl.open(handler);
  // @ts-expect-error only HTTP services can be published.
  void production.publish("db", handler);
  // @ts-expect-error named publication uses saved visitor policy.
  void production.publish("web", handler, { access: "anonymous" });
  // @ts-expect-error authority is captured by the deployment.
  void production.publish(handler, { token: "other" });
  // @ts-expect-error the working directory is captured by the deployment.
  void production.publish(handler, { directory: "/other" });
  // @ts-expect-error publication identities are not per-call options.
  void production.publish(handler, { publisherCredentialFile: "/private/file" });
  void createClient({ project: "shop/checkout" }).deployment("production").publish("web", handler);
});
