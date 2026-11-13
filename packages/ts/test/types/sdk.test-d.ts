import { tnl, createClient } from "@tnldotdev/tnl";
import { assertType, test } from "vitest";

test("publication belongs to a captured deployment and keeps framework options separate", () => {
  const deployment = createClient({ project: "acme/shop", token: "private" }).deployment(
    "production",
  );
  const handler = () => new Response("app");
  assertType<Promise<import("@tnldotdev/tnl").Publication>>(deployment.publish(handler));
  void deployment.publish(handler, { access: { ip: ["127.0.0.1"] } });
  void tnl.prepare({ service: "web", directory: "/project", stateDir: "/private/client" });

  // @ts-expect-error publication has no unscoped compatibility facade.
  tnl.open(handler);
  // @ts-expect-error authority belongs to the captured deployment, not a second identity.
  deployment.publish(handler, { publisherCredentialFile: "/private/publisher.json" });
  // @ts-expect-error enrollment is an explicit native setup operation.
  void deployment.publish(handler, { enrollmentKey: "key" });
  // @ts-expect-error publication credentials were removed.
  void deployment.publish(handler, { credential: "old" });
  // @ts-expect-error use access.ip for visitor IP settings.
  void deployment.publish(handler, { allowIP: ["127.0.0.1"] });
});
