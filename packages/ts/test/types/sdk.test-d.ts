import {
  tnl,
  type PublisherCredentialFile,
  type PublisherIdentityID,
  type PublishOptions,
} from "@tnldotdev/tnl";
import { assertType, test } from "vitest";

test("publication accepts either prepared identity and keeps app options separate", () => {
  const file: PublisherCredentialFile = { publisherCredentialFile: "/private/publisher.json" };
  const stored: PublisherIdentityID = { publisherIdentityID: `pub_${"A".repeat(22)}` };
  const handler = () => new Response("app");
  assertType<Promise<import("@tnldotdev/tnl").Publication>>(tnl.publish(handler));
  void tnl.publish(handler, file);
  void tnl.publish(handler, {
    ...stored,
    stateDir: "/private/client",
    access: { ip: ["127.0.0.1"] },
  });
  void tnl.prepare({ service: "web", directory: "/project", stateDir: "/private/client" });
  // @ts-expect-error publishing has one name, with no compatibility alias.
  void tnl.open(handler);

  // @ts-expect-error a publisher file and stored publisher ID are separate choices.
  const both: PublishOptions = {
    publisherCredentialFile: "/private/publisher.json",
    publisherIdentityID: "id",
  };
  void both;
  // @ts-expect-error enrollment is an explicit native setup operation.
  void tnl.publish(handler, { enrollmentKey: "key" });
  // @ts-expect-error publication credentials were removed.
  void tnl.publish(handler, { credential: "old" });
  // @ts-expect-error use access.ip for visitor IP settings.
  void tnl.publish(handler, { allowIP: ["127.0.0.1"] });
});
