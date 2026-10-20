import { tnl } from "@tnldotdev/tnl";

tnl.port satisfies number;
tnl.dev satisfies boolean;
const service = tnl.services.anyService;
if (service) {
  service.metadata.hostname satisfies string;
  service.metadata.port satisfies number;
  service.metadata.public satisfies boolean;
  if (service.metadata.protocol === "http" || service.metadata.protocol === "kubernetes") {
    service.metadata.url satisfies `https://${string}`;
  }
  // @ts-expect-error browser-safe metadata never contains native TLS keys.
  void service.metadata.ssl;
}
// @ts-expect-error there is no separate server entrypoint.
void import("@tnldotdev/tnl/server");
