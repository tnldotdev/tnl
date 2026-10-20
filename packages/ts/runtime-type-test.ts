import { tnl } from "@tnldotdev/tnl";

tnl.port satisfies number;
tnl.dev satisfies boolean;
const service = tnl.services.anyService;
if (service) {
  service.hostname satisfies string;
  service.port satisfies number;
  service.public satisfies boolean;
  if (service.protocol === "http" || service.protocol === "kubernetes") {
    service.url satisfies `https://${string}`;
  }
  // @ts-expect-error browser-safe metadata never contains native TLS keys.
  void service.ssl;
}
// @ts-expect-error there is no separate server entrypoint.
void import("@tnldotdev/tnl/server");
