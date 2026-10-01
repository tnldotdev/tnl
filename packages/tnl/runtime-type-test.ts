import { tnl } from "@tnldotdev/tnl";

tnl.port satisfies number;
tnl.dev satisfies boolean;
// @ts-expect-error metadata may be absent until narrowed.
tnl.namespace satisfies string;
// @ts-expect-error service metadata also requires narrowing.
void tnl.services.anyService;

if (tnl.namespace && tnl.services) {
  tnl.namespace satisfies string;
  tnl.services.anyService satisfies
    | import("./dist/internal/runtime.js").ProjectServiceMetadata
    | undefined;
  tnl.dev satisfies boolean;

  const service = tnl.services.anyService;
  // @ts-expect-error arbitrary services may be absent even when metadata exists.
  service.hostname satisfies string;
  if (service) {
    service.hostname satisfies string;
    service.url satisfies `https://${string}`;
    // @ts-expect-error service fields are readonly.
    service.hostname = "other.example";
    // @ts-expect-error service URLs are readonly.
    service.url = "https://other.example";
  }

  // @ts-expect-error project metadata is readonly.
  tnl.namespace = "other.example";
  // @ts-expect-error the services collection is readonly.
  tnl.services = {};
  // @ts-expect-error service entries are readonly.
  tnl.services.anyService = service;
  // @ts-expect-error runtime lifecycle metadata is readonly.
  tnl.dev = false;

  // @ts-expect-error project metadata is exposed directly.
  void tnl.project;
  // @ts-expect-error services are properties, not a lookup helper.
  tnl.service("api");
  // @ts-expect-error there is no separate public tunnel value.
  void tnl.tunnel;
}
