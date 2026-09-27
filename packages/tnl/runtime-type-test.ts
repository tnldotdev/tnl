import { tnl } from "@tnldotdev/tnl";

tnl.port satisfies number;
tnl.dev satisfies boolean;
// @ts-expect-error Metadata may be absent until narrowed.
tnl.namespace satisfies string;
// @ts-expect-error Service metadata also requires narrowing.
void tnl.services.anyService;

if (tnl.namespace && tnl.services) {
  tnl.namespace satisfies string;
  tnl.services.anyService satisfies
    | import("./dist/internal/runtime.js").ProjectServiceMetadata
    | undefined;
  tnl.dev satisfies boolean;

  const service = tnl.services.anyService;
  // @ts-expect-error Arbitrary services may be absent even when metadata exists.
  service.hostname satisfies string;
  if (service) {
    service.hostname satisfies string;
    service.url satisfies `https://${string}`;
    // @ts-expect-error Service fields are readonly.
    service.hostname = "other.example";
    // @ts-expect-error Service URLs are readonly.
    service.url = "https://other.example";
  }

  // @ts-expect-error Project metadata is readonly.
  tnl.namespace = "other.example";
  // @ts-expect-error The services collection is readonly.
  tnl.services = {};
  // @ts-expect-error Service entries are readonly.
  tnl.services.anyService = service;
  // @ts-expect-error Runtime lifecycle metadata is readonly.
  tnl.dev = false;

  // @ts-expect-error Project metadata is exposed directly.
  void tnl.project;
  // @ts-expect-error Services are properties, not a lookup helper.
  tnl.service("api");
  // @ts-expect-error There is no separate public tunnel value.
  void tnl.tunnel;
}
