import { tnl } from "@tnldotdev/tnl";

// @ts-expect-error Metadata may be absent until narrowed.
void tnl.memberNamespace;
// @ts-expect-error Service metadata also requires narrowing the root value.
void tnl.services.anyService;

if (tnl) {
  tnl.memberNamespace satisfies string;
  tnl.services.anyService.hostname satisfies string;
  tnl.services.anyService.url satisfies `https://${string}`;
  tnl.runningUnderTnlDev satisfies boolean;

  // @ts-expect-error Project metadata is readonly.
  tnl.memberNamespace = "other.example";
  // @ts-expect-error The services collection is readonly.
  tnl.services = {};
  // @ts-expect-error Service entries are readonly.
  tnl.services.anyService = { ...tnl.services.anyService };
  // @ts-expect-error Service fields are readonly.
  tnl.services.anyService.hostname = "other.example";
  // @ts-expect-error Service URLs are readonly.
  tnl.services.anyService.url = "https://other.example";
  // @ts-expect-error Runtime lifecycle metadata is readonly.
  tnl.runningUnderTnlDev = false;

  // @ts-expect-error Project metadata is exposed directly.
  void tnl.project;
  // @ts-expect-error Services are properties, not a lookup helper.
  tnl.service("api");
  // @ts-expect-error There is no separate public tunnel value.
  void tnl.tunnel;
}
