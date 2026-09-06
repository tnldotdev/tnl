import { tnl } from "@tnldotdev/tnl";

if (tnl) {
  tnl.memberNamespace satisfies string;
  tnl.services.anyService.hostname satisfies string;
  tnl.services.anyService.url satisfies `https://${string}`;
  tnl.runningUnderTnlDev satisfies boolean;

  // @ts-expect-error Project metadata is exposed directly.
  void tnl.project;
  // @ts-expect-error Services are properties, not a lookup helper.
  tnl.service("api");
  // @ts-expect-error There is no separate public tunnel value.
  void tnl.tunnel;
}
