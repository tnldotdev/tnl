import { tnl } from "@tnldotdev/tnl";

declare module "@tnldotdev/tnl" {
  interface TnlProjectMetadata {
    readonly namespace: "member.example";
    readonly services: {
      readonly api: {
        readonly hostname: "api.member.example";
        readonly namespace: "member.example";
        readonly url: "https://api.member.example";
      };
      readonly web: {
        readonly hostname: "web.member.example";
        readonly namespace: "member.example";
        readonly url: "https://web.member.example";
      };
    };
  }
}

// @ts-expect-error Augmentation does not make metadata always present.
void tnl.namespace;
// @ts-expect-error Known services still require narrowing the root value.
void tnl.services.api;

if (tnl) {
  tnl.namespace satisfies "member.example";
  tnl.services.api.hostname satisfies "api.member.example";
  tnl.services.api.namespace satisfies "member.example";
  tnl.services.api.url satisfies "https://api.member.example";
  tnl.runningUnderTnlDev satisfies boolean;

  // Assign valid literal values so these errors specifically check readonly ownership.
  // @ts-expect-error Project metadata is readonly after augmentation.
  tnl.namespace = "member.example";
  // @ts-expect-error The services collection is readonly.
  tnl.services = { ...tnl.services };
  // @ts-expect-error Generated service entries are readonly.
  tnl.services.api = { ...tnl.services.api };
  // @ts-expect-error Generated service fields are readonly.
  tnl.services.api.hostname = "api.member.example";
  // @ts-expect-error Generated service URLs are readonly.
  tnl.services.api.url = "https://api.member.example";
  // @ts-expect-error Runtime lifecycle metadata is readonly.
  tnl.runningUnderTnlDev = false;

  // @ts-expect-error Generated project declarations reject unknown services.
  void tnl.services.worker;
}
