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

// @ts-expect-error augmentation does not make metadata always present.
tnl.namespace satisfies "member.example";
// @ts-expect-error known services still require narrowing the root value.
void tnl.services.api;

if (tnl.namespace && tnl.services) {
  tnl.namespace satisfies "member.example";
  tnl.services.api.hostname satisfies "api.member.example";
  tnl.services.api.namespace satisfies "member.example";
  tnl.services.api.url satisfies "https://api.member.example";
  tnl.dev satisfies boolean;

  // assign valid literal values so these errors specifically check readonly ownership.
  // @ts-expect-error project metadata is readonly after augmentation.
  tnl.namespace = "member.example";
  // @ts-expect-error the services collection is readonly.
  tnl.services = { ...tnl.services };
  // @ts-expect-error generated service entries are readonly.
  tnl.services.api = { ...tnl.services.api };
  // @ts-expect-error generated service fields are readonly.
  tnl.services.api.hostname = "api.member.example";
  // @ts-expect-error generated service URLs are readonly.
  tnl.services.api.url = "https://api.member.example";
  // @ts-expect-error runtime lifecycle metadata is readonly.
  tnl.dev = false;

  // @ts-expect-error generated project declarations reject unknown services.
  void tnl.services.worker;
}
