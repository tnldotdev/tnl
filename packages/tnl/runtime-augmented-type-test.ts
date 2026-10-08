import { tnl } from "@tnldotdev/tnl";
import { defineConfig } from "@tnldotdev/tnl/config";

declare module "@tnldotdev/tnl" {
  interface TnlProjectMetadata {
    readonly worktree: {
      readonly label: {
        readonly project: "shop";
        readonly id: "k7n2p9";
        readonly fullLabel: "shop-k7n2p9";
      };
    };
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

defineConfig(({ worktree, project }) => {
  worktree.label.project satisfies "shop";
  worktree.label.id satisfies "k7n2p9";
  worktree.label.fullLabel satisfies "shop-k7n2p9";
  project.relativeDirectory satisfies string;
  // @ts-expect-error the generated primary-checkout label has no checkout property.
  void worktree.label.checkout;
  return {};
});

if (tnl.worktree) {
  tnl.worktree.label.fullLabel satisfies "shop-k7n2p9";
  // @ts-expect-error generated primary-checkout metadata omits checkout.
  void tnl.worktree.label.checkout;
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
