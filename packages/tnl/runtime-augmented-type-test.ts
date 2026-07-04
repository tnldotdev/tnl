import { tnl } from "@tnldotdev/tnl";

declare module "@tnldotdev/tnl" {
  interface TnlProjectMetadata {
    readonly memberNamespace: "member.example";
    readonly services: {
      readonly api: {
        readonly hostname: "api.member.example";
        readonly url: "https://api.member.example";
      };
      readonly web: {
        readonly hostname: "web.member.example";
        readonly url: "https://web.member.example";
      };
    };
  }
}

if (tnl) {
  tnl.memberNamespace satisfies "member.example";
  tnl.services.api.hostname satisfies "api.member.example";
  tnl.services.api.url satisfies "https://api.member.example";
  tnl.runningUnderTnlDev satisfies boolean;

  // @ts-expect-error Generated project declarations reject unknown services.
  void tnl.services.worker;
}
