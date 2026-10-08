import "@tnldotdev/tnl";

declare module "@tnldotdev/tnl" {
  interface TnlProjectMetadata {
    readonly worktree: {
      readonly label: {
        readonly project: "tnl";
        readonly id: "bb4eff";
        readonly fullLabel: "tnl-bb4eff";
      };
    };
    readonly namespace: "ecstatic-penguin.tnl.dev";
    readonly services: {
      readonly api: {
        readonly namespace: "ecstatic-penguin.tnl.dev";
        readonly hostname: "api-tnl-bb4eff.ecstatic-penguin.tnl.dev";
        readonly url: "https://api-tnl-bb4eff.ecstatic-penguin.tnl.dev";
      };
      readonly web: {
        readonly namespace: "ecstatic-penguin.tnl.dev";
        readonly hostname: "web-tnl-bb4eff.ecstatic-penguin.tnl.dev";
        readonly url: "https://web-tnl-bb4eff.ecstatic-penguin.tnl.dev";
      };
    };
  }
}
