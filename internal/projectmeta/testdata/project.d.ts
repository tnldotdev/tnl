import "@tnldotdev/tnl";

declare module "@tnldotdev/tnl" {
  interface TnlProjectMetadata {
    readonly memberNamespace: "busy-toast.tnl.dev";
    readonly services: {
      readonly api: {
        readonly memberNamespace: "busy-toast.tnl.dev";
        readonly hostname: "api-tnl-bb4eff.busy-toast.tnl.dev";
        readonly url: "https://api-tnl-bb4eff.busy-toast.tnl.dev";
      };
      readonly web: {
        readonly memberNamespace: "busy-toast.tnl.dev";
        readonly hostname: "web-tnl-bb4eff.busy-toast.tnl.dev";
        readonly url: "https://web-tnl-bb4eff.busy-toast.tnl.dev";
      };
    };
  }
}
