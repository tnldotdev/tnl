import type { TnlPublicEnvironment } from "@tnldotdev/dev";

type ViteTnlEnvironment = Partial<TnlPublicEnvironment<"VITE_">>;

declare global {
  interface ImportMetaEnv extends ViteTnlEnvironment {}

  interface ImportMeta {
    readonly env: ImportMetaEnv;
  }
}

export type { TnlHostname, TnlPublicURL, TnlTunnelID } from "@tnldotdev/dev";
