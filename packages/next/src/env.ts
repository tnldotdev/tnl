import type { TnlPublicEnvironment } from "@tnldotdev/dev";

type NextTnlEnvironment = Partial<TnlPublicEnvironment<"NEXT_PUBLIC_">>;

declare global {
  namespace NodeJS {
    interface ProcessEnv extends NextTnlEnvironment {}
  }
}

export type { TnlHostname, TnlPublicURL, TnlTunnelID } from "@tnldotdev/dev";
