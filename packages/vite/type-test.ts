import type { Plugin } from "vite";
import tnl from "./dist/index.js";
import type { TnlHostname, TnlPublicURL, TnlTunnelID } from "./dist/env.js";
import "./dist/env.js";

const plugin: Plugin = tnl();

import.meta.env.VITE_TNL_HOSTNAME satisfies TnlHostname | undefined;
import.meta.env.VITE_TNL_TUNNEL_ID satisfies TnlTunnelID | undefined;
import.meta.env.VITE_TNL_URL satisfies TnlPublicURL | undefined;

// @ts-expect-error The URL is absent outside tnl dev.
import.meta.env.VITE_TNL_URL satisfies TnlPublicURL;

// @ts-expect-error tnl configuration belongs in the project config file.
tnl({ public: true });

export { plugin };
