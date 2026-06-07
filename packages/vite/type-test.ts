import type { Plugin } from "vite";
import tnl from "./dist/index.js";
import type { TnlHostname, TnlPublicURL, TnlTunnelID } from "./dist/env.js";
import "./dist/env.js";

const plugin: Plugin = tnl();
const staticPlugin: Plugin = tnl({
  controlURL: "https://tnl.example.com",
  host: "agent.example.com",
  allowIP: ["198.51.100.0/24"],
  allowCurrentIP: true,
});
const dynamicPlugin: Plugin = tnl(async ({ cwd, env, worktree }) => ({
  host: `${env.USER ?? worktree.label}.${cwd.length}.example.com`,
}));

import.meta.env.VITE_TNL_HOSTNAME satisfies TnlHostname | undefined;
import.meta.env.VITE_TNL_TUNNEL_ID satisfies TnlTunnelID | undefined;
import.meta.env.VITE_TNL_URL satisfies TnlPublicURL | undefined;

// @ts-expect-error The URL is absent outside tnl dev.
import.meta.env.VITE_TNL_URL satisfies TnlPublicURL;

// @ts-expect-error unknown options are rejected.
tnl({ allowCurrentIp: true });

export { dynamicPlugin, plugin, staticPlugin };
