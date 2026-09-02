import { withTnl } from "./dist/index.js";
import type { TnlHostname, TnlPublicURL, TnlTunnelID } from "./dist/env.js";
import "./dist/env.js";

const objectConfig = withTnl({ reactStrictMode: true });
const promisedConfig = withTnl(Promise.resolve({ reactStrictMode: true }));
const synchronousFactory = withTnl((_phase, { defaultConfig }) => ({
  ...defaultConfig,
  reactStrictMode: true,
}));

const asynchronousFactory = withTnl(async (_phase, { defaultConfig }) => ({
  ...defaultConfig,
  allowedDevOrigins: ["existing.example"],
}));
const staticOptions = withTnl(
  { reactStrictMode: true },
  {
    server: "https://tnl.example.com",
    name: "agent.example.com",
    allowIP: ["198.51.100.0/24"],
    allowCurrentIP: true,
  },
);
const dynamicOptions = withTnl({}, async ({ cwd, env, worktree }) => ({
  name: `${env.USER ?? worktree.label}.${cwd.length}.example.com`,
}));

process.env.NEXT_PUBLIC_TNL_HOSTNAME satisfies TnlHostname | undefined;
process.env.NEXT_PUBLIC_TNL_TUNNEL_ID satisfies TnlTunnelID | undefined;
process.env.NEXT_PUBLIC_TNL_URL satisfies TnlPublicURL | undefined;

// @ts-expect-error The URL is absent outside tnl dev.
process.env.NEXT_PUBLIC_TNL_URL satisfies TnlPublicURL;

export {
  asynchronousFactory,
  dynamicOptions,
  objectConfig,
  promisedConfig,
  staticOptions,
  synchronousFactory,
};
