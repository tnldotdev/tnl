import type { Plugin } from "vite";
import tnl from "./dist/index.js";

const plugin: Plugin = tnl();
const staticPlugin: Plugin = tnl({
  server: "https://tnl.example.com",
  name: "agent.example.com",
  allowIP: ["198.51.100.0/24"],
  allowCurrentIP: true,
});
const dynamicPlugin: Plugin = tnl(async ({ cwd, env, worktree }) => ({
  name: `${env.USER ?? worktree.label}.${cwd.length}.example.com`,
}));

// @ts-expect-error unknown options are rejected.
tnl({ allowCurrentIp: true });

export { dynamicPlugin, plugin, staticPlugin };
