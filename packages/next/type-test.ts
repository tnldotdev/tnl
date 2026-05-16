import { withTnl } from "./dist/index.js";

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

export {
  asynchronousFactory,
  dynamicOptions,
  objectConfig,
  promisedConfig,
  staticOptions,
  synchronousFactory,
};
