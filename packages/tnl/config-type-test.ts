import { defineConfig, type TnlConfig } from "@tnldotdev/tnl/config";

const staticConfig: TnlConfig = {
  tunnel: { allowIP: ["192.0.2.0/24"], subdomain: "review" },
  publish: { target: 3000 },
  dev: { command: ["pnpm", "dev"], startupTimeout: "30s" },
};

const dynamicConfig = defineConfig(async ({ cwd, env, worktree }) => ({
  ...staticConfig,
  tunnel: { subdomain: `${env.USER ?? "user"}-${worktree.label}-${cwd.length}` },
}));

// @ts-expect-error TypeScript configuration has an implicit version.
defineConfig({ version: 1 });

// @ts-expect-error Server configuration is static-only.
defineConfig({ tnld: { mode: "relay" } });

export { dynamicConfig, staticConfig };
