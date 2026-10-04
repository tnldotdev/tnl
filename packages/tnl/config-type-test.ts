import {
  defineConfig,
  type TnlConfig,
  type TnlConfigContext,
  type TnlConfigInput,
} from "@tnldotdev/tnl/config";

const staticConfig = {
  tunnel: { allowIP: ["192.0.2.0/24"], domain: "example.test", requestLimit: 750 },
  publish: { target: 3000 },
  dev: { command: ["pnpm", "dev"], startupTimeout: "30s" },
} satisfies TnlConfigInput;

const dynamicConfig = defineConfig(async ({ cwd, env, worktree }) => ({
  ...staticConfig,
  tunnel: { name: `${env.USER ?? "user"}-${worktree.label}-${cwd.length}` },
}));

declare const environment: TnlConfigContext["env"];
environment.ARBITRARY_VARIABLE satisfies string | undefined;
// @ts-expect-error environment variables need not exist.
environment.ARBITRARY_VARIABLE satisfies string;

declare const services: NonNullable<TnlConfig["services"]>;
// @ts-expect-error configured services need not exist for an arbitrary name.
services.arbitraryService.directory satisfies string | undefined;
const service = services.arbitraryService;
if (service) service.directory satisfies string | undefined;

const projectScopedSettings = {
  server: "https://control.example",
  team: "studio",
  services: {
    web: { dev: { port: 4173 } },
  },
} satisfies TnlConfig;
// @ts-expect-error server belongs to the project, not a service.
({ server: "https://control.example" }) satisfies NonNullable<TnlConfig["services"]>[string];
// @ts-expect-error team belongs to the project, not a service.
({ team: "studio" }) satisfies NonNullable<TnlConfig["services"]>[string];

const literalConfig = defineConfig({
  dev: { port: 4173 },
  tunnel: { name: "api" },
} as const);
literalConfig.dev.port satisfies 4173;
literalConfig.tunnel.name satisfies "api";

const exactConfig = defineConfig({ tunnel: { publicURL: "https://api.example.test" } } as const);
exactConfig.tunnel.publicURL satisfies "https://api.example.test";

// @ts-expect-error TypeScript configuration has an implicit version.
defineConfig({ version: 1 });

// @ts-expect-error server configuration is static-only.
defineConfig({ tnld: { role: "relay" } });

export { dynamicConfig, exactConfig, literalConfig, projectScopedSettings, staticConfig };
