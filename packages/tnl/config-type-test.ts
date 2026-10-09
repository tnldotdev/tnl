import {
  defineConfig,
  type TnlConfig,
  type TnlConfigContext,
  type TnlConfigInput,
  type TnlConfigForServices,
} from "@tnldotdev/tnl/config";

const staticConfig = {
  tunnel: { allowIP: ["192.0.2.0/24"], domain: "example.test", requestLimit: 750 },
  publish: { target: 3000 },
  readiness: { path: "/health", status: 204 },
} satisfies TnlConfigInput;

const dynamicConfig = defineConfig(async ({ cwd, env, worktree }) => ({
  ...staticConfig,
  tunnel: { name: `${env.USER ?? "user"}-${worktree.label.fullLabel}-${cwd.length}` },
}));

defineConfig(({ worktree, project }) => {
  worktree.label.project satisfies string;
  worktree.label.checkout satisfies string | undefined;
  worktree.label.id satisfies string;
  worktree.label.fullLabel satisfies string;
  project.relativeDirectory satisfies string;
  return {};
});

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
  feedback: true,
  services: {
    web: { readiness: { path: "/health", status: 204 } },
  },
} satisfies TnlConfig;
const mountedServices = {
  services: {
    web: { paths: { "/api": "api", "/v1": { service: "api", stripPrefix: true } } },
    api: {},
  },
} satisfies TnlConfig;
const integrationConfig = defineConfig({
  oauth: true,
  services: { api: {} },
  webhooks: {
    payments: {
      service: "api",
      path: "/api/webhooks/payments",
      provider: "stripe",
      sourceIPs: ["198.51.100.0/24"],
    },
    customProvider: { service: "api", path: "/hooks/other", provider: "custom" },
  },
} as const);
integrationConfig.oauth satisfies true;
integrationConfig.webhooks.customProvider.provider satisfies "custom";

const aliasConfig = defineConfig({
  services: {
    api: {},
    web: { paths: { "/api": "api", "/v1": { service: "api", stripPrefix: true } } },
  },
  aliases: { review: { service: "web" }, nested: { service: "api", name: "api.shop" } },
});
aliasConfig.aliases.review.service satisfies "web";
aliasConfig.aliases.nested.name satisfies "api.shop";
const aliasFactory = defineConfig(async ({ worktree }) => ({
  services: {
    api: { tunnel: { name: `api-${worktree.label.id}` } },
    web: { paths: { "/api": "api" } },
  },
  aliases: { review: { service: "web" } },
}));
type AliasFactoryResult = Awaited<ReturnType<typeof aliasFactory>>;
declare const aliasFactoryResult: AliasFactoryResult;
if (aliasFactoryResult.aliases?.review) {
  aliasFactoryResult.aliases.review.service satisfies "api" | "web";
}

// the generated TnlConfig describes the file shape. provide known names when
// checking a plain object without defineConfig's service-key inference.
const explicitServices = {
  services: { api: {}, web: { paths: { "/api": "api" } } },
  aliases: { review: { service: "web" } },
  webhooks: { hook: { service: "api", path: "/hook", provider: "custom" } },
} satisfies TnlConfigForServices<"api" | "web">;
({
  services: { api: {} },
  aliases: {
    review: {
      // @ts-expect-error "missing" is not assignable to configured service "api".
      service: "missing",
    },
  },
}) satisfies TnlConfigForServices<"api">;
({
  services: { api: {} },
  webhooks: {
    hook: {
      // @ts-expect-error "missing" is not assignable to configured service "api".
      service: "missing",
      path: "/hook",
      provider: "custom",
    },
  },
}) satisfies TnlConfigForServices<"api">;
({
  services: {
    api: {
      paths: {
        // @ts-expect-error "missing" is not assignable to configured service "api".
        "/other": "missing",
      },
    },
  },
}) satisfies TnlConfigForServices<"api">;
// @ts-expect-error aliases reference a configured entry service.
defineConfig({ services: { api: {} }, aliases: { review: { service: "missing" } } });
defineConfig({
  // @ts-expect-error webhook service references are checked too.
  services: { api: {} },
  webhooks: { hook: { service: "missing", path: "/hook", provider: "custom" } },
});
// @ts-expect-error string path mounts name a configured service.
defineConfig({ services: { web: { paths: { "/api": "missing" } }, api: {} } });
// @ts-expect-error object path mounts name a configured service.
defineConfig({ services: { web: { paths: { "/api": { service: "missing" } } }, api: {} } });
// @ts-expect-error a service cannot mount itself.
defineConfig({ services: { api: { paths: { "/api": "api" } } } });
// @ts-expect-error factory returns retain service-reference checks.
defineConfig(() => ({ services: { api: {} }, aliases: { review: { service: "missing" } } }));
// @ts-expect-error async factory returns retain service-reference checks.
defineConfig(async () => ({ services: { api: {} }, aliases: { review: { service: "missing" } } }));
defineConfig(() => ({
  services: { api: {} },
  // @ts-expect-error factory webhook references must match service keys too.
  webhooks: { hook: { service: "missing", path: "/hook", provider: "custom" } },
}));
// @ts-expect-error async factory webhook references must match service keys too.
defineConfig(async () => ({
  services: { api: {} },
  webhooks: { hook: { service: "missing", path: "/hook", provider: "custom" } },
}));
// @ts-expect-error factory string mounts retain service-reference checks.
defineConfig(() => ({ services: { api: {}, web: { paths: { "/api": "missing" } } } }));
// @ts-expect-error factory object mounts retain service-reference checks.
defineConfig(() => ({ services: { api: {}, web: { paths: { "/api": { service: "missing" } } } } }));
// @ts-expect-error server belongs to the project, not a service.
({ server: "https://control.example" }) satisfies NonNullable<TnlConfig["services"]>[string];
// @ts-expect-error team belongs to the project, not a service.
({ team: "studio" }) satisfies NonNullable<TnlConfig["services"]>[string];

const literalConfig = defineConfig({
  readiness: { path: "/health", status: 204 },
  tunnel: { name: "api" },
} as const);
literalConfig.readiness.status satisfies 204;
literalConfig.tunnel.name satisfies "api";

const exactConfig = defineConfig({ tunnel: { publicURL: "https://api.example.test" } } as const);
exactConfig.tunnel.publicURL satisfies "https://api.example.test";

// @ts-expect-error TypeScript configuration has an implicit version.
defineConfig({ version: 1 });

// @ts-expect-error server configuration is static-only.
defineConfig({ tnld: { role: "relay" } });

export {
  aliasConfig,
  aliasFactory,
  dynamicConfig,
  exactConfig,
  integrationConfig,
  explicitServices,
  literalConfig,
  mountedServices,
  projectScopedSettings,
  staticConfig,
};
