import {
  defineConfig,
  type TnlConfig,
  type TnlConfigContext,
  type TnlConfigInput,
  type TnlConfigForServices,
  type TnlRatePeriod,
  type TnlByteRate,
} from "@tnldotdev/tnl/config";
import type { OpenOptions } from "@tnldotdev/tnl";

({ limits: { http: { rate: { count: 2, per: "1h30m" } } } }) satisfies OpenOptions;
({
  limits: {
    http: {
      rate: {
        count: 2,
        // @ts-expect-error ad-hoc rate periods use the generated duration-literal type.
        per: "minute",
      },
    },
  },
}) satisfies OpenOptions;

const staticConfig = {
  inspection: { mode: "summary", retention: "168h", maxBytes: "64MiB" },
  tunnel: {
    allowIP: ["192.0.2.0/24"],
    domain: "example.test",
    limits: {
      traffic: {
        connections: 32,
        rate: { count: 20, per: "1s", burst: 40 },
        bandwidth: { upload: "8MiB/s", download: "16MiB/s" },
      },
      http: { total: 20, rate: { count: 5, per: "1m" }, concurrency: 750 },
    },
  },
} satisfies TnlConfigInput;

const namedTargets = defineConfig({
  services: {
    web: {
      target: { type: "app" },
      readiness: { path: "/health" },
      http: { paths: { "/api": "api" } },
    },
    api: { target: { type: "address", address: 3000 } },
    orders: {
      protocol: "postgres",
      target: { type: "address", address: "db.internal:5432" },
      tcp: { visitorTLS: "passthrough" },
    },
  },
});
defineConfig({
  // @ts-expect-error TCP service limits cannot be configured on an HTTP service.
  services: { web: { protocol: "http", tunnel: { limits: { tcp: { concurrency: 2 } } } } },
});
defineConfig({
  // @ts-expect-error HTTP request limits cannot be configured on a TCP service.
  services: {
    db: {
      protocol: "postgres",
      target: { type: "address", address: "db:5432" },
      tunnel: { limits: { http: { concurrency: 2 } } },
    },
  },
});
({
  services: {
    shell: {
      protocol: "ssh",
      target: { type: "address", address: "sshd:22" },
      // @ts-expect-error SSH does not have visitor TLS to terminate.
      tcp: { visitorTLS: "passthrough" },
    },
  },
}) satisfies TnlConfig;
({
  services: {
    web: {
      // @ts-expect-error app registration now names the service instead of selecting its directory.
      directory: "apps/web",
    },
  },
}) satisfies TnlConfig;
namedTargets.services.web.target.type satisfies "app";
namedTargets.services.orders.protocol satisfies "postgres";
({
  services: {
    web: {
      target: {
        // @ts-expect-error the app reports its own bound address.
        type: "app",
        address: 3000,
      },
    },
  },
}) satisfies TnlConfig;
// @ts-expect-error an explicit target requires an address.
defineConfig({ services: { orders: { protocol: "postgres", target: { type: "address" } } } });
defineConfig({
  // @ts-expect-error nested HTTP path mounts name a configured service.
  services: { web: { target: { type: "app" }, http: { paths: { "/api": "missing" } } }, api: {} },
});

({
  services: {
    web: { target: { type: "app" } },
    orders: {
      inspection: { mode: "none", retention: "48h", maxBytes: "16MiB" },
      protocol: "postgres",
      target: {
        type: "address",
        address: "db.internal:5432",
        tls: { serverName: "db.internal", caFile: "./ca.pem" },
      },
    },
  },
}) satisfies TnlConfig;
({
  // @ts-expect-error the retired root publish block is not accepted in TypeScript.
  publish: { target: 3000 },
}) satisfies TnlConfig;

"1m" satisfies TnlRatePeriod;
"8MiB/s" satisfies TnlByteRate;
// @ts-expect-error visitor bandwidth uses binary units per second.
"8MB/s" satisfies TnlByteRate;
"1h30m" satisfies TnlRatePeriod;
"1h2m3s4ms" satisfies TnlRatePeriod;
// @ts-expect-error rate periods require a numeric amount and duration unit.
"minute" satisfies TnlRatePeriod;
// @ts-expect-error rate periods do not use plain numbers.
"1" satisfies TnlRatePeriod;
// @ts-expect-error rate periods do not include spaces.
"1 minute" satisfies TnlRatePeriod;
({
  tunnel: {
    // @ts-expect-error requestLimit is not a configuration alias for limits.concurrency.
    requestLimit: 5,
  },
}) satisfies TnlConfig;
({
  services: {
    api: {
      protocol: "http",
      tunnel: {
        limits: {
          http: {
            rate: {
              count: 1,
              // @ts-expect-error service limits use the same rate period type.
              per: "minute",
            },
          },
        },
      },
    },
  },
}) satisfies TnlConfig;

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
services.arbitraryService.target satisfies object | undefined;
const service = services.arbitraryService;
if (service) service.target satisfies object | undefined;

const projectScopedSettings = {
  server: "https://control.example",
  team: "studio",
  feedback: true,
  services: {
    web: { target: { type: "app" }, readiness: { path: "/health" } },
  },
} satisfies TnlConfig;
const composeProject = defineConfig(({ worktree }) => ({
  publisher: {
    type: "docker",
    compose: { file: "compose.yaml", project: worktree.label.fullLabel, service: "publisher" },
    containerPort: 3781,
  },
  services: {
    orders: {
      protocol: "postgres",
      target: {
        type: "docker",
        compose: { file: "compose.yaml", project: worktree.label.fullLabel, service: "db" },
        containerPort: 5432,
      },
    },
  },
}));
type ComposeProjectConfig = Awaited<ReturnType<typeof composeProject>>;
declare const composeProjectConfig: ComposeProjectConfig;
if (
  composeProjectConfig.services?.orders.target?.type === "docker" &&
  "compose" in composeProjectConfig.services.orders.target
) {
  composeProjectConfig.services.orders.target.compose.service satisfies string;
}
const mountedServices = {
  services: {
    web: { http: { paths: { "/api": "api", "/v1": { service: "api", stripPrefix: true } } } },
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
    web: { http: { paths: { "/api": "api", "/v1": { service: "api", stripPrefix: true } } } },
  },
  aliases: { review: { service: "web" }, nested: { service: "api", name: "api.shop" } },
});
aliasConfig.aliases.review.service satisfies "web";
aliasConfig.aliases.nested.name satisfies "api.shop";
const aliasFactory = defineConfig(async ({ worktree }) => ({
  services: {
    api: { tunnel: { name: `api-${worktree.label.id}` } },
    web: { http: { paths: { "/api": "api" } } },
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
  services: { api: {}, web: { http: { paths: { "/api": "api" } } } },
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
      http: {
        paths: {
          // @ts-expect-error "missing" is not assignable to configured service "api".
          "/other": "missing",
        },
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
defineConfig({ services: { web: { http: { paths: { "/api": "missing" } } }, api: {} } });
defineConfig({
  // @ts-expect-error object path mounts name a configured service.
  services: { web: { http: { paths: { "/api": { service: "missing" } } } }, api: {} },
});
// @ts-expect-error a service cannot mount itself.
defineConfig({ services: { api: { http: { paths: { "/api": "api" } } } } });
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
defineConfig(() => ({ services: { api: {}, web: { http: { paths: { "/api": "missing" } } } } }));
defineConfig(() => ({
  // @ts-expect-error factory object mounts retain service-reference checks.
  services: { api: {}, web: { http: { paths: { "/api": { service: "missing" } } } } },
}));
// @ts-expect-error server belongs to the project, not a service.
({ server: "https://control.example" }) satisfies NonNullable<TnlConfig["services"]>[string];
// @ts-expect-error team belongs to the project, not a service.
({ team: "studio" }) satisfies NonNullable<TnlConfig["services"]>[string];

const literalConfig = defineConfig({
  tunnel: { name: "api" },
  services: { api: { target: { type: "app" }, readiness: { path: "/health" } } },
} as const);
literalConfig.services.api.readiness.path satisfies "/health";
literalConfig.tunnel.name satisfies "api";

const exactConfig = defineConfig({ tunnel: { publicURL: "https://api.example.test" } } as const);
exactConfig.tunnel.publicURL satisfies "https://api.example.test";

// @ts-expect-error TypeScript configuration has an implicit version.
defineConfig({ version: 1 });

// @ts-expect-error server configuration is static-only.
defineConfig({ tnld: { role: "relay" } });

export {
  namedTargets,
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
