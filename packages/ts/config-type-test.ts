import {
  defineConfig,
  type TnlConfig,
  type TnlConfigContext,
  type TnlConfigForServices,
  type TnlRatePeriod,
  type TnlByteSize,
} from "@tnldotdev/tnl/config";

export const config = defineConfig({
  inspection: { mode: "summary", retention: "24h", maxBytes: "64MiB" },
  tunnel: {
    access: { ip: ["192.0.2.0/24"] },
    limits: {
      http: { total: 100, concurrency: 5, rate: { count: 10, per: "1m", burst: 3 } },
      tcp: { concurrency: 3 },
      traffic: {
        connections: 8,
        rate: 5,
        ratePer: "1s",
        burst: 10,
        uploadBytes: 1048576,
        downloadBytes: 2097152,
      },
    },
  },
  publisher: {
    type: "compose",
    service: "publisher",
  },
  services: {
    web: {
      target: { type: "app" },
      http: {
        open: true,
        readiness: { path: "/health" },
        paths: { "/api": "api", "/v1": { service: "api", stripPrefix: true } },
      },
    },
    api: {
      target: {
        type: "address",
        address: "https://localhost:4000",
        tls: { caFile: "./ca.pem", serverName: "localhost" },
      },
    },
    db: {
      protocol: "postgres",
      target: {
        type: "compose",
        service: "db",
        port: 5432,
        tls: {},
      },
    },
    cache: { protocol: "redis", target: { type: "docker", container: "shop-cache", port: 6379 } },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
});
config.services.db.protocol satisfies "postgres";
config.services.web.http.paths["/api"] satisfies "api";

export const factory = defineConfig(async ({ worktree, project, env, cwd }) => ({
  services: {
    web: { http: { paths: { "/api": "api" } } },
    api: {
      tunnel: {
        name: `${env.USER ?? "user"}-${worktree.label.id}-${cwd.length}-${project.relativeDirectory.length}`,
      },
    },
  },
  aliases: { review: { service: "web" } },
}));

// ordinary factories must preserve their returned discriminants without as const.
export const literalAddressFactory = defineConfig(() => ({
  services: { web: { target: { type: "address", address: 3000 } } },
}));
export const literalAsyncAddressFactory = defineConfig(async () => ({
  services: {
    web: { target: { type: "address", address: 3000 } },
    db: { protocol: "postgres", target: { type: "address", address: 5432 } },
  },
}));
declare const literalAddressResult: Awaited<ReturnType<typeof literalAddressFactory>>;
literalAddressResult.services.web.target.type satisfies "address";
declare const literalAsyncAddressResult: Awaited<ReturnType<typeof literalAsyncAddressFactory>>;
literalAsyncAddressResult.services.web.target.type satisfies "address";
literalAsyncAddressResult.services.db.protocol satisfies "postgres";
export const addressFactory = defineConfig(({ worktree }) => ({
  inspection: { mode: "summary", retention: "24h", maxBytes: "64MiB" },
  tunnel: { access: { ip: ["192.0.2.0/24"] }, limits: { http: { rate: { count: 5, per: "1m" } } } },
  services: {
    web: {
      protocol: "http",
      target: { type: "address", address: 3000 },
      http: { paths: { "/api": { service: "api", stripPrefix: true } } },
    },
    api: { target: { type: "app" }, tunnel: { name: worktree.label.id } },
    db: { protocol: "postgres", target: { type: "address", address: 5432 } },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
}));
export const asyncAddressFactory = defineConfig(async ({ worktree }) => ({
  tunnel: { access: { ip: ["192.0.2.0/24"] } },
  services: {
    web: { target: { type: "address", address: 3000 }, http: { paths: { "/api": "api" } } },
    api: { protocol: "http", target: { type: "app" }, tunnel: { name: worktree.label.id } },
    db: {
      protocol: "postgres",
      target: { type: "compose", service: "db", port: 5432 },
    },
    cache: { protocol: "redis", target: { type: "docker", container: "cache", port: 6379 } },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
}));
declare const addressFactoryResult: Awaited<ReturnType<typeof addressFactory>>;
addressFactoryResult.services.web.target.type satisfies "address";
addressFactoryResult.services.web.protocol satisfies "http";
addressFactoryResult.services.db.protocol satisfies "postgres";
addressFactoryResult.services.web.http.paths["/api"].service satisfies "api";
declare const asyncAddressFactoryResult: Awaited<ReturnType<typeof asyncAddressFactory>>;
asyncAddressFactoryResult.services.web.target.type satisfies "address";
asyncAddressFactoryResult.services.db.target.type satisfies "compose";
asyncAddressFactoryResult.services.cache.target.type satisfies "docker";
asyncAddressFactoryResult.services.db.protocol satisfies "postgres";
asyncAddressFactoryResult.aliases.review.service satisfies "web";

export const databasePublisher = {
  publisher: { type: "compose", service: "publisher" },
  services: { db: { protocol: "postgres", target: { type: "address", address: 5432 } } },
} satisfies TnlConfig;
defineConfig(databasePublisher);
defineConfig(() => databasePublisher);
defineConfig(async () => databasePublisher);
export const mixedPublisherFactory = defineConfig(() => ({
  ...databasePublisher,
  services: { ...databasePublisher.services, web: { target: { type: "app" } } },
}));
export const mixedAsyncPublisherFactory = defineConfig(async () => ({
  ...databasePublisher,
  services: { ...databasePublisher.services, web: { target: { type: "app" } } },
}));

"1h30m" satisfies TnlRatePeriod;
"1h2m3s4ms" satisfies TnlRatePeriod;
"1024KiB" satisfies TnlByteSize;
// @ts-expect-error duration units are required.
"minute" satisfies TnlRatePeriod;
// @ts-expect-error byte sizes use whole binary units.
"1.5MB" satisfies TnlByteSize;

declare const context: TnlConfigContext;
context.env.ARBITRARY satisfies string | undefined;
context.worktree.label.checkout satisfies string | undefined;
context.project.relativeDirectory satisfies string;
declare const services: NonNullable<TnlConfig["services"]>;
// @ts-expect-error arbitrary service keys may be absent.
services.arbitrary.target satisfies unknown;
if (services.arbitrary) services.arbitrary.target satisfies unknown;
// @ts-expect-error public service directories are removed.
({ services: { web: { directory: "apps/web" } } }) satisfies TnlConfig;

// @ts-expect-error root publication settings have been removed.
({ publish: { target: 3000 } }) satisfies TnlConfig;
// @ts-expect-error readiness belongs under service.http.
({ readiness: { path: "/" } }) satisfies TnlConfig;
// @ts-expect-error flat limits have been removed.
({ tunnel: { limits: { requests: 3 } } }) satisfies TnlConfig;
// @ts-expect-error browser opening belongs under service.http.
({ tunnel: { open: true } }) satisfies TnlConfig;
// @ts-expect-error target variants reject unrelated discovery fields.
({ services: { web: { target: { type: "app", address: 3000 } } } }) satisfies TnlConfig;
({
  // @ts-expect-error Compose discovery requires a service and private port.
  services: { db: { target: { type: "compose", service: "db" } } },
}) satisfies TnlConfig;
// @ts-expect-error Docker discovery requires the private port.
({ services: { db: { target: { type: "docker", container: "db" } } } }) satisfies TnlConfig;
// @ts-expect-error host placement has no container fields.
({ publisher: { type: "host", port: 8765 } }) satisfies TnlConfig;
({
  // @ts-expect-error private target TLS never accepts visitor passthrough.
  services: { web: { target: { type: "address", address: 3000, tls: { passthrough: true } } } },
}) satisfies TnlConfig;
// @ts-expect-error protocol limits use duration-literal periods.
({ tunnel: { limits: { tcp: { rate: { count: 1, per: "minute" } } } } }) satisfies TnlConfig;

export const known = {
  services: { api: {}, web: { http: { paths: { "/api": "api" } } } },
  aliases: { review: { service: "web" } },
} satisfies TnlConfigForServices<"api" | "web">;
// @ts-expect-error aliases must name a configured service.
defineConfig({ services: { api: {} }, aliases: { review: { service: "missing" } } });
// @ts-expect-error string path mounts name another configured service.
defineConfig({ services: { web: { http: { paths: { "/api": "missing" } } }, api: {} } });
defineConfig({
  // @ts-expect-error object path mounts name another configured service.
  services: { web: { http: { paths: { "/api": { service: "missing" } } } }, api: {} },
});
// @ts-expect-error services cannot mount themselves.
defineConfig({ services: { api: { http: { paths: { "/api": "api" } } } } });
defineConfig({
  services: { db: { protocol: "postgres", target: { type: "address", address: 5432 } } },
  // @ts-expect-error aliases can only select HTTP services.
  aliases: { review: { service: "db" } },
});
defineConfig({
  services: {
    // @ts-expect-error HTTP mounts cannot select TCP services.
    web: { http: { paths: { "/db": "db" } } },
    db: { protocol: "postgres", target: { type: "address", address: 5432 } },
  },
});
// @ts-expect-error factory references retain configured service names.
defineConfig(() => ({ services: { api: {} }, aliases: { review: { service: "missing" } } }));
// @ts-expect-error async factory references retain configured service names.
defineConfig(async () => ({
  services: { api: {}, web: { http: { paths: { "/api": "missing" } } } },
}));
// @ts-expect-error version is implicit for TypeScript configuration.
defineConfig({ version: 1 });
// @ts-expect-error daemon configuration is static-only.
defineConfig({ tnld: { role: "relay" } });

// the same non-fresh invalid values must fail file-shape, object, and factory checks.
const tcpApp = { services: { db: { protocol: "postgres", target: { type: "app" } } } } as const;
// @ts-expect-error TCP services cannot select an app target.
tcpApp satisfies TnlConfig;
// @ts-expect-error TCP services cannot select an app target.
defineConfig(tcpApp);
// @ts-expect-error TCP services cannot select an app target.
defineConfig(() => tcpApp);
// @ts-expect-error TCP services cannot select an app target.
defineConfig(async () => tcpApp);

const tcpHTTP = {
  services: {
    db: { protocol: "postgres", target: { type: "address", address: 5432 }, http: { open: true } },
  },
} as const;
// @ts-expect-error HTTP settings cannot be applied to a TCP service.
tcpHTTP satisfies TnlConfig;
// @ts-expect-error HTTP settings cannot be applied to a TCP service.
defineConfig(tcpHTTP);
// @ts-expect-error HTTP settings cannot be applied to a TCP service.
defineConfig(() => tcpHTTP);
// @ts-expect-error HTTP settings cannot be applied to a TCP service.
defineConfig(async () => tcpHTTP);

const missingTCPTarget = { services: { db: { protocol: "postgres" } } } as const;
// @ts-expect-error a TCP service needs a private target.
missingTCPTarget satisfies TnlConfig;
// @ts-expect-error a TCP service needs a private target.
defineConfig(missingTCPTarget);
// @ts-expect-error a TCP service needs a private target.
defineConfig(() => missingTCPTarget);
// @ts-expect-error a TCP service needs a private target.
defineConfig(async () => missingTCPTarget);

const mixedApp = { services: { web: { target: { type: "app", address: 3000 } } } } as const;
// @ts-expect-error app targets cannot contain address fields, including non-fresh values.
mixedApp satisfies TnlConfig;
// @ts-expect-error app targets cannot contain address fields.
defineConfig(mixedApp);
// @ts-expect-error app targets cannot contain address fields.
defineConfig(() => mixedApp);
// @ts-expect-error app targets cannot contain address fields.
defineConfig(async () => mixedApp);

const mixedAddress = {
  services: { web: { target: { type: "address", address: 3000, container: "web" } } },
} as const;
// @ts-expect-error address targets cannot contain Docker fields.
mixedAddress satisfies TnlConfig;
// @ts-expect-error address targets cannot contain Docker fields.
defineConfig(mixedAddress);
// @ts-expect-error address targets cannot contain Docker fields.
defineConfig(() => mixedAddress);
// @ts-expect-error address targets cannot contain Docker fields.
defineConfig(async () => mixedAddress);

const mixedCompose = {
  services: {
    web: {
      target: {
        type: "compose",
        project: "shop",
        file: "compose.yml",
        service: "web",
        port: 3000,
        container: "web",
      },
    },
  },
} as const;
// @ts-expect-error Compose targets cannot contain Docker fields.
mixedCompose satisfies TnlConfig;
// @ts-expect-error Compose targets cannot contain Docker fields.
defineConfig(mixedCompose);
// @ts-expect-error Compose targets cannot contain Docker fields.
defineConfig(() => mixedCompose);
// @ts-expect-error Compose targets cannot contain Docker fields.
defineConfig(async () => mixedCompose);

const mixedDocker = {
  services: {
    db: {
      protocol: "mysql",
      target: { type: "docker", container: "db", port: 3306, address: "db:3306" },
    },
  },
} as const;
// @ts-expect-error Docker targets cannot contain address fields.
mixedDocker satisfies TnlConfig;
// @ts-expect-error Docker targets cannot contain address fields.
defineConfig(mixedDocker);
// @ts-expect-error Docker targets cannot contain address fields.
defineConfig(() => mixedDocker);
// @ts-expect-error Docker targets cannot contain address fields.
defineConfig(async () => mixedDocker);

const tcpAlias = {
  services: { db: { protocol: "postgres", target: { type: "address", address: 5432 } } },
  aliases: { review: { service: "db" } },
} as const satisfies TnlConfig;
// @ts-expect-error aliases must select an HTTP service.
defineConfig(tcpAlias);
// @ts-expect-error factory aliases must select an HTTP service.
defineConfig(() => tcpAlias);
// @ts-expect-error async factory aliases must select an HTTP service.
defineConfig(async () => tcpAlias);

const tcpWebhook = {
  services: { db: { protocol: "postgres", target: { type: "address", address: 5432 } } },
  webhooks: { hook: { service: "db", path: "/hook", provider: "custom" } },
} as const satisfies TnlConfig;
// @ts-expect-error webhooks must select an HTTP service.
defineConfig(tcpWebhook);
// @ts-expect-error factory webhooks must select an HTTP service.
defineConfig(() => tcpWebhook);
// @ts-expect-error async factory webhooks must select an HTTP service.
defineConfig(async () => tcpWebhook);

const tcpMount = {
  services: {
    web: { http: { paths: { "/db": "db" } } },
    db: { protocol: "postgres", target: { type: "address", address: 5432 } },
  },
} as const satisfies TnlConfig;
// @ts-expect-error mounts must select another HTTP service.
defineConfig(tcpMount);
// @ts-expect-error factory mounts must select another HTTP service.
defineConfig(() => tcpMount);
// @ts-expect-error async factory mounts must select another HTTP service.
defineConfig(async () => tcpMount);

const tcpObjectMount = {
  services: {
    web: { http: { paths: { "/db": { service: "db" } } } },
    db: { protocol: "postgres", target: { type: "address", address: 5432 } },
  },
} as const satisfies TnlConfig;
// @ts-expect-error object mounts must select another HTTP service.
defineConfig(tcpObjectMount);
// @ts-expect-error factory object mounts must select another HTTP service.
defineConfig(() => tcpObjectMount);
// @ts-expect-error async factory object mounts must select another HTTP service.
defineConfig(async () => tcpObjectMount);

const unnamedTCPWebhook = {
  ...tcpWebhook,
  webhooks: { hook: { service: "", path: "/hook", provider: "custom" } },
} as const satisfies TnlConfig;
// @ts-expect-error configured TCP services do not create an unnamed HTTP service.
defineConfig(unnamedTCPWebhook);
// @ts-expect-error configured TCP services do not create an unnamed HTTP service.
defineConfig(() => unnamedTCPWebhook);
// @ts-expect-error configured TCP services do not create an unnamed HTTP service.
defineConfig(async () => unnamedTCPWebhook);

export const unnamedWebhook = {
  webhooks: { hook: { service: "", path: "/hook", provider: "custom" } },
} as const satisfies TnlConfig;
defineConfig(unnamedWebhook);
defineConfig(() => unnamedWebhook);
defineConfig(async () => unnamedWebhook);
defineConfig(() => ({ webhooks: { hook: { service: "", path: "/hook", provider: "custom" } } }));
defineConfig(async () => ({
  webhooks: { hook: { service: "", path: "/hook", provider: "custom" } },
}));

// @ts-expect-error Compose publisher ports are derived by the runtime.
({ publisher: { type: "compose", service: "publisher", port: 8765 } }) satisfies TnlConfig;
// @ts-expect-error combined byte totals are removed.
({ tunnel: { limits: { traffic: { totalBytes: 1024 } } } }) satisfies TnlConfig;
// @ts-expect-error combined byte rates are removed.
({ tunnel: { limits: { traffic: { rate: { bytes: 1024, per: "1s" } } } } }) satisfies TnlConfig;

// @ts-expect-error an ordinary factory cannot mix address and Docker fields.
defineConfig(() => ({
  services: { web: { target: { type: "address", address: 3000, container: "web" } } },
}));
// @ts-expect-error an ordinary async factory cannot mix app and address fields.
defineConfig(async () => ({ services: { web: { target: { type: "app", address: 3000 } } } }));
