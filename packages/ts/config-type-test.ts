import {
  defineConfig,
  type TnlConfig,
  type TnlConfigContext,
  type TnlConfigForServices,
  type TnlRatePeriod,
  type TnlByteSize,
} from "@tnldotdev/tnl/config";

export const grouped = defineConfig({
  publishers: { cloud: { description: "database publisher", aws: { replicas: 2 } } },
  services: {
    db: {
      publisher: "cloud",
      protocol: "postgres",
      target: { type: "address", address: "db.internal:5432" },
      access: { team: true },
    },
    internal: { target: { type: "app" } },
  },
});
defineConfig({
  publishers: { cloud: {} },
  services: {
    // @ts-expect-error groups must be declared.
    db: { publisher: "missing", target: { type: "address", address: "db.internal:5432" } },
  },
});
defineConfig({
  publishers: { cloud: {} },
  // @ts-expect-error remote groups cannot use app discovery.
  services: { web: { publisher: "cloud", target: { type: "app" } } },
});
// @ts-expect-error local is reserved.
defineConfig({ publishers: { local: {} } });
const infrastructureGroup = {
  publishers: { cloud: { description: "db", type: "self-hosted" } },
} as const;
// @ts-expect-error provider selection uses the aws key, including inferred values.
defineConfig(infrastructureGroup);
const detailedAWSGroup = {
  publishers: { production: { aws: { replicas: 2, vpcId: "vpc-12345678" } } },
} as const;
// @ts-expect-error inferred AWS objects also reject deploy-time settings.
defineConfig(detailedAWSGroup);
defineConfig({ publishers: { production: { aws: {} } } });
defineConfig({
  publishers: {
    production: {
      aws: {
        // @ts-expect-error capacity must be numeric.
        replicas: "2",
      },
    },
  },
});
defineConfig({
  publishers: {
    production: {
      aws: {
        // @ts-expect-error detailed infrastructure settings belong in deploy-time parameters.
        vpcId: "vpc-12345678",
      },
    },
  },
});

export const config = defineConfig({
  inspection: { mode: "summary", retention: "24h", maxBytes: "64MiB" },
  publicURL: {
    access: { ip: ["192.0.2.0/24"] },
    limits: {
      http: { total: 100, concurrency: 5, rate: { count: 10, per: "1m", burst: 3 } },
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
  services: {
    web: {
      publicURL: {},
      target: { type: "app" },
      http: {
        open: true,
        readiness: { path: "/health" },
        paths: { "/api": "api", "/v1": { service: "api", stripPrefix: true } },
      },
    },
    api: {
      name: "api-preview",
      publicURL: {},
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
    cache: {
      protocol: "tcp",
      name: "shared-cache",
      target: { type: "docker", container: "shop-cache", port: 6379 },
    },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
});

config.services.db.protocol satisfies "postgres";
config.services.cache.name satisfies "shared-cache";
config.services.api.name satisfies "api-preview";
config.services.api.publicURL satisfies object;
config.services.web.http.paths["/api"] satisfies "api";

export const factory = defineConfig(async ({ worktree, project, env, cwd }) => ({
  services: {
    web: { publicURL: {}, http: { paths: { "/api": "api" } } },
    api: {
      name: `${env.USER ?? "user"}-${worktree.label.id}-${cwd.length}-${project.relativeDirectory.length}`,
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
    db: { protocol: "tcp", target: { type: "address", address: 5432 } },
  },
}));
declare const literalAddressResult: Awaited<ReturnType<typeof literalAddressFactory>>;
literalAddressResult.services.web.target.type satisfies "address";
declare const literalAsyncAddressResult: Awaited<ReturnType<typeof literalAsyncAddressFactory>>;
literalAsyncAddressResult.services.web.target.type satisfies "address";
literalAsyncAddressResult.services.db.protocol satisfies "tcp";
export const addressFactory = defineConfig(({ worktree }) => ({
  inspection: { mode: "summary", retention: "24h", maxBytes: "64MiB" },
  publicURL: {
    access: { ip: ["192.0.2.0/24"] },
    limits: { http: { rate: { count: 5, per: "1m" } } },
  },
  services: {
    web: {
      protocol: "http",
      publicURL: {},
      target: { type: "address", address: 3000 },
      http: { paths: { "/api": { service: "api", stripPrefix: true } } },
    },
    api: { publicURL: {}, target: { type: "app" }, name: worktree.label.id },
    db: { protocol: "tcp", target: { type: "address", address: 5432 } },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
}));
export const asyncAddressFactory = defineConfig(async ({ worktree }) => ({
  publicURL: { access: { ip: ["192.0.2.0/24"] } },
  services: {
    web: {
      publicURL: {},
      target: { type: "address", address: 3000 },
      http: { paths: { "/api": "api" } },
    },
    api: { publicURL: {}, target: { type: "app" }, name: worktree.label.id },
    db: {
      protocol: "tcp",
      target: { type: "compose", service: "db", port: 5432 },
    },
    cache: {
      protocol: "tcp",
      name: "cache",
      target: { type: "docker", container: "cache", port: 6379 },
    },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
}));
declare const addressFactoryResult: Awaited<ReturnType<typeof addressFactory>>;
addressFactoryResult.services.web.target.type satisfies "address";
addressFactoryResult.services.web.protocol satisfies "http";
addressFactoryResult.services.db.protocol satisfies "tcp";
addressFactoryResult.services.web.http.paths["/api"].service satisfies "api";
declare const asyncAddressFactoryResult: Awaited<ReturnType<typeof asyncAddressFactory>>;
asyncAddressFactoryResult.services.web.target.type satisfies "address";
asyncAddressFactoryResult.services.db.target.type satisfies "compose";
asyncAddressFactoryResult.services.cache.target.type satisfies "docker";
asyncAddressFactoryResult.services.db.protocol satisfies "tcp";
asyncAddressFactoryResult.aliases.review.service satisfies "web";

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
({ publicURL: { limits: { requests: 3 } } }) satisfies TnlConfig;
// @ts-expect-error browser opening belongs under service.http.
({ publicURL: { open: true } }) satisfies TnlConfig;
// @ts-expect-error target variants reject unrelated discovery fields.
({ services: { web: { target: { type: "app", address: 3000 } } } }) satisfies TnlConfig;
({
  // @ts-expect-error Compose discovery requires a service and private port.
  services: { db: { target: { type: "compose", service: "db" } } },
}) satisfies TnlConfig;

const duplicatedPublicName = {
  services: { web: { name: "site", publicURL: { name: "other", access: "anonymous" } } },
} as const;
// @ts-expect-error name is common service metadata, never duplicated in publicURL.
duplicatedPublicName satisfies TnlConfig;
// @ts-expect-error inferred values cannot duplicate the saved name in publicURL.
defineConfig(duplicatedPublicName);
// @ts-expect-error factories cannot duplicate the saved name in publicURL.
defineConfig(() => duplicatedPublicName);

const publicPool = {
  services: { web: { publicURL: { publisherPool: true, access: "anonymous" } } },
} as const;
// @ts-expect-error publisherPool is common service metadata, not public URL policy.
publicPool satisfies TnlConfig;
// @ts-expect-error inferred values cannot put publisherPool under publicURL.
defineConfig(publicPool);
// @ts-expect-error Docker discovery requires the private port.
({ services: { db: { target: { type: "docker", container: "db" } } } }) satisfies TnlConfig;
// @ts-expect-error publisher placement is not project configuration.
({ publisher: { type: "host", port: 8765 } }) satisfies TnlConfig;
({
  // @ts-expect-error private target TLS never accepts visitor passthrough.
  services: { web: { target: { type: "address", address: 3000, tls: { passthrough: true } } } },
}) satisfies TnlConfig;
// @ts-expect-error protocol limits use duration-literal periods.
({ publicURL: { limits: { tcp: { rate: { count: 1, per: "minute" } } } } }) satisfies TnlConfig;

export const known = {
  services: { api: {}, web: { publicURL: {}, http: { paths: { "/api": "api" } } } },
  aliases: { review: { service: "web" } },
} satisfies TnlConfigForServices<"api" | "web">;
// @ts-expect-error aliases must name a configured service.
defineConfig({ services: { api: {} }, aliases: { review: { service: "missing" } } });
defineConfig({
  // @ts-expect-error string path mounts name another configured service.
  services: { web: { publicURL: {}, http: { paths: { "/api": "missing" } } }, api: {} },
});
defineConfig({
  services: {
    // @ts-expect-error object path mounts name another configured service.
    web: { publicURL: {}, http: { paths: { "/api": { service: "missing" } } } },
    api: {},
  },
});
// @ts-expect-error services cannot mount themselves.
defineConfig({ services: { api: { publicURL: {}, http: { paths: { "/api": "api" } } } } });
defineConfig({
  services: { db: { protocol: "postgres", target: { type: "address", address: 5432 } } },
});
defineConfig({
  services: {
    db: {
      protocol: "tcp",
      target: { type: "address", address: 5432, tls: {} },
    },
  },
});
defineConfig({
  services: {
    db: { protocol: "tcp", target: { type: "address", address: 5432 } },
  },
  // @ts-expect-error aliases can only select HTTP services.
  aliases: { review: { service: "db" } },
});
defineConfig({
  services: {
    // @ts-expect-error HTTP mounts cannot select TCP services.
    web: { publicURL: {}, http: { paths: { "/db": "db" } } },
    db: { protocol: "tcp", target: { type: "address", address: 5432 } },
  },
});
// @ts-expect-error factory references retain configured service names.
defineConfig(() => ({ services: { api: {} }, aliases: { review: { service: "missing" } } }));
// @ts-expect-error async factory references retain configured service names.
defineConfig(async () => ({
  services: { api: {}, web: { publicURL: {}, http: { paths: { "/api": "missing" } } } },
}));
// @ts-expect-error version is implicit for TypeScript configuration.
defineConfig({ version: 1 });
// @ts-expect-error daemon configuration is static-only.
defineConfig({ tnld: { role: "relay" } });

// the same non-fresh invalid values must fail file-shape, object, and factory checks.
defineConfig({ services: { db: { protocol: "tcp", target: { type: "address", address: 5432 } } } });
defineConfig({
  services: {
    db: { protocol: "tcp", name: "database", target: { type: "address", address: 5432 } },
  },
});
defineConfig({
  services: {
    db: {
      protocol: "tcp",
      // @ts-expect-error explicit private saved names must be strings.
      name: 42,
      target: { type: "address", address: 5432 },
    },
  },
});
defineConfig({
  services: {
    db: {
      protocol: "tcp",
      // @ts-expect-error private TCP services cannot declare public URL settings.
      publicURL: { hostname: "db.example" },
      target: { type: "address", address: 5432 },
    },
  },
});

const tcpApp = {
  services: { db: { protocol: "tcp", target: { type: "app" } } },
} as const;
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
    db: {
      protocol: "tcp",
      target: { type: "address", address: 5432 },
      http: { open: true },
    },
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

const missingTCPTarget = {
  services: { db: { protocol: "tcp" } },
} as const;
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
      protocol: "tcp",
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
  services: {
    db: { protocol: "tcp", target: { type: "address", address: 5432 } },
  },
  aliases: { review: { service: "db" } },
} as const satisfies TnlConfig;
// @ts-expect-error aliases must select an HTTP service.
defineConfig(tcpAlias);
// @ts-expect-error factory aliases must select an HTTP service.
defineConfig(() => tcpAlias);
// @ts-expect-error async factory aliases must select an HTTP service.
defineConfig(async () => tcpAlias);

const tcpWebhook = {
  services: {
    db: { protocol: "tcp", target: { type: "address", address: 5432 } },
  },
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
    web: { publicURL: {}, http: { paths: { "/db": "db" } } },
    db: { protocol: "tcp", target: { type: "address", address: 5432 } },
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
    web: { publicURL: {}, http: { paths: { "/db": { service: "db" } } } },
    db: { protocol: "tcp", target: { type: "address", address: 5432 } },
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
// @ts-expect-error webhook receivers must name a local public HTTP service.
defineConfig(unnamedWebhook);
// @ts-expect-error webhook receivers must name a local public HTTP service.
defineConfig(() => unnamedWebhook);
// @ts-expect-error webhook receivers must name a local public HTTP service.
defineConfig(async () => unnamedWebhook);
// @ts-expect-error webhook receivers must name a local public HTTP service.
defineConfig(() => ({ webhooks: { hook: { service: "", path: "/hook", provider: "custom" } } }));
// @ts-expect-error webhook receivers must name a local public HTTP service.
defineConfig(async () => ({
  webhooks: { hook: { service: "", path: "/hook", provider: "custom" } },
}));

const privateWebhook = {
  services: { api: {} },
  webhooks: { hook: { service: "api", path: "/hook", provider: "custom" } },
} as const satisfies TnlConfig;
// @ts-expect-error private HTTP is not a webhook receiver.
defineConfig(privateWebhook);
const remoteReadiness = {
  publishers: { cloud: {} },
  services: {
    web: {
      publisher: "cloud",
      publicURL: {},
      target: { type: "address", address: 3000 },
      http: { readiness: { path: "/health" } },
    },
  },
} as const satisfies TnlConfig;
// @ts-expect-error remote assignments cannot honor readiness overrides.
defineConfig(remoteReadiness);
const remoteMount = {
  publishers: { cloud: {} },
  services: {
    web: {
      publisher: "cloud",
      publicURL: {},
      target: { type: "address", address: 3000 },
      http: { paths: { "/api": "api" } },
    },
    api: {},
  },
} as const satisfies TnlConfig;
// @ts-expect-error remote assignments cannot honor path mounts.
defineConfig(remoteMount);

// @ts-expect-error publisher placement is not project configuration.
({ publisher: { type: "compose", service: "publisher", port: 8765 } }) satisfies TnlConfig;
// @ts-expect-error combined byte totals are removed.
({ publicURL: { limits: { traffic: { totalBytes: 1024 } } } }) satisfies TnlConfig;
// @ts-expect-error combined byte rates are removed.
({ publicURL: { limits: { traffic: { rate: { bytes: 1024, per: "1s" } } } } }) satisfies TnlConfig;

({
  services: {
    api: {
      target: {
        type: "address",
        address: "https://api.example",
        tls: {},
        // @ts-expect-error application authentication is not target configuration.
        auth: {},
      },
    },
  },
}) satisfies TnlConfig;

defineConfig({
  publishers: { production: { aws: { replicas: 2 } } },
  services: {
    cluster: {
      publisher: "production",
      protocol: "kubernetes",
      target: { type: "eks", cluster: "development", region: "us-east-1" },
    },
    db: {
      protocol: "postgres",
      target: { type: "rds", cluster: "orders", region: "us-east-1", endpoint: "reader" },
    },
  },
  workloads: {
    deploy: {
      provider: "github",
      github: {
        workflow: ".github/workflows/deploy.yml",
        ref: "refs/heads/main",
        events: ["push"],
      },
      services: ["cluster", "db"],
      maxDuration: "1h",
    },
  },
});
defineConfig({
  services: { api: {} },
  workloads: {
    deploy: {
      provider: "github",
      github: {
        workflow: ".github/workflows/deploy.yml",
        ref: "refs/heads/main",
        events: ["push"],
      },
      // @ts-expect-error workload policies select existing service keys.
      services: ["missing"],
    },
  },
});
defineConfig({
  services: {
    inventory: {},
    models: { protocol: "postgres", target: { type: "address", address: "localhost:5432" } },
  },
  workloads: {
    storefront: {
      provider: "vercel",
      teamId: "team_one",
      projectId: "prj_store",
      environment: "production",
      services: ["inventory", "models"],
    },
    machine: {
      provider: "fly",
      org: "acme",
      orgId: "123",
      app: "store",
      appId: "456",
      services: ["inventory"],
    },
    worker: {
      provider: "oidc",
      issuer: "https://issuer.example",
      jwksUrl: "https://issuer.example/.well-known/jwks",
      audience: "tnl-store",
      claims: { sub: "service:store" },
      tokenFile: "/run/provider/token",
      services: ["models"],
    },
  },
});
defineConfig({
  services: {
    cluster: {
      protocol: "http",
      // @ts-expect-error EKS targets require the kubernetes protocol.
      target: { type: "eks", cluster: "development", region: "us-east-1" },
    },
  },
});
defineConfig({
  services: {
    db: {
      protocol: "postgres",
      // @ts-expect-error RDS reader endpoints require a cluster.
      target: { type: "rds", instance: "orders", region: "us-east-1", endpoint: "reader" },
    },
  },
});
// @ts-expect-error an ordinary factory cannot mix address and Docker fields.
defineConfig(() => ({
  services: { web: { target: { type: "address", address: 3000, container: "web" } } },
}));
// @ts-expect-error an ordinary async factory cannot mix app and address fields.
defineConfig(async () => ({ services: { web: { target: { type: "app", address: 3000 } } } }));

({
  // @ts-expect-error existing sshd services use opaque tcp, not a separate protocol.
  services: { shell: { protocol: "ssh", target: { type: "address", address: 22 } } },
}) satisfies TnlConfig;
({
  services: {
    // @ts-expect-error service-level TLS has been replaced by target.tls.
    db: { protocol: "tcp", target: { type: "address", address: 5432 }, tls: { ca: "system" } },
  },
}) satisfies TnlConfig;
