import {
  defineConfig,
  type TnlConfig,
  type TnlConfigContext,
  type TnlConfigForServices,
  type TnlRatePeriod,
  type TnlByteSize,
  type TnlServiceTarget,
} from "@tnldotdev/tnl/config";
import { assert, assertType, expectTypeOf, test } from "vitest";

function local<const Services, const Targets>(services: Services, targets: Targets) {
  return { services, deployments: { local: { targets } } };
}

export const grouped = defineConfig({
  services: { db: { protocol: "postgres" }, internal: {} },
  deployments: {
    cloud: {
      description: "database publisher",
      targets: { db: { address: "db.internal:5432", access: { team: true } } },
    },
    local: { targets: { internal: {} } },
  },
});

test("deployments select declared bindings and reject infrastructure settings", () => {
  assertType<TnlConfig>(grouped);
  defineConfig({
    services: { db: {} },
    // @ts-expect-error every binding needs a logical declaration.
    deployments: { cloud: { targets: { missing: { address: 3000 } } } },
  });
  defineConfig({
    services: { web: {} },
    // @ts-expect-error remote deployments cannot use app discovery.
    deployments: { cloud: { targets: { web: { type: "app" } } } },
  });
  // @ts-expect-error local is client-side and has no server reachability.
  defineConfig({ deployments: { local: { public: true } } });
  const infrastructure = {
    deployments: { cloud: { description: "db", type: "self-hosted" } },
  } as const;
  // @ts-expect-error inferred infrastructure settings are rejected.
  defineConfig(infrastructure);
  const aws = {
    deployments: { production: { aws: { replicas: 2, vpcId: "vpc-12345678" } } },
  } as const;
  // @ts-expect-error inferred AWS settings are rejected too.
  defineConfig(aws);
  // @ts-expect-error fresh AWS settings are rejected.
  defineConfig({ deployments: { production: { aws: {} } } });
});

test("saved services select exposure independently of protocol and placement", () => {
  const project = defineConfig({
    services: { api: {}, db: { protocol: "postgres" } },
    deployments: {
      production: {
        targets: {
          api: { address: "http://app.internal:3000", public: true },
          db: { address: "db.internal:5432", public: false },
        },
      },
    },
  });
  expectTypeOf(project.deployments.production.targets.api.public).toEqualTypeOf<true>();
  expectTypeOf(project.deployments.production.targets.db.public).toEqualTypeOf<false>();
  defineConfig({
    services: { app: {} },
    // @ts-expect-error app-owned exposure has not switched to the service endpoint lifecycle yet.
    deployments: { local: { targets: { app: { public: true } } } },
  });
});

test("public URLs cannot carry service endpoint exposure in generated configuration types", () => {
  assertType<TnlServiceTarget>({ publicURL: {} });
  assertType<TnlServiceTarget>({ address: "http://web.internal:3000", public: false });
  assertType<TnlServiceTarget>({ address: "http://web.internal:3000", public: true });
  // @ts-expect-error the publication choice must not admit unknown binding fields.
  assertType<TnlServiceTarget>({ publicURL: {}, unexpected: true });
  for (const publicExposure of [false, true] as const) {
    const binding = { publicURL: {}, public: publicExposure } as const;
    // @ts-expect-error generated binding types reject either explicit endpoint flag.
    assertType<TnlServiceTarget>(binding);
    const project = {
      services: { web: {} },
      deployments: { production: { targets: { web: binding } } },
    } as const;
    // @ts-expect-error generated project types reject inferred mixed publication settings.
    assertType<TnlConfig>(project);
    // @ts-expect-error defineConfig must not admit the inferred combination either.
    defineConfig(project);
    // @ts-expect-error factories follow the same publication boundary.
    defineConfig(() => project);
  }
});

const config = defineConfig({
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
  services: { web: {}, api: {}, db: { protocol: "postgres" }, cache: { protocol: "tcp" } },
  deployments: {
    local: {
      targets: {
        web: {
          publicURL: {},
          type: "app",
          http: {
            open: true,
            readiness: { path: "/health" },
            paths: { "/api": "api", "/v1": { service: "api", stripPrefix: true } },
          },
        },
        api: {
          name: "api-preview",
          publicURL: {},
          type: "address",
          address: "https://localhost:4000",
          tls: { ca: "system", hostname: "localhost" },
        },
        db: { type: "compose", service: "db", port: 5432, tls: {} },
        cache: { name: "shared-cache", type: "docker", container: "shop-cache", port: 6379 },
      },
    },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
});

test("configuration preserves service, target, name, and path literals", () => {
  expectTypeOf(config.services.db.protocol).toEqualTypeOf<"postgres">();
  expectTypeOf(config.deployments.local.targets.cache.name).toEqualTypeOf<"shared-cache">();
  expectTypeOf(config.deployments.local.targets.api.name).toEqualTypeOf<"api-preview">();
  assertType<object>(config.deployments.local.targets.api.publicURL);
  expectTypeOf(config.deployments.local.targets.web.http.paths["/api"]).toEqualTypeOf<"api">();
});

export const factory = defineConfig(async ({ worktree, project, env, cwd }) => ({
  services: { web: {}, api: {} },
  deployments: {
    local: {
      targets: {
        web: { publicURL: {}, http: { paths: { "/api": "api" } } },
        api: {
          name: `${env.USER ?? "user"}-${worktree.label.id}-${cwd.length}-${project.relativeDirectory.length}`,
        },
      },
    },
  },
  aliases: { review: { service: "web" } },
}));
export const literalAddressFactory = defineConfig(() =>
  local({ web: {} }, { web: { type: "address", address: 3000 } }),
);
export const literalAsyncAddressFactory = defineConfig(async () =>
  local(
    { web: {}, db: { protocol: "tcp" } },
    { web: { type: "address", address: 3000 }, db: { address: 5432 } },
  ),
);
export const addressFactory = defineConfig(({ worktree }) => ({
  inspection: { mode: "summary", retention: "24h", maxBytes: "64MiB" },
  publicURL: {
    access: { ip: ["192.0.2.0/24"] },
    limits: { http: { rate: { count: 5, per: "1m" } } },
  },
  services: { web: { protocol: "http" }, api: {}, db: { protocol: "tcp" } },
  deployments: {
    local: {
      targets: {
        web: {
          publicURL: {},
          type: "address",
          address: 3000,
          http: { paths: { "/api": { service: "api", stripPrefix: true } } },
        },
        api: { publicURL: {}, type: "app", name: worktree.label.id },
        db: { address: 5432 },
      },
    },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
}));
export const asyncAddressFactory = defineConfig(async ({ worktree }) => ({
  publicURL: { access: { ip: ["192.0.2.0/24"] } },
  services: { web: {}, api: {}, db: { protocol: "tcp" }, cache: { protocol: "tcp" } },
  deployments: {
    local: {
      targets: {
        web: { publicURL: {}, type: "address", address: 3000, http: { paths: { "/api": "api" } } },
        api: { publicURL: {}, type: "app", name: worktree.label.id },
        db: { type: "compose", service: "db", port: 5432 },
        cache: { name: "cache", type: "docker", container: "cache", port: 6379 },
      },
    },
  },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
}));
declare const literalAddressResult: Awaited<ReturnType<typeof literalAddressFactory>>;
declare const literalAsyncAddressResult: Awaited<ReturnType<typeof literalAsyncAddressFactory>>;
declare const addressFactoryResult: Awaited<ReturnType<typeof addressFactory>>;
declare const asyncAddressFactoryResult: Awaited<ReturnType<typeof asyncAddressFactory>>;
test("sync and async factories preserve literal discriminants without casts", () => {
  expectTypeOf(literalAddressResult.deployments.local.targets.web.type).toEqualTypeOf<"address">();
  expectTypeOf(
    literalAsyncAddressResult.deployments.local.targets.web.type,
  ).toEqualTypeOf<"address">();
  expectTypeOf(literalAsyncAddressResult.services.db.protocol).toEqualTypeOf<"tcp">();
  expectTypeOf(addressFactoryResult.deployments.local.targets.web.type).toEqualTypeOf<"address">();
  expectTypeOf(addressFactoryResult.services.web.protocol).toEqualTypeOf<"http">();
  expectTypeOf(addressFactoryResult.services.db.protocol).toEqualTypeOf<"tcp">();
  expectTypeOf(
    addressFactoryResult.deployments.local.targets.web.http.paths["/api"].service,
  ).toEqualTypeOf<"api">();
  expectTypeOf(
    asyncAddressFactoryResult.deployments.local.targets.web.type,
  ).toEqualTypeOf<"address">();
  expectTypeOf(
    asyncAddressFactoryResult.deployments.local.targets.db.type,
  ).toEqualTypeOf<"compose">();
  expectTypeOf(
    asyncAddressFactoryResult.deployments.local.targets.cache.type,
  ).toEqualTypeOf<"docker">();
  expectTypeOf(asyncAddressFactoryResult.services.db.protocol).toEqualTypeOf<"tcp">();
  expectTypeOf(asyncAddressFactoryResult.aliases.review.service).toEqualTypeOf<"web">();
});

test("duration and byte-size values require their units", () => {
  assertType<TnlRatePeriod>("1h30m");
  assertType<TnlRatePeriod>("1h2m3s4ms");
  assertType<TnlByteSize>("1024KiB");
  // @ts-expect-error duration units are required.
  "minute" satisfies TnlRatePeriod;
  // @ts-expect-error byte sizes use whole binary units.
  "1.5MB" satisfies TnlByteSize;
});
declare const context: TnlConfigContext;
declare const services: NonNullable<TnlConfig["services"]>;
test("configuration context and arbitrary service lookups preserve absence", () => {
  expectTypeOf(context.env.ARBITRARY).toEqualTypeOf<string | undefined>();
  expectTypeOf(context.worktree.label.checkout).toEqualTypeOf<string | undefined>();
  expectTypeOf(context.project.relativeDirectory).toEqualTypeOf<string>();
  // @ts-expect-error arbitrary service keys may be absent.
  services.arbitrary.protocol satisfies unknown;
  assert(services.arbitrary !== undefined);
  assertType<unknown>(services.arbitrary.protocol);
});

test("configuration enforces service ownership and references for literals and factories", () => {
  defineConfig({
    services: { web: {}, api: {} },
    deployments: {
      production: {
        targets: {
          web: { publicURL: {} },
          api: {
            address: "https://api.internal:8443",
            tls: {},
            publicURL: { access: "anonymous" },
          },
        },
      },
    },
  });
  defineConfig({
    services: { web: {} },
    deployments: {
      // @ts-expect-error named remote URLs cannot be temporary.
      production: { targets: { web: { publicURL: { ephemeral: true } } } },
    },
  });
  defineConfig({
    services: { web: {} },
    deployments: {
      // @ts-expect-error named visitor policy belongs on publicURL, not http.
      production: { targets: { web: { publicURL: {}, http: { access: "restricted" } } } },
    },
  });
  // @ts-expect-error service-owned target definitions have been replaced.
  defineConfig({ services: { web: { target: { type: "app" } } } });
  // @ts-expect-error public service directories are removed.
  ({ services: { web: { directory: "apps/web" } } }) satisfies TnlConfig;
  // @ts-expect-error root publication settings have been removed.
  ({ publish: { target: 3000 } }) satisfies TnlConfig;
  // @ts-expect-error readiness belongs in a binding's HTTP settings.
  ({ readiness: { path: "/" } }) satisfies TnlConfig;
  // @ts-expect-error flat limits have been removed.
  ({ publicURL: { limits: { requests: 3 } } }) satisfies TnlConfig;
  // @ts-expect-error browser opening belongs in a binding's HTTP settings.
  ({ publicURL: { open: true } }) satisfies TnlConfig;
  // @ts-expect-error protocol limits use duration-literal periods.
  ({ publicURL: { limits: { tcp: { rate: { count: 1, per: "minute" } } } } }) satisfies TnlConfig;
  // @ts-expect-error combined byte totals are removed.
  ({ publicURL: { limits: { traffic: { totalBytes: 1024 } } } }) satisfies TnlConfig;
  ({
    // @ts-expect-error combined byte rates are removed.
    publicURL: { limits: { traffic: { rate: { bytes: 1024, per: "1s" } } } },
  }) satisfies TnlConfig;
  // @ts-expect-error version is implicit for TypeScript configuration.
  defineConfig({ version: 1 });
  // @ts-expect-error daemon configuration is static-only.
  defineConfig({ tnld: { role: "relay" } });

  const mixedApp = local({ web: {} }, { web: { type: "app", address: 3000 } });
  // @ts-expect-error app targets cannot contain addresses, including non-fresh objects.
  mixedApp satisfies TnlConfig;
  // @ts-expect-error app targets cannot contain addresses.
  defineConfig(mixedApp);
  // @ts-expect-error synchronous factory variants remain disjoint.
  defineConfig(() => mixedApp);
  // @ts-expect-error asynchronous factory variants remain disjoint.
  defineConfig(async () => mixedApp);
  const mixedAddress = local(
    { web: {} },
    { web: { type: "address", address: 3000, container: "web" } },
  );
  // @ts-expect-error address targets cannot contain Docker fields.
  mixedAddress satisfies TnlConfig;
  // @ts-expect-error inferred address targets remain disjoint.
  defineConfig(mixedAddress);
  // @ts-expect-error synchronous address factories remain disjoint.
  defineConfig(() => mixedAddress);
  // @ts-expect-error asynchronous address factories remain disjoint.
  defineConfig(async () => mixedAddress);
  const mixedCompose = local(
    { web: {} },
    {
      web: {
        type: "compose",
        project: "shop",
        file: "compose.yml",
        service: "web",
        port: 3000,
        container: "web",
      },
    },
  );
  // @ts-expect-error Compose targets cannot contain Docker fields.
  mixedCompose satisfies TnlConfig;
  // @ts-expect-error inferred Compose targets remain disjoint.
  defineConfig(mixedCompose);
  // @ts-expect-error synchronous Compose factories remain disjoint.
  defineConfig(() => mixedCompose);
  // @ts-expect-error asynchronous Compose factories remain disjoint.
  defineConfig(async () => mixedCompose);
  const mixedDocker = local(
    { db: { protocol: "tcp" } },
    { db: { type: "docker", container: "db", port: 3306, address: "db:3306" } },
  );
  // @ts-expect-error Docker targets cannot contain addresses.
  mixedDocker satisfies TnlConfig;
  // @ts-expect-error inferred Docker targets remain disjoint.
  defineConfig(mixedDocker);
  // @ts-expect-error synchronous Docker factories remain disjoint.
  defineConfig(() => mixedDocker);
  // @ts-expect-error asynchronous Docker factories remain disjoint.
  defineConfig(async () => mixedDocker);
  // @ts-expect-error Compose discovery requires a private port.
  local({ db: {} }, { db: { type: "compose", service: "db" } }) satisfies TnlConfig;
  // @ts-expect-error Docker discovery requires a private port.
  local({ db: {} }, { db: { type: "docker", container: "db" } }) satisfies TnlConfig;
  // @ts-expect-error private TLS never accepts visitor passthrough.
  local({ web: {} }, { web: { address: 3000, tls: { passthrough: true } } }) satisfies TnlConfig;
  // @ts-expect-error target configuration cannot contain application authentication.
  local({ api: {} }, { api: { address: "https://api.example", auth: {} } }) satisfies TnlConfig;
  const duplicatedPublicName = local(
    { web: {} },
    { web: { name: "site", publicURL: { name: "other", access: "anonymous" } } },
  );
  // @ts-expect-error saved names are never duplicated inside publicURL.
  duplicatedPublicName satisfies TnlConfig;
  // @ts-expect-error inferred public names are checked.
  defineConfig(duplicatedPublicName);
  // @ts-expect-error factory public names are checked.
  defineConfig(() => duplicatedPublicName);
  const publicPool = local(
    { web: {} },
    { web: { publicURL: { publisherPool: true, access: "anonymous" } } },
  );
  // @ts-expect-error public URL policy does not contain publisher pools.
  publicPool satisfies TnlConfig;
  // @ts-expect-error inferred pool settings are rejected.
  defineConfig(publicPool);

  // logical declarations need no binding until a deployment selects them.
  defineConfig({ services: { db: { protocol: "tcp" } } });
  defineConfig(local({ db: { protocol: "postgres" } }, { db: { address: 5432 } }));
  defineConfig(local({ db: { protocol: "tcp" } }, { db: { address: 5432, tls: {} } }));
  defineConfig(local({ db: { protocol: "tcp" } }, { db: { name: "database", address: 5432 } }));
  // @ts-expect-error saved endpoint names are strings.
  defineConfig(local({ db: { protocol: "tcp" } }, { db: { name: 42, address: 5432 } }));
  const tcpApp = local({ db: { protocol: "tcp" } }, { db: { type: "app" } });
  // @ts-expect-error TCP bindings cannot use app discovery.
  defineConfig(tcpApp);
  // @ts-expect-error sync factories retain protocol boundaries.
  defineConfig(() => tcpApp);
  // @ts-expect-error async factories retain protocol boundaries.
  defineConfig(async () => tcpApp);
  const missingTCPTarget = local({ db: { protocol: "tcp" } }, { db: {} });
  // @ts-expect-error a selected TCP binding needs a target.
  defineConfig(missingTCPTarget);
  // @ts-expect-error sync factories require selected targets.
  defineConfig(() => missingTCPTarget);
  // @ts-expect-error async factories require selected targets.
  defineConfig(async () => missingTCPTarget);
  const tcpHTTP = local(
    { db: { protocol: "tcp" } },
    { db: { address: 5432, http: { open: true } } },
  );
  // @ts-expect-error TCP bindings cannot use HTTP settings.
  defineConfig(tcpHTTP);
  // @ts-expect-error sync factories retain HTTP boundaries.
  defineConfig(() => tcpHTTP);
  // @ts-expect-error async factories retain HTTP boundaries.
  defineConfig(async () => tcpHTTP);
  const tcpPublicURL = local(
    { db: { protocol: "tcp" } },
    { db: { address: 5432, publicURL: { hostname: "db.example" } } },
  );
  // @ts-expect-error TCP bindings cannot enable public URLs.
  defineConfig(tcpPublicURL);

  const known = {
    ...local(
      { api: {}, web: {} },
      { api: {}, web: { publicURL: {}, http: { paths: { "/api": "api" } } } },
    ),
    aliases: { review: { service: "web" } },
  } satisfies TnlConfigForServices<"api" | "web">;
  assertType<TnlConfigForServices<"api" | "web">>(known);
  // @ts-expect-error aliases name existing services.
  defineConfig({ services: { api: {} }, aliases: { review: { service: "missing" } } });
  // @ts-expect-error sync factory aliases retain service names.
  defineConfig(() => ({ services: { api: {} }, aliases: { review: { service: "missing" } } }));
  const missingMount = local(
    { web: {}, api: {} },
    { web: { publicURL: {}, http: { paths: { "/api": "missing" } } }, api: {} },
  );
  // @ts-expect-error path mounts name existing bindings.
  defineConfig(missingMount);
  const missingObjectMount = local(
    { web: {}, api: {} },
    { web: { publicURL: {}, http: { paths: { "/api": { service: "missing" } } } }, api: {} },
  );
  // @ts-expect-error object mounts name existing bindings.
  defineConfig(missingObjectMount);
  // @ts-expect-error services cannot mount themselves.
  defineConfig(local({ api: {} }, { api: { publicURL: {}, http: { paths: { "/api": "api" } } } }));
  // @ts-expect-error async factories retain mount references.
  defineConfig(async () =>
    local(
      { api: {}, web: {} },
      { api: {}, web: { publicURL: {}, http: { paths: { "/api": "missing" } } } },
    ),
  );
  const tcpAlias = {
    ...local({ db: { protocol: "tcp" } }, { db: { address: 5432 } }),
    aliases: { review: { service: "db" } },
  } as const;
  // @ts-expect-error aliases select HTTP services.
  defineConfig(tcpAlias);
  // @ts-expect-error sync alias factories retain protocols.
  defineConfig(() => tcpAlias);
  // @ts-expect-error async alias factories retain protocols.
  defineConfig(async () => tcpAlias);
  const tcpWebhook = {
    ...local({ db: { protocol: "tcp" } }, { db: { address: 5432 } }),
    webhooks: { hook: { service: "db", path: "/hook", provider: "custom" } },
  } as const;
  // @ts-expect-error webhook receivers are HTTP services.
  defineConfig(tcpWebhook);
  // @ts-expect-error sync webhook factories retain protocols.
  defineConfig(() => tcpWebhook);
  // @ts-expect-error async webhook factories retain protocols.
  defineConfig(async () => tcpWebhook);
  const tcpMount = local(
    { web: {}, db: { protocol: "tcp" } },
    { web: { publicURL: {}, http: { paths: { "/db": "db" } } }, db: { address: 5432 } },
  );
  // @ts-expect-error mounts select HTTP services.
  defineConfig(tcpMount);
  // @ts-expect-error sync mount factories retain protocols.
  defineConfig(() => tcpMount);
  // @ts-expect-error async mount factories retain protocols.
  defineConfig(async () => tcpMount);
  const tcpObjectMount = local(
    { web: {}, db: { protocol: "tcp" } },
    {
      web: { publicURL: {}, http: { paths: { "/db": { service: "db" } } } },
      db: { address: 5432 },
    },
  );
  // @ts-expect-error object mounts select HTTP services.
  defineConfig(tcpObjectMount);
  // @ts-expect-error sync object mount factories retain protocols.
  defineConfig(() => tcpObjectMount);
  // @ts-expect-error async object mount factories retain protocols.
  defineConfig(async () => tcpObjectMount);
  const unnamedTCPWebhook = {
    ...tcpWebhook,
    webhooks: { hook: { service: "", path: "/hook", provider: "custom" } },
  } as const;
  // @ts-expect-error TCP declarations do not create unnamed HTTP receivers.
  defineConfig(unnamedTCPWebhook);
  // @ts-expect-error sync factories cannot create unnamed receivers.
  defineConfig(() => unnamedTCPWebhook);
  // @ts-expect-error async factories cannot create unnamed receivers.
  defineConfig(async () => unnamedTCPWebhook);
  const unnamedWebhook = {
    webhooks: { hook: { service: "", path: "/hook", provider: "custom" } },
  } as const;
  // @ts-expect-error receivers require a local public binding.
  defineConfig(unnamedWebhook);
  // @ts-expect-error sync factories require a local public binding.
  defineConfig(() => unnamedWebhook);
  // @ts-expect-error async factories require a local public binding.
  defineConfig(async () => unnamedWebhook);
  const privateAlias = {
    ...local({ web: {} }, { web: {} }),
    aliases: { review: { service: "web" } },
  } as const;
  // @ts-expect-error aliases require an explicit public URL.
  defineConfig(privateAlias);
  // @ts-expect-error sync factories cannot alias private bindings.
  defineConfig(() => privateAlias);
  // @ts-expect-error async factories cannot alias private bindings.
  defineConfig(async () => privateAlias);
  const privateWebhook = {
    ...local({ api: {} }, { api: {} }),
    webhooks: { hook: { service: "api", path: "/hook", provider: "custom" } },
  } as const;
  // @ts-expect-error private HTTP is not a webhook receiver.
  defineConfig(privateWebhook);
  const remote = {
    services: { web: {}, api: {} },
    deployments: { cloud: { targets: { web: { address: 3000 }, api: { address: 4000 } } } },
  } as const;
  defineConfig({
    ...remote,
    deployments: {
      // @ts-expect-error remote assignments cannot honor local readiness.
      cloud: { targets: { web: { address: 3000, http: { readiness: { path: "/health" } } } } },
    },
  });
  defineConfig({
    ...remote,
    deployments: {
      cloud: {
        targets: {
          // @ts-expect-error remote assignments cannot honor local mounts.
          web: { address: 3000, http: { paths: { "/api": "api" } } },
          api: { address: 4000 },
        },
      },
    },
  });
  // @ts-expect-error remote bindings are not local alias entries.
  defineConfig({ ...remote, aliases: { review: { service: "web" } } });

  defineConfig({
    services: { cluster: { protocol: "kubernetes" }, db: { protocol: "postgres" } },
    deployments: {
      production: {
        targets: {
          cluster: { type: "eks", cluster: "development", region: "us-east-1" },
          db: { type: "rds", cluster: "orders", region: "us-east-1", endpoint: "reader" },
        },
      },
    },
    workloads: {
      deploy: {
        deployment: "production",
        github: { workflow: ".github/workflows/deploy.yml", branch: "main", events: ["push"] },
        services: ["cluster", "db"],
        maxDuration: "1h",
      },
    },
  });
  const wrongEKSProtocol = local(
    { cluster: { protocol: "http" } },
    { cluster: { type: "eks", cluster: "development", region: "us-east-1" } },
  );
  // @ts-expect-error EKS targets require the Kubernetes protocol.
  defineConfig(wrongEKSProtocol);
  const instanceReader = local(
    { db: { protocol: "postgres" } },
    { db: { type: "rds", instance: "orders", region: "us-east-1", endpoint: "reader" } },
  );
  // @ts-expect-error RDS reader endpoints require a cluster.
  defineConfig(instanceReader);
  // @ts-expect-error existing sshd services use opaque TCP.
  ({ services: { shell: { protocol: "ssh" } } }) satisfies TnlConfig;
  defineConfig({
    ...remote,
    // @ts-expect-error workloads select bindings in their exact deployment.
    workloads: { ci: { deployment: "cloud", fly: { app: "web" }, services: ["missing"] } },
  });
  const missingDeployment = {
    ...remote,
    workloads: { ci: { deployment: "missing", fly: { app: "web" }, services: ["web"] } },
  } as const;
  // @ts-expect-error deployment selectors must exist.
  defineConfig(missingDeployment);
  const localWorkload = {
    ...local({ web: {}, explicit: {} }, { web: {}, explicit: {} }),
    workloads: { ci: { deployment: "local", fly: { app: "web" }, services: ["web", "explicit"] } },
  } as const;
  // @ts-expect-error provider workloads cannot select local bindings.
  defineConfig(localWorkload);
  // @ts-expect-error sync factories cannot select local workload bindings.
  defineConfig(() => localWorkload);
  // @ts-expect-error async factories cannot select local workload bindings.
  defineConfig(async () => localWorkload);

  defineConfig({
    services: { inventory: {}, models: { protocol: "postgres" } },
    deployments: {
      production: {
        targets: { inventory: { address: 3000 }, models: { address: "localhost:5432" } },
      },
    },
    workloads: {
      storefront: {
        deployment: "production",
        vercel: { team: "acme", project: "store", environment: "production" },
        services: ["inventory", "models"],
      },
      machine: { deployment: "production", fly: { app: "store" }, services: ["inventory"] },
      worker: {
        deployment: "production",
        oidc: { issuer: "https://issuer.example", claims: { sub: "service:store" } },
        token: { file: "/run/provider/token" },
        services: ["models"],
      },
      cloud: {
        deployment: "production",
        google: { serviceAccount: "orders@project.iam.gserviceaccount.com" },
        services: ["models"],
      },
      pod: {
        deployment: "production",
        kubernetes: { serviceAccount: "orders", namespace: "production" },
        services: ["models"],
      },
      gitlab: {
        deployment: "production",
        gitlab: { project: "shop/storefront", pipelineSource: "push" },
        services: ["models"],
      },
    },
  });
  ({
    workloads: {
      mixed: {
        deployment: "production",
        github: { workflow: ".github/workflows/test.yml" },
        // @ts-expect-error a workload selects exactly one provider.
        fly: { app: "worker" },
        services: ["db"],
      },
      // @ts-expect-error a provider block is required.
      missing: { deployment: "production", services: ["db"] },
      old: {
        deployment: "production",
        // @ts-expect-error provider blocks replace the old discriminator.
        provider: "fly",
        fly: { app: "worker" },
        services: ["db"],
      },
      refs: {
        deployment: "production",
        github: {
          workflow: ".github/workflows/test.yml",
          branch: "main",
          // @ts-expect-error branch and tag are mutually exclusive.
          tag: "v1",
        },
        services: ["db"],
      },
      gitlabRefs: {
        deployment: "production",
        gitlab: {
          branch: "main",
          // @ts-expect-error GitLab branch and tag are mutually exclusive.
          tag: "v1",
        },
        services: ["db"],
      },
      gitlabSource: {
        deployment: "production",
        gitlab: {
          // @ts-expect-error GitLab sources are exact known values.
          pipelineSource: "*",
        },
        services: ["db"],
      },
      gitlabDefaults: { deployment: "production", gitlab: {}, services: ["db"] },
      sources: {
        deployment: "production",
        fly: { app: "worker" },
        token: {
          file: "/run/token",
          // @ts-expect-error token file and environment sources are mutually exclusive.
          env: "TOKEN",
        },
        services: ["db"],
      },
      defaults: {
        deployment: "production",
        github: { workflow: ".github/workflows/test.yml" },
        token: { env: "TOKEN" },
        services: ["db"],
      },
    },
  }) satisfies TnlConfig;
  defineConfig({ ...config, inspection: { maxBytes: "1GiB" } });
  // @ts-expect-error TLS belongs on a binding, not a declaration.
  ({ services: { db: { protocol: "tcp", tls: { ca: "system" } } } }) satisfies TnlConfig;
});
