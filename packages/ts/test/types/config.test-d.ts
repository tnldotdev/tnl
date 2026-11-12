import {
  defineConfig,
  type TnlConfig,
  type TnlConfigContext,
  type TnlConfigForServices,
  type TnlRatePeriod,
  type TnlByteSize,
} from "@tnldotdev/tnl/config";
import { assert, assertType, expectTypeOf, test } from "vitest";

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
  environments: {
    local: {
      targets: {
        web: {
          publicURL: {},
          http: {
            open: true,
            readiness: { path: "/health" },
            paths: { "/api": "api", "/v1": { service: "api", stripPrefix: true } },
          },
        },
        api: {
          name: "api-preview",
          publicURL: {},
          address: "https://localhost:4000",
          tls: { caFile: "./ca.pem", hostname: "localhost" },
        },
        db: { discovery: { type: "compose", service: "db", port: 5432 } },
        cache: {
          name: "shared-cache",
          discovery: { type: "docker", container: "shop-cache", port: 6379 },
        },
      },
    },
    staging: {
      server: "https://staging.example",
      targets: {
        web: { address: 3000 },
        api: { address: "http://api.internal:3000" },
        db: { address: "db.staging.internal:5432", tls: {} },
        cache: { address: "cache.internal:6379" },
      },
      workloads: {
        accounts: {
          vercel: { project: "tnl-accounts-staging", environment: "production" },
          visit: ["db"],
        },
      },
    },
  },
  collections: { customers: {} },
  aliases: { review: { service: "web" } },
  webhooks: { payments: { service: "api", path: "/hooks/payments", provider: "stripe" } },
});

export const factory = defineConfig(({ worktree, project, env, cwd }) => ({
  services: { web: {}, api: {}, db: { protocol: "postgres" } },
  environments: {
    local: {
      targets: {
        web: { publicURL: {}, address: 3000, http: { paths: { "/api": "api" } } },
        api: {
          name: `${env.USER ?? "user"}-${worktree.label.id}-${cwd.length}-${project.relativeDirectory.length}`,
        },
        db: { discovery: { type: "compose", service: "db", port: 5432 } },
      },
    },
  },
  aliases: { review: { service: "web" } },
}));
export const asyncFactory = defineConfig(async ({ worktree }) => ({
  services: { web: { protocol: "http" }, db: { protocol: "tcp" } },
  environments: {
    local: {
      targets: {
        web: { publicURL: {}, name: worktree.label.id, address: 3000 },
        db: { discovery: { type: "docker", container: "cache", port: 6379 } },
      },
    },
  },
}));
declare const factoryResult: Awaited<ReturnType<typeof factory>>;
declare const asyncResult: Awaited<ReturnType<typeof asyncFactory>>;
test("configuration and ordinary factories preserve literals without casts", () => {
  expectTypeOf(config.services.db.protocol).toEqualTypeOf<"postgres">();
  expectTypeOf(config.environments.local.targets.cache.name).toEqualTypeOf<"shared-cache">();
  expectTypeOf(config.environments.local.targets.api.name).toEqualTypeOf<"api-preview">();
  expectTypeOf(config.environments.local.targets.web.http.paths["/api"]).toEqualTypeOf<"api">();
  expectTypeOf(factoryResult.services.db.protocol).toEqualTypeOf<"postgres">();
  expectTypeOf(
    factoryResult.environments.local.targets.db.discovery.type,
  ).toEqualTypeOf<"compose">();
  expectTypeOf(
    factoryResult.environments.local.targets.web.http.paths["/api"],
  ).toEqualTypeOf<"api">();
  expectTypeOf(asyncResult.services.web.protocol).toEqualTypeOf<"http">();
  expectTypeOf(asyncResult.environments.local.targets.db.discovery.type).toEqualTypeOf<"docker">();
  expectTypeOf(factoryResult.aliases.review.service).toEqualTypeOf<"web">();
  assertType<TnlConfig>(config);
  defineConfig({ ...config, inspection: { maxBytes: "1GiB" } });
  ({
    services: { db: { protocol: "postgres" } },
    environments: { staging: { targets: { db: { address: "db:5432" } } } },
  }) satisfies TnlConfigForServices<"db">;
});

declare const context: TnlConfigContext;
declare const services: NonNullable<TnlConfig["services"]>;
test("context and arbitrary lookups preserve absence and units", () => {
  expectTypeOf(context.env.ARBITRARY).toEqualTypeOf<string | undefined>();
  expectTypeOf(context.worktree.label.checkout).toEqualTypeOf<string | undefined>();
  expectTypeOf(context.project.relativeDirectory).toEqualTypeOf<string>();
  // @ts-expect-error arbitrary service keys may be absent.
  services.arbitrary.protocol satisfies unknown;
  assert(services.arbitrary !== undefined);
  assertType<unknown>(services.arbitrary.protocol);
  assertType<TnlRatePeriod>("1h30m");
  assertType<TnlRatePeriod>("1h2m3s4ms");
  assertType<TnlByteSize>("1024KiB");
  // @ts-expect-error duration units are required.
  "minute" satisfies TnlRatePeriod;
  // @ts-expect-error byte sizes use whole binary units.
  "1.5MB" satisfies TnlByteSize;
});

test("retired group and service-target syntax is rejected, including inferred factories", () => {
  const groups = { publisherGroups: { customer: { template: true } } } as const;
  // @ts-expect-error collections replace publisher groups, not their spelling.
  defineConfig(groups);
  // @ts-expect-error factories cannot revive group/template syntax.
  defineConfig(() => groups);
  // @ts-expect-error async factories cannot revive group/template syntax.
  defineConfig(async () => groups);
  const deployment = {
    publisherGroups: {
      production: { aws: { replicas: 2, vpcId: "vpc-12345678" }, type: "self-hosted" },
    },
  } as const;
  // @ts-expect-error infrastructure deployment settings are not configuration.
  defineConfig(deployment);
  // @ts-expect-error deployment settings remain forbidden in factories.
  defineConfig(() => deployment);
  const template = {
    services: { db: { protocol: "postgres", publisherGroup: "customer", targetBinding: "group" } },
  } as const;
  // @ts-expect-error definitions contain neither publisher assignments nor target-binding templates.
  defineConfig(template);
  // @ts-expect-error factories reject removed target authority too.
  defineConfig(() => template);
  // @ts-expect-error async factories reject removed target authority too.
  defineConfig(async () => template);
  const rootTarget = {
    services: { db: { protocol: "postgres", target: { type: "address", address: 5432 } } },
  } as const;
  // @ts-expect-error targets belong in environments, not service definitions.
  rootTarget satisfies TnlConfig;
  // @ts-expect-error root workload permissions have been removed.
  defineConfig({ workloads: {} });
  // @ts-expect-error collections contain no second service schema or template.
  defineConfig({ collections: { customers: { template: true, services: { db: {} } } } });
  // @ts-expect-error public service directories have been removed.
  ({ services: { web: { directory: "apps/web" } } }) satisfies TnlConfig;
  // @ts-expect-error root publication settings have been removed.
  ({ publish: { target: 3000 } }) satisfies TnlConfig;
  // @ts-expect-error readiness belongs to local target HTTP settings.
  ({ readiness: { path: "/" } }) satisfies TnlConfig;
  // @ts-expect-error flat limits have been removed.
  ({ publicURL: { limits: { requests: 3 } } }) satisfies TnlConfig;
  // @ts-expect-error browser opening is not public URL policy.
  ({ publicURL: { open: true } }) satisfies TnlConfig;
  // @ts-expect-error publisher placement is not project configuration.
  ({ publisherGroup: { type: "host", port: 8765 } }) satisfies TnlConfig;
  // @ts-expect-error publisher placement is not project configuration.
  ({ publisherGroup: { type: "compose", service: "publisher", port: 8765 } }) satisfies TnlConfig;
  // @ts-expect-error combined byte totals have been removed.
  ({ publicURL: { limits: { traffic: { totalBytes: 1024 } } } }) satisfies TnlConfig;
  const byteRate = {
    publicURL: { limits: { traffic: { rate: { bytes: 1024, per: "1s" } } } },
  } as const;
  // @ts-expect-error combined byte rates have been removed.
  byteRate satisfies TnlConfig;
  // @ts-expect-error protocol limits require duration-literal periods.
  ({ publicURL: { limits: { tcp: { rate: { count: 1, per: "minute" } } } } }) satisfies TnlConfig;
  // @ts-expect-error TypeScript configuration has an implicit version.
  defineConfig({ version: 1 });
  // @ts-expect-error daemon configuration is static-only.
  defineConfig({ tnld: { role: "relay" } });
  // @ts-expect-error existing sshd uses opaque tcp, not a separate protocol.
  ({ services: { shell: { protocol: "ssh" } } }) satisfies TnlConfig;
});

test("target variants remain disjoint for objects and both factory forms", () => {
  // @ts-expect-error ordinary factory returns cannot mix destination authorities.
  defineConfig(() => ({
    services: { web: {} },
    environments: {
      local: {
        targets: {
          web: { address: 3000, discovery: { type: "docker", container: "web", port: 3000 } },
        },
      },
    },
  }));
  // @ts-expect-error ordinary async returns cannot mix destination authorities.
  defineConfig(async () => ({
    services: { web: {} },
    environments: {
      local: {
        targets: {
          web: { address: 3000, discovery: { type: "docker", container: "web", port: 3000 } },
        },
      },
    },
  }));
  const mixed = {
    services: { web: {} },
    environments: {
      local: {
        targets: {
          web: { address: 3000, discovery: { type: "docker", container: "web", port: 3000 } },
        },
      },
    },
  } as const;
  // @ts-expect-error address and discovery are mutually exclusive.
  mixed satisfies TnlConfig;
  // @ts-expect-error non-fresh mixed targets are rejected.
  defineConfig(mixed);
  // @ts-expect-error factories cannot mix address and discovery.
  defineConfig(() => mixed);
  // @ts-expect-error async factories cannot mix address and discovery.
  defineConfig(async () => mixed);
  const compose = {
    services: { db: { protocol: "postgres" } },
    environments: {
      local: {
        targets: {
          db: { discovery: { type: "compose", service: "db", port: 5432, container: "db" } },
        },
      },
    },
  } as const;
  // @ts-expect-error Compose targets cannot contain Docker fields.
  compose satisfies TnlConfig;
  // @ts-expect-error inferred Compose targets are exact.
  defineConfig(compose);
  // @ts-expect-error synchronous factories preserve discovery exactness.
  defineConfig(() => compose);
  // @ts-expect-error asynchronous factories preserve discovery exactness.
  defineConfig(async () => compose);
  const docker = {
    services: { db: { protocol: "tcp" } },
    environments: {
      local: {
        targets: {
          db: { discovery: { type: "docker", container: "db", port: 3306, address: "db:3306" } },
        },
      },
    },
  } as const;
  // @ts-expect-error Docker discovery cannot contain address fields.
  docker satisfies TnlConfig;
  // @ts-expect-error inferred Docker targets remain exact.
  defineConfig(docker);
  // @ts-expect-error factory Docker targets remain exact.
  defineConfig(() => docker);
  // @ts-expect-error async factory Docker targets remain exact.
  defineConfig(async () => docker);
  const missingPort = {
    environments: { local: { targets: { db: { discovery: { type: "compose", service: "db" } } } } },
  } as const;
  // @ts-expect-error Compose discovery requires a private port.
  missingPort satisfies TnlConfig;
  const dockerWithoutPort = {
    environments: {
      local: { targets: { db: { discovery: { type: "docker", container: "db" } } } },
    },
  } as const;
  // @ts-expect-error Docker discovery requires a private port.
  dockerWithoutPort satisfies TnlConfig;
  const duplicateName = {
    services: { web: {} },
    environments: { local: { targets: { web: { name: "site", publicURL: { name: "other" } } } } },
  } as const;
  // @ts-expect-error saved names are never duplicated in publicURL.
  duplicateName satisfies TnlConfig;
  // @ts-expect-error inferred duplicate public names are rejected.
  defineConfig(duplicateName);
  // @ts-expect-error factories reject duplicate public names.
  defineConfig(() => duplicateName);
  const pool = {
    environments: { local: { targets: { web: { publicURL: { publisherPool: true } } } } },
  } as const;
  // @ts-expect-error publisherPool is not public URL policy.
  pool satisfies TnlConfig;
  // @ts-expect-error inferred publisherPool is rejected.
  defineConfig(pool);
  const passthrough = {
    environments: { local: { targets: { web: { address: 3000, tls: { passthrough: true } } } } },
  } as const;
  // @ts-expect-error target TLS cannot request visitor passthrough.
  passthrough satisfies TnlConfig;
  const authentication = {
    environments: { local: { targets: { api: { address: "https://api.example", auth: {} } } } },
  } as const;
  // @ts-expect-error application authentication is not target configuration.
  defineConfig(authentication);
  // @ts-expect-error service-level TLS has been removed.
  ({ services: { db: { protocol: "tcp", tls: { ca: "system" } } } }) satisfies TnlConfig;
});

test("references retain protocol, locality, and explicit public URL intent", () => {
  const privateAlias = { services: { web: {} }, aliases: { review: { service: "web" } } } as const;
  // @ts-expect-error aliases require an explicit local publicURL entry.
  defineConfig(privateAlias);
  // @ts-expect-error synchronous factories cannot alias private HTTP.
  defineConfig(() => privateAlias);
  // @ts-expect-error asynchronous factories cannot alias private HTTP.
  defineConfig(async () => privateAlias);
  const tcp = {
    services: { db: { protocol: "tcp" } },
    environments: { local: { targets: { db: { address: 5432 } } } },
    aliases: { review: { service: "db" } },
  } as const;
  // @ts-expect-error aliases select HTTP only.
  defineConfig(tcp);
  // @ts-expect-error factory aliases select HTTP only.
  defineConfig(() => tcp);
  // @ts-expect-error async factory aliases select HTTP only.
  defineConfig(async () => tcp);
  const webhook = {
    ...tcp,
    aliases: {},
    webhooks: { hook: { service: "db", path: "/hook", provider: "custom" } },
  } as const;
  // @ts-expect-error webhooks select public local HTTP only.
  defineConfig(webhook);
  // @ts-expect-error factory webhooks cannot select TCP.
  defineConfig(() => webhook);
  // @ts-expect-error async factory webhooks cannot select TCP.
  defineConfig(async () => webhook);
  const unnamed = {
    webhooks: { hook: { service: "", path: "/hook", provider: "custom" } },
  } as const;
  // @ts-expect-error no unnamed webhook receiver is invented.
  defineConfig(unnamed);
  // @ts-expect-error synchronous factories cannot invent unnamed HTTP.
  defineConfig(() => unnamed);
  // @ts-expect-error asynchronous factories cannot invent unnamed HTTP.
  defineConfig(async () => unnamed);
  const mount = {
    services: { web: {}, db: { protocol: "tcp" } },
    environments: {
      local: {
        targets: {
          web: { publicURL: {}, http: { paths: { "/db": "db" } } },
          db: { address: 5432 },
        },
      },
    },
  } as const;
  // @ts-expect-error string mounts cannot select TCP services.
  defineConfig(mount);
  // @ts-expect-error factory string mounts cannot select TCP.
  defineConfig(() => mount);
  // @ts-expect-error async factory string mounts cannot select TCP.
  defineConfig(async () => mount);
  const objectMount = {
    ...mount,
    environments: {
      local: {
        targets: {
          web: { publicURL: {}, http: { paths: { "/db": { service: "db" } } } },
          db: { address: 5432 },
        },
      },
    },
  } as const;
  // @ts-expect-error object mounts cannot select TCP services.
  defineConfig(objectMount);
  // @ts-expect-error factory object mounts cannot select TCP.
  defineConfig(() => objectMount);
  // @ts-expect-error async factory object mounts cannot select TCP.
  defineConfig(async () => objectMount);
  const unknown = {
    services: { api: {}, web: {} },
    environments: {
      local: { targets: { web: { publicURL: {}, http: { paths: { "/api": "missing" } } } } },
    },
  } as const;
  // @ts-expect-error string mounts name another configured service.
  defineConfig(unknown);
  // @ts-expect-error factory references retain the configured names.
  defineConfig(() => unknown);
  // @ts-expect-error async factory references retain the configured names.
  defineConfig(async () => unknown);
  const self = {
    services: { api: {} },
    environments: {
      local: { targets: { api: { publicURL: {}, http: { paths: { "/api": "api" } } } } },
    },
  } as const;
  // @ts-expect-error services cannot mount themselves.
  defineConfig(self);
  const tcpHTTP = {
    services: { db: { protocol: "tcp" } },
    environments: { local: { targets: { db: { address: 5432, http: { open: true } } } } },
  } as const;
  // @ts-expect-error TCP cannot have HTTP settings.
  defineConfig(tcpHTTP);
  // @ts-expect-error factory protocol checks do not widen away failures.
  defineConfig(() => tcpHTTP);
  // @ts-expect-error async factory protocol checks do not widen away failures.
  defineConfig(async () => tcpHTTP);
  const missingTCP = {
    services: { db: { protocol: "tcp" } },
    environments: { local: { targets: { db: {} } } },
  } as const;
  // @ts-expect-error a selected local TCP target needs a destination.
  defineConfig(missingTCP);
  // @ts-expect-error factories cannot turn TCP into an app listener.
  defineConfig(() => missingTCP);
  // @ts-expect-error async factories cannot turn TCP into an app listener.
  defineConfig(async () => missingTCP);
  const remoteReadiness = {
    services: { web: {} },
    environments: {
      staging: { targets: { web: { address: 3000, http: { readiness: { path: "/health" } } } } },
    },
  } as const;
  // @ts-expect-error remote publishers cannot honor local readiness settings.
  defineConfig(remoteReadiness);
  const remoteMount = {
    services: { web: {}, api: {} },
    environments: {
      staging: {
        targets: {
          web: { address: 3000, http: { paths: { "/api": "api" } } },
          api: { address: 4000 },
        },
      },
    },
  } as const;
  // @ts-expect-error remote publishers cannot honor local path mounts.
  defineConfig(remoteMount);
  // @ts-expect-error unknown aliases are rejected in ordinary factories too.
  defineConfig(() => ({ services: { api: {} }, aliases: { review: { service: "missing" } } }));
});

test("workloads declare one provider and explicit environment service rights", () => {
  // @ts-expect-error ordinary async factories retain the visit service allowlist.
  defineConfig(async () => ({
    services: { db: { protocol: "postgres" } },
    environments: {
      staging: {
        targets: { db: { address: 5432 } },
        workloads: { worker: { fly: { app: "worker" }, visit: ["missing"] } },
      },
    },
  }));
  defineConfig({
    services: { cluster: { protocol: "kubernetes" }, db: { protocol: "postgres" } },
    environments: {
      staging: {
        targets: {
          cluster: { discovery: { type: "eks", cluster: "development", region: "us-east-1" } },
          db: {
            discovery: { type: "rds", cluster: "orders", region: "us-east-1", endpoint: "reader" },
          },
        },
        workloads: {
          deploy: {
            github: { workflow: ".github/workflows/deploy.yml", branch: "main", events: ["push"] },
            visit: ["cluster", "db"],
            maxDuration: "1h",
          },
          storefront: {
            vercel: { team: "acme", project: "store", environment: "production" },
            visit: ["db"],
          },
          machine: { fly: { app: "store" }, visit: ["db"] },
          worker: {
            oidc: { issuer: "https://issuer.example", claims: { sub: "service:store" } },
            token: { file: "/run/provider/token" },
            visit: ["db"],
          },
          cloud: {
            google: { serviceAccount: "orders@project.iam.gserviceaccount.com" },
            visit: ["db"],
          },
          pod: { kubernetes: { serviceAccount: "orders", namespace: "production" }, visit: ["db"] },
          pipeline: {
            gitlab: { project: "shop/storefront", pipelineSource: "push" },
            visit: ["db"],
          },
          defaults: { gitlab: {}, visit: ["db"] },
        },
      },
    },
  });
  const unknown = {
    services: { db: { protocol: "postgres" } },
    environments: {
      staging: {
        targets: { db: { address: 5432 } },
        workloads: { worker: { fly: { app: "worker" }, visit: ["missing"] } },
      },
    },
  } as const;
  // @ts-expect-error visit selects existing service keys in this environment.
  defineConfig(unknown);
  // @ts-expect-error sync factories retain explicit visit service names.
  defineConfig(() => unknown);
  // @ts-expect-error async factories retain explicit visit service names.
  defineConfig(async () => unknown);
  const local = {
    services: { db: { protocol: "postgres" } },
    environments: { local: { workloads: { worker: { fly: { app: "worker" }, visit: ["db"] } } } },
  } as const;
  // @ts-expect-error local app listeners do not establish workload permissions.
  defineConfig(local);
  // @ts-expect-error local workload permissions are rejected in factories.
  defineConfig(() => local);
  // @ts-expect-error local workload permissions are rejected in async factories.
  defineConfig(async () => local);
  const eks = {
    services: { cluster: { protocol: "http" } },
    environments: {
      staging: {
        targets: {
          cluster: { discovery: { type: "eks", cluster: "development", region: "us-east-1" } },
        },
      },
    },
  } as const;
  // @ts-expect-error EKS requires the kubernetes protocol.
  defineConfig(eks);
  const rds = {
    services: { db: { protocol: "postgres" } },
    environments: {
      staging: {
        targets: {
          db: {
            discovery: { type: "rds", instance: "orders", region: "us-east-1", endpoint: "reader" },
          },
        },
      },
    },
  } as const;
  // @ts-expect-error RDS reader endpoints require a cluster.
  defineConfig(rds);
  const mixed = {
    services: { db: {} },
    environments: {
      staging: {
        targets: { db: { address: 3000 } },
        workloads: {
          worker: {
            github: { workflow: ".github/workflows/test.yml" },
            fly: { app: "worker" },
            visit: ["db"],
          },
        },
      },
    },
  } as const;
  // @ts-expect-error workloads select exactly one provider block.
  mixed satisfies TnlConfig;
  // @ts-expect-error inferred mixed provider objects are rejected.
  defineConfig(mixed);
  // @ts-expect-error factory inference cannot widen mixed providers to TnlConfig.
  defineConfig(() => mixed);
  // @ts-expect-error async factory inference cannot widen mixed providers.
  defineConfig(async () => mixed);
  const noProvider = {
    environments: { staging: { workloads: { missing: { visit: ["db"] } } } },
  } as const;
  // @ts-expect-error every workload needs a provider block.
  noProvider satisfies TnlConfig;
  const providerDiscriminator = {
    environments: {
      staging: {
        workloads: { worker: { provider: "fly", fly: { app: "worker" }, visit: ["db"] } },
      },
    },
  } as const;
  // @ts-expect-error provider blocks replace the old discriminator.
  defineConfig(providerDiscriminator);
  const githubRefs = {
    environments: {
      staging: {
        workloads: {
          worker: {
            github: { workflow: ".github/workflows/test.yml", branch: "main", tag: "v1" },
            visit: ["db"],
          },
        },
      },
    },
  } as const;
  // @ts-expect-error GitHub branch and tag are mutually exclusive.
  githubRefs satisfies TnlConfig;
  const gitlabRefs = {
    environments: {
      staging: { workloads: { worker: { gitlab: { branch: "main", tag: "v1" }, visit: ["db"] } } },
    },
  } as const;
  // @ts-expect-error GitLab branch and tag are mutually exclusive.
  gitlabRefs satisfies TnlConfig;
  const wildcardSource = {
    environments: {
      staging: { workloads: { worker: { gitlab: { pipelineSource: "*" }, visit: ["db"] } } },
    },
  } as const;
  // @ts-expect-error GitLab pipeline sources are exact known values.
  wildcardSource satisfies TnlConfig;
  const tokens = {
    environments: {
      staging: {
        workloads: {
          worker: {
            fly: { app: "worker" },
            token: { file: "/run/token", env: "TOKEN" },
            visit: ["db"],
          },
        },
      },
    },
  } as const;
  // @ts-expect-error token file and environment variable are mutually exclusive.
  tokens satisfies TnlConfig;
});
