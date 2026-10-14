import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";

type Environment = "staging" | "production";
type Role = "control" | "ingress" | "relay-a" | "relay-b";
const roles: Role[] = ["control", "ingress", "relay-a", "relay-b"];

const serviceSchema = z
  .object({
    protocol: z.enum(["tcp", "udp"]),
    internal_port: z.number().int(),
    ports: z.array(
      z
        .object({
          port: z.number().int().optional(),
          start_port: z.number().int().optional(),
          end_port: z.number().int().optional(),
          handlers: z.array(z.string()).optional(),
          proxy_proto_options: z.object({ version: z.string() }).passthrough().optional(),
        })
        .passthrough(),
    ),
  })
  .passthrough();
const machineSchema = z
  .object({
    id: z.string().min(1),
    state: z.string(),
    image_ref: z.object({ digest: z.string() }),
    config: z
      .object({
        image: z.string().optional(),
        env: z.record(z.string(), z.string()),
        metadata: z.object({ fly_process_group: z.string().optional() }).passthrough().optional(),
        services: z.array(serviceSchema),
      })
      .passthrough(),
  })
  .passthrough();
type Machine = z.infer<typeof machineSchema>;

const relayCounts = z.object({ app: z.number().int().positive(), udp: z.literal(1) });
const countsSchema = z.object({
  control: z.number().int().positive(),
  ingress: z.number().int().positive(),
  "relay-a": relayCounts,
  "relay-b": relayCounts,
});
const topologySchema = z.object({
  organization: z.string().min(1),
  staging: countsSchema,
  production: countsSchema,
});
type RoleCounts = z.infer<typeof countsSchema>;

const flyServiceSchema = serviceSchema.extend({
  processes: z.array(z.enum(["app", "udp"])).optional(),
  auto_stop_machines: z.boolean().optional(),
  auto_start_machines: z.boolean().optional(),
  tcp_checks: z
    .array(
      z
        .object({
          interval: z.string(),
          timeout: z.string(),
          grace_period: z.string(),
        })
        .passthrough(),
    )
    .optional(),
});
const flyConfigSchema = z.object({
  app: z.string(),
  primary_region: z.string(),
  kill_signal: z.string(),
  kill_timeout: z.string().regex(/^[1-9][0-9]*s$/),
  env: z.record(z.string(), z.string()),
  metrics: z.array(z.object({ port: z.number().int(), path: z.string() })).optional(),
  services: z.array(flyServiceSchema),
  vm: z
    .array(
      z.object({
        cpu_kind: z.enum(["shared", "performance"]),
        cpus: z.number().int().positive(),
        memory: z.string(),
      }),
    )
    .length(1),
  processes: z.record(z.string(), z.string()).optional(),
});
type FlyConfig = z.infer<typeof flyConfigSchema>;

export function ingressServicesMatch(
  actual: Machine["config"]["services"],
  expected: FlyConfig["services"],
): boolean {
  const ports = (services: typeof actual) =>
    services.map((service) => ({
      protocol: service.protocol,
      internal_port: service.internal_port,
      ports: service.ports.map((port) => ({
        port: port.port,
        start_port: port.start_port,
        end_port: port.end_port,
        handlers: port.handlers,
        proxy_version: port.proxy_proto_options?.version,
      })),
    }));
  return isDeepStrictEqual(ports(actual), ports(expected));
}

function requireValue(value: string | undefined, pattern: RegExp, name: string): string {
  if (!value || !pattern.test(value)) throw new Error(`invalid ${name}`);
  return value;
}

function run(command: string, args: string[]): string {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env: process.env,
    maxBuffer: 8 * 1024 * 1024,
    timeout: 10 * 60 * 1000,
  });
  if (result.error || result.status !== 0) {
    // docker and flyctl may include connection details in their errors.
    const hint =
      command === "flyctl" ? "check Fly access and app state" : "check the image or database";
    throw new Error(`${command} ${args[0]} ${args[1]} failed; ${hint} before retrying`);
  }
  return result.stdout.trim();
}

function machines(app: string): Machine[] {
  return z
    .array(machineSchema)
    .parse(JSON.parse(run("flyctl", ["machine", "list", "--app", app, "--json"])));
}

function check(app: string, role: Role, count: number, members: Machine[]): void {
  if (members.length !== count || members.some((member) => member.state !== "started")) {
    throw new Error(`${app}: expected ${count} started Machines`);
  }
  const identities = members.map((member) => {
    if (role === "control") return member.id;
    const env = member.config.env;
    if (role === "ingress") return env.TNLD_INGRESS_ID;
    if (
      env.TNLD_RELAY_SERVICE_ID !== role ||
      env.TNLD_INTERNAL_RELAY_ADDRESS !== `${member.id}.vm.${app}.internal:9445`
    )
      throw new Error(`${app}: relay identity or internal address is missing`);
    return env.TNLD_RELAY_ID;
  });
  if (identities.some((identity) => !identity) || new Set(identities).size !== count) {
    throw new Error(`${app}: Machine identities must be distinct`);
  }
  if (role === "control") return;
  if (role === "ingress") return;
  const udp = members.filter((member) => member.config.metadata?.fly_process_group === "udp");
  if (
    udp.length !== 1 ||
    members.some((member) => {
      const group = member.config.metadata?.fly_process_group;
      if (group !== "udp" && group !== "app") return true;
      const services = member.config.services;
      const tcp = services.filter(
        (service) =>
          service.protocol === "tcp" &&
          service.internal_port === 8443 &&
          service.ports.some((port) => port.port === 443),
      );
      const publicUDP = services.filter(
        (service) =>
          service.protocol === "udp" &&
          service.internal_port === 443 &&
          service.ports.some((port) => port.port === 443),
      );
      return (
        tcp.length !== 1 ||
        publicUDP.length !== (group === "udp" ? 1 : 0) ||
        services.length !== (group === "udp" ? 2 : 1)
      );
    })
  )
    throw new Error(`${app}: expected one public UDP receiver and TCP on every relay`);
}

function directURL(environment: Environment): void {
  if (process.env.TNLD_DATABASE_BRANCH !== environment) {
    throw new Error(`database branch does not match ${environment}`);
  }
  const raw = process.env.TNLD_DATABASE_DIRECT_URL;
  if (!raw) throw new Error("missing direct control database URL");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("invalid direct control database URL");
  }
  if (
    !["postgres:", "postgresql:"].includes(url.protocol) ||
    !url.username ||
    !url.password ||
    url.pathname.length < 2 ||
    url.hostname.includes("pooler")
  )
    throw new Error("expected a direct PostgreSQL migration URL");
}

function platformDigest(image: string): string {
  const index = z
    .object({
      manifests: z.array(
        z.object({
          digest: z.string(),
          platform: z.object({ os: z.string(), architecture: z.string() }).optional(),
        }),
      ),
    })
    .parse(JSON.parse(run("docker", ["buildx", "imagetools", "inspect", "--raw", image])));
  const digests = index.manifests
    .filter((entry) => entry.platform?.os === "linux" && entry.platform.architecture === "amd64")
    .map((entry) => entry.digest);
  const [digest] = digests;
  if (digests.length !== 1 || !digest || !/^sha256:[a-f0-9]{64}$/.test(digest)) {
    throw new Error("server image needs one Linux amd64 platform");
  }
  return digest;
}

function countFor(counts: RoleCounts, role: Role): number {
  const value = counts[role];
  return typeof value === "number" ? value : value.app + value.udp;
}

function appConfig(app: string): FlyConfig {
  const config = flyConfigSchema.parse(
    JSON.parse(
      run("flyctl", ["config", "show", "--local", "--config", `deploy/server/fly.${app}.toml`]),
    ),
  );
  if (config.app !== app) throw new Error(`${app}: manifest names a different app`);
  return config;
}

function ensureApps(organization: string, environment: Environment): void {
  const apps = z
    .array(z.object({ Name: z.string() }))
    .parse(JSON.parse(run("flyctl", ["apps", "list", "--org", organization, "--json"])));
  const names = new Set(apps.map((app) => app.Name));
  for (const role of roles) {
    const app = `tnl-${role}-${environment}`;
    if (!names.has(app)) run("flyctl", ["apps", "create", app, "--org", organization, "--yes"]);
    const ips = z
      .array(z.object({ Type: z.string() }))
      .parse(JSON.parse(run("flyctl", ["ips", "list", "--app", app, "--json"])));
    if (!ips.some((ip) => ip.Type === "v4"))
      run("flyctl", ["ips", "allocate-v4", "--app", app, "--yes"]);
    if (!ips.some((ip) => ip.Type === "v6")) run("flyctl", ["ips", "allocate-v6", "--app", app]);
  }
}

function ensureSecrets(environment: Environment): void {
  for (const role of roles) {
    const app = `tnl-${role}-${environment}`;
    const names = new Set(
      z
        .array(z.object({ name: z.string() }))
        .parse(JSON.parse(run("flyctl", ["secrets", "list", "--app", app, "--json"])))
        .map((secret) => secret.name),
    );
    const required =
      role === "control"
        ? ["TNLD_DATABASE_URL", "TNLD_STORAGE_KEY", "TNLD_CLUSTER_SECRET"]
        : ["TNLD_CLUSTER_SECRET"];
    const missing = required.filter((name) => !names.has(name));
    if (missing.length > 0)
      throw new Error(`${app}: set Fly secrets ${missing.join(", ")} and rerun deployment`);
  }
}

function machineSettings(
  config: FlyConfig,
  role: Role,
  group: "app" | "udp",
  imageTag: string,
  member?: Machine,
) {
  const vm = config.vm[0];
  const memory = vm && /^([0-9]+)mb$/.exec(vm.memory)?.[1];
  if (!vm || !memory) throw new Error(`${config.app}: unsupported Machine memory setting`);
  const env: Record<string, string> = {
    ...config.env,
    FLY_PROCESS_GROUP: group,
    PRIMARY_REGION: config.primary_region,
  };
  if (role === "ingress")
    env.TNLD_INGRESS_ID =
      member?.config.env.TNLD_INGRESS_ID ?? `ingress-${randomBytes(8).toString("hex")}`;
  if (role.startsWith("relay-")) {
    env.TNLD_RELAY_ID =
      member?.config.env.TNLD_RELAY_ID ?? `${role}-${randomBytes(8).toString("hex")}`;
    if (member) env.TNLD_INTERNAL_RELAY_ADDRESS = `${member.id}.vm.${config.app}.internal:9445`;
  }
  const services = config.services
    .filter((service) => !service.processes || service.processes.includes(group))
    .map((service) => {
      const {
        processes: _processes,
        auto_stop_machines,
        auto_start_machines,
        tcp_checks,
        ...settings
      } = service;
      return {
        ...settings,
        ...(auto_stop_machines !== undefined ? { autostop: auto_stop_machines } : {}),
        ...(auto_start_machines !== undefined ? { autostart: auto_start_machines } : {}),
        ...(tcp_checks ? { checks: tcp_checks.map((check) => ({ ...check, type: "tcp" })) } : {}),
      };
    });
  return {
    image: imageTag,
    env,
    guest: { cpu_kind: vm.cpu_kind, cpus: vm.cpus, memory_mb: Number(memory) },
    metadata: member?.config.metadata ?? { fly_process_group: group },
    services,
    ...(config.metrics?.[0] ? { metrics: config.metrics[0] } : {}),
    stop_config: { signal: config.kill_signal, timeout: config.kill_timeout },
    ...(!member && config.processes?.[group] ? { init: { cmd: [config.processes[group]] } } : {}),
  };
}

function createMachine(
  app: string,
  role: Role,
  group: "app" | "udp",
  config: FlyConfig,
  imageTag: string,
  digest: string,
): void {
  const before = new Set(machines(app).map((machine) => machine.id));
  const settings = machineSettings(config, role, group, imageTag);
  run("flyctl", [
    "machine",
    "create",
    imageTag,
    "--app",
    app,
    "--region",
    config.primary_region,
    "--machine-config",
    JSON.stringify(settings),
  ]);
  const added = machines(app).filter((machine) => !before.has(machine.id));
  const [machine] = added;
  if (added.length !== 1 || !machine) throw new Error(`${app}: could not identify new Machine`);
  if (machine.image_ref.digest !== digest)
    throw new Error(`${app}: new Machine has the wrong image`);
  run("flyctl", ["machine", "wait", machine.id, "--app", app, "--state", "stopped"]);
  if (role.startsWith("relay-")) {
    run("flyctl", [
      "machine",
      "update",
      machine.id,
      "--app",
      app,
      "--skip-start",
      "--yes",
      "--env",
      `TNLD_INTERNAL_RELAY_ADDRESS=${machine.id}.vm.${app}.internal:9445`,
    ]);
  }
  run("flyctl", ["machine", "start", machine.id, "--app", app]);
  run("flyctl", [
    "machine",
    "wait",
    machine.id,
    "--app",
    app,
    "--state",
    "started",
    "--wait-timeout",
    "3m",
  ]);
}

function updateMachine(
  app: string,
  role: Role,
  config: FlyConfig,
  digest: string,
  member: Machine,
  skipStart = false,
): void {
  const group = member.config.metadata?.fly_process_group === "udp" ? "udp" : "app";
  const settings = machineSettings(config, role, group, `ghcr.io/tnldotdev/tnl@${digest}`, member);
  if (
    member.image_ref.digest === digest &&
    isDeepStrictEqual(member.config.env, settings.env) &&
    (role !== "ingress" || ingressServicesMatch(member.config.services, settings.services))
  )
    return;
  run("flyctl", [
    "machine",
    "update",
    member.id,
    "--app",
    app,
    "--machine-config",
    JSON.stringify({ ...member.config, ...settings }),
    "--yes",
    ...(skipStart ? ["--skip-start"] : []),
  ]);
  if (!skipStart)
    run("flyctl", [
      "machine",
      "wait",
      member.id,
      "--app",
      app,
      "--state",
      "started",
      "--wait-timeout",
      "3m",
    ]);
}

function ensureMachines(
  app: string,
  role: Role,
  counts: RoleCounts,
  config: FlyConfig,
  imageTag: string,
  digest: string,
): void {
  const existing = machines(app);
  if (existing.length > countFor(counts, role))
    throw new Error(`${app}: more Machines than configured`);
  const desiredGroups = role.startsWith("relay-") ? (["app", "udp"] as const) : (["app"] as const);
  for (const group of desiredGroups) {
    const desired = role.startsWith("relay-")
      ? counts[role as "relay-a" | "relay-b"][group]
      : countFor(counts, role);
    const current = role.startsWith("relay-")
      ? existing.filter((machine) => machine.config.metadata?.fly_process_group === group).length
      : existing.length;
    if (current > desired) throw new Error(`${app}: more ${group} Machines than configured`);
    for (let index = current; index < desired; index++)
      createMachine(app, role, group, config, imageTag, digest);
  }
  for (const machine of machines(app)) {
    if (machine.state === "started") continue;
    if (
      role.startsWith("relay-") &&
      machine.config.env.TNLD_INTERNAL_RELAY_ADDRESS !== `${machine.id}.vm.${app}.internal:9445`
    ) {
      run("flyctl", ["machine", "wait", machine.id, "--app", app, "--state", "stopped"]);
      run("flyctl", [
        "machine",
        "update",
        machine.id,
        "--app",
        app,
        "--skip-start",
        "--yes",
        "--env",
        `TNLD_INTERNAL_RELAY_ADDRESS=${machine.id}.vm.${app}.internal:9445`,
      ]);
    }
    const current = machines(app).find((member) => member.id === machine.id);
    if (!current) throw new Error(`${app}: Machine disappeared during startup`);
    updateMachine(app, role, config, digest, current, true);
    run("flyctl", ["machine", "start", machine.id, "--app", app]);
    run("flyctl", [
      "machine",
      "wait",
      machine.id,
      "--app",
      app,
      "--state",
      "started",
      "--wait-timeout",
      "3m",
    ]);
  }
  check(app, role, countFor(counts, role), machines(app));
}

function deploy(
  environment: Environment,
  digest: string,
  counts: RoleCounts,
  imageTag: string,
): void {
  for (const role of roles) {
    const app = `tnl-${role}-${environment}`;
    appConfig(app);
    run("flyctl", ["config", "validate", "-c", `deploy/server/fly.${app}.toml`]);
  }
  const deployOrder: readonly Role[] = machines(`tnl-control-${environment}`).length
    ? ["ingress", "control", "relay-a", "relay-b"]
    : roles;
  for (const role of deployOrder) {
    const app = `tnl-${role}-${environment}`;
    const manifest = appConfig(app);
    ensureMachines(app, role, counts, manifest, imageTag, digest);
    for (const member of machines(app).sort(
      (a, b) =>
        Number(a.config.metadata?.fly_process_group === "udp") -
        Number(b.config.metadata?.fly_process_group === "udp"),
    )) {
      updateMachine(app, role, manifest, digest, member);
    }
    const current = machines(app);
    check(app, role, countFor(counts, role), current);
    if (current.some((member) => member.image_ref.digest !== digest)) {
      throw new Error(`${app}: Machines are not all on the selected image`);
    }
  }
}

function main(): void {
  try {
    const [environmentArg, imageArg, versionArg, commitArg] = process.argv.slice(2);
    const environment = requireValue(
      environmentArg,
      /^(staging|production)$/,
      "environment",
    ) as Environment;
    const image = requireValue(
      imageArg,
      /^ghcr\.io\/tnldotdev\/tnl@sha256:[a-f0-9]{64}$/,
      "image digest",
    );
    const version = requireValue(
      versionArg,
      /^(?:main-[a-f0-9]{40}|[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?)$/,
      "version",
    );
    const commit = requireValue(commitArg, /^[a-f0-9]{40}$/, "commit");
    if (environment === "staging" ? version !== `main-${commit}` : version.startsWith("main-")) {
      throw new Error("image version does not match the deployment environment");
    }
    directURL(environment);
    const topology = topologySchema.parse(
      JSON.parse(readFileSync("deploy/server/process-counts.json", "utf8")),
    );
    const installed = run("docker", ["run", "--rm", image, "version"]);
    if (installed !== `tnld ${version} (${commit})`)
      throw new Error("image version or commit does not match deployment");
    const digest = platformDigest(image);
    ensureApps(topology.organization, environment);
    ensureSecrets(environment);
    run("docker", ["run", "--rm", "--env", "TNLD_DATABASE_DIRECT_URL", image, "migrate"]);
    const imageTag = `ghcr.io/tnldotdev/tnl:${environment === "staging" ? `sha-${commit}` : `v${version}`}`;
    deploy(environment, digest, topology[environment], imageTag);
    process.stdout.write(`${environment} tnld ${version} deployed from ${image}\n`);
  } catch (error) {
    process.stderr.write(
      `server deployment: ${error instanceof Error ? error.message : "unexpected failure"}\n`,
    );
    process.exitCode = 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) main();
