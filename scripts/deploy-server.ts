import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { connect } from "node:tls";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { z } from "zod";

const roles = ["control", "ingress", "relay-a", "relay-b"] as const;
type Role = (typeof roles)[number];
type Environment = "staging" | "production";
const digest = /^ghcr\.io\/tnldotdev\/tnl@sha256:[a-f0-9]{64}$/;
const commitPattern = /^[a-f0-9]{40}$/;
const portSchema = z.object({
  port: z.number().int().optional(),
  start_port: z.number().int().optional(),
  end_port: z.number().int().optional(),
  handlers: z.array(z.string()).optional(),
  proxy_proto_options: z.object({ version: z.string() }).optional(),
});
const serviceSchema = z.object({
  protocol: z.string(),
  internal_port: z.number().int(),
  ports: z.array(portSchema),
});
const manifestSchema = z.object({
  app: z.string(),
  env: z.record(z.string(), z.string()),
  services: z.array(serviceSchema),
});
type Manifest = z.infer<typeof manifestSchema>;
const machineSchema = z.object({
  state: z.string(),
  image_ref: z.object({ digest: z.string() }),
  config: z.object({ env: z.record(z.string(), z.string()), services: z.array(serviceSchema) }),
});
const credentialSchema = z.object({
  environment: z.literal("production"),
  control: z
    .object({
      TNLD_DATABASE_URL: z.string().startsWith("postgresql://"),
      TNLD_STORAGE_KEY: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      TNLD_LOGIN_TOKEN: z.string().regex(/^tnl_login_[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/),
      TNLD_CLUSTER_SECRET: z.string().min(32),
      TNLD_INGRESS_IPV4_ADDRESSES: z.ipv4(),
      TNLD_ROUTE53_MANAGED_ZONE_ID: z.string().min(1),
      TNLD_ROUTE53_SERVER_ZONE_ID: z.string().min(1),
      TNLD_WEBHOOK_SECRET: z.string().min(32),
      TNLD_WEB_SERVICE_SECRET: z.string().min(32),
      TNLD_PUBLIC_URL_USAGE_TOKEN: z.string().min(1),
    })
    .catchall(z.string().min(1)),
  ingress: z.strictObject({ TNLD_CLUSTER_SECRET: z.string().min(32) }),
  "relay-a": z.strictObject({ TNLD_CLUSTER_SECRET: z.string().min(32) }),
  "relay-b": z.strictObject({ TNLD_CLUSTER_SECRET: z.string().min(32) }),
});

function run(program: string, args: string[], input?: string, timeout = 120_000): string {
  const result = spawnSync(program, args, {
    input,
    encoding: "utf8",
    timeout,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    // external tools may print credentials in diagnostics; never forward stderr.
    throw new Error(`${program} ${args[0]} failed; check credentials and app state`);
  }
  return result.stdout;
}

function manifest(role: Role, environment: Environment): Manifest {
  const app = `tnl-${role}-${environment}`;
  const path = `deploy/server/fly.${app}.toml`;
  run("flyctl", ["config", "validate", "--config", path]);
  const data: unknown = JSON.parse(run("flyctl", ["config", "show", "--local", "--config", path]));
  const parsed = manifestSchema.parse(data);
  if (parsed.app !== app) throw new Error(`${path}: wrong app`);
  return parsed;
}

const isProxyPort = (port: z.infer<typeof portSchema>, number: number): boolean =>
  (port.port === number ||
    (port.start_port !== undefined &&
      port.end_port !== undefined &&
      port.start_port <= number &&
      port.end_port >= number)) &&
  port.handlers?.length === 1 &&
  port.handlers[0] === "proxy_proto" &&
  port.proxy_proto_options?.version === "v2";

export function checkPorts(control: Manifest, ingress: Manifest): void {
  if (
    control.env.TNLD_TCP_PORTS !== "1024-65535" ||
    control.env.TNLD_REQUIRE_PROXY_HEADER !== "true" ||
    ingress.env.TNLD_REQUIRE_PROXY_HEADER !== "true"
  ) {
    throw new Error("control inventory or public listener PROXY v2 requirement differs");
  }
  const services = ingress.services.filter((s) => s.protocol === "tcp" && s.internal_port === 8443);
  if (
    services.length !== 1 ||
    services[0]?.ports.length !== 2 ||
    !services[0].ports.some((p) => p.port === 443 && isProxyPort(p, 443)) ||
    !services[0].ports.some(
      (p) => p.start_port === 1024 && p.end_port === 65535 && isProxyPort(p, 5432),
    )
  ) {
    throw new Error("ingress must expose 443 and 1024-65535/tcp with PROXY v2");
  }
}

export function checkTopology(environment: Environment, configs: Record<Role, Manifest>): void {
  checkPorts(configs.control, configs.ingress);
  for (const role of roles) {
    if (configs[role].app !== `tnl-${role}-${environment}`) throw new Error(`${role}: wrong app`);
  }
  if (
    configs.control.env.TNLD_ROLE !== "control" ||
    configs.ingress.env.TNLD_ROLE !== "ingress" ||
    configs["relay-a"].env.TNLD_RELAY_SERVICE_ID !== "relay-a" ||
    configs["relay-b"].env.TNLD_RELAY_SERVICE_ID !== "relay-b"
  ) {
    throw new Error("split roles or relay service identities differ");
  }
  for (const role of ["relay-a", "relay-b"] as const) {
    const services = configs[role].services;
    if (
      configs[role].env.TNLD_ROLE !== "relay" ||
      !services.some((s) => s.protocol === "tcp" && s.ports.some((p) => p.port === 443)) ||
      !services.some((s) => s.protocol === "udp" && s.ports.some((p) => p.port === 443))
    ) {
      throw new Error(`${role}: expected public TCP and QUIC listeners`);
    }
  }
}

export function deploymentOrder(hasControlMachines: boolean): readonly Role[] {
  // adding public ports on ingress must precede advertising them on control.
  return hasControlMachines ? ["ingress", "control", "relay-a", "relay-b"] : roles;
}

function option(args: string[], name: string): string {
  const index = args.indexOf(name);
  const value = args[index + 1];
  if (index < 0 || !value || value.startsWith("--")) throw new Error(`pass ${name}`);
  return value;
}

function verifyImage(image: string, commit: string): string {
  const version = run("docker", ["run", "--rm", image, "version"]).trim();
  if (!/^tnld [^\s]+ \([a-f0-9]{40}\)$/.test(version) || !version.endsWith(`(${commit})`)) {
    throw new Error("selected image does not contain the selected commit");
  }
  const index: unknown = JSON.parse(
    run("docker", ["buildx", "imagetools", "inspect", "--raw", image]),
  );
  const imageIndex = z
    .object({
      manifests: z.array(
        z.object({
          digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
          platform: z.object({ os: z.string(), architecture: z.string() }).optional(),
        }),
      ),
    })
    .parse(index);
  const amd64 = imageIndex.manifests.filter(
    (m) => m.platform?.os === "linux" && m.platform.architecture === "amd64",
  );
  if (amd64.length !== 1 || !amd64[0])
    throw new Error("selected image needs exactly one Linux amd64 platform");
  return amd64[0].digest;
}

async function probeRedis(host: string, port: number, cert: string, key: string): Promise<void> {
  if (!Number.isInteger(port) || port < 1024 || port > 65535)
    throw new Error("pass an allocated TCP port");
  await new Promise<void>((done, fail) => {
    const socket = connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: true,
      timeout: 5000,
      cert: readFileSync(cert),
      key: readFileSync(key),
    });
    let response = "";
    socket.on("secureConnect", () => socket.write("*1\r\n$4\r\nPING\r\n"));
    socket.on("data", (data: Buffer) => {
      response += data.toString("utf8");
      if (response.includes("\r\n")) {
        socket.destroy();
        if (response === "+PONG\r\n") done();
        else fail(new Error("staging Redis target did not return PONG"));
      }
    });
    socket.on("timeout", () => socket.destroy(new Error("staging TCP visitor timed out")));
    socket.on("error", fail);
    socket.on("close", () => {
      if (!response.includes("\r\n"))
        fail(new Error("staging TCP visitor closed without a response"));
    });
  });
}

async function main(args: string[]): Promise<void> {
  const command = args[0];
  if (command === "provision-production") {
    const path = option(args, "--credentials");
    const file = statSync(path);
    if (!file.isFile() || file.size > 64 * 1024 || file.mode & 0o077)
      throw new Error("credential JSON must be a private regular file under 64 KiB (chmod 600)");
    const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
    const credentials = credentialSchema.parse(raw);
    for (const [key, value] of Object.entries(credentials.control)) {
      if (
        !/^(TNLD|AWS)_[A-Z0-9_]+$/.test(key) ||
        key === "TNLD_DATABASE_DIRECT_URL" ||
        /[\r\n\0]/.test(value)
      ) {
        throw new Error(
          "invalid control secret name or value; do not pass the direct migration URL to control",
        );
      }
    }
    const secret = credentials.control.TNLD_CLUSTER_SECRET;
    if (roles.some((role) => credentials[role].TNLD_CLUSTER_SECRET !== secret))
      throw new Error("cluster secrets differ between roles");
    for (const role of roles) {
      const app = `tnl-${role}-production`;
      const entries = Object.entries(credentials[role])
        .map(([key, value]) => `${key}=${value}`)
        .join("\n");
      run("flyctl", ["secrets", "import", "--stage", "--app", app], entries + "\n");
    }
    process.stdout.write("production secrets staged; no Machines updated\n");
    return;
  }
  if (
    command !== "manifests" &&
    command !== "check" &&
    command !== "qualify" &&
    command !== "apply"
  )
    throw new Error("use manifests, check, apply, qualify, or provision-production");
  const environment: Environment =
    command === "apply"
      ? z.enum(["staging", "production"]).parse(option(args, "--environment"))
      : "staging";
  const configs = Object.fromEntries(
    roles.map((role) => [role, manifest(role, environment)]),
  ) as Record<Role, Manifest>;
  checkTopology(environment, configs);
  if (command === "manifests" || command === "check") {
    const prod = Object.fromEntries(
      roles.map((role) => [role, manifest(role, "production")]),
    ) as Record<Role, Manifest>;
    checkTopology("production", prod);
    if (command === "manifests") {
      process.stdout.write("Fly role manifests and PROXY v2 ports valid\n");
      return;
    }
  }
  const image = option(args, "--image");
  const commit = option(args, "--commit");
  if (!digest.test(image) || !commitPattern.test(commit))
    throw new Error("pass an exact image digest and full commit");
  const expectedDigest = verifyImage(image, commit);
  if (command === "check") {
    process.stdout.write(`manifests and image valid; selected ${commit} ${image}\n`);
    return;
  }
  if (command === "apply") {
    // on an existing server, expose ingress ports before control offers them.
    const existing: unknown = JSON.parse(
      run("flyctl", ["machine", "list", "--app", configs.control.app, "--json"]),
    );
    const order = deploymentOrder(z.array(z.unknown()).parse(existing).length > 0);
    for (const role of order) {
      const app = configs[role].app;
      run(
        "flyctl",
        [
          "deploy",
          "--config",
          `deploy/server/fly.${app}.toml`,
          "--image",
          image,
          "--ha=false",
          "--yes",
        ],
        undefined,
        10 * 60_000,
      );
      process.stdout.write(`${app}: deployed ${commit} ${expectedDigest}\n`);
    }
    return;
  }
  for (const role of roles) {
    const app = configs[role].app;
    const machines: unknown = JSON.parse(
      run("flyctl", ["machine", "list", "--app", app, "--json"]),
    );
    const members = z.array(machineSchema).min(1).parse(machines);
    if (role !== "control" && members.length !== 1) {
      throw new Error(`${app}: this topology needs one Machine per ingress or relay app`);
    }
    if (
      members.some(
        (member) => member.state !== "started" || member.image_ref.digest !== expectedDigest,
      )
    ) {
      throw new Error(`${app}: not all Machines are started on the selected image`);
    }
    if (role === "ingress") {
      for (const member of members) {
        if (member.config.env.TNLD_REQUIRE_PROXY_HEADER !== "true")
          throw new Error(`${app}: running ingress does not require PROXY v2`);
        checkPorts(configs.control, { ...configs.ingress, services: member.config.services });
      }
    }
    if (
      role === "control" &&
      members.some(
        (member) =>
          member.config.env.TNLD_TCP_PORTS !== "1024-65535" ||
          member.config.env.TNLD_REQUIRE_PROXY_HEADER !== "true",
      )
    ) {
      throw new Error(`${app}: running control does not advertise the qualified TCP ports`);
    }
  }
  const url = new URL(option(args, "--http-url"));
  const domain = configs.control.env.TNLD_MANAGED_DOMAIN;
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    url.search ||
    url.hash ||
    !domain ||
    !url.hostname.endsWith(`.${domain}`)
  )
    throw new Error("pass an HTTPS public URL in the selected staging managed domain");
  const expected = option(args, "--expect");
  const result = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(10_000) });
  if (!result.ok || !(await result.text()).includes(expected))
    throw new Error("staging HTTP visitor response did not match");
  const host = option(args, "--redis-host");
  if (!host.endsWith(`.${domain}`)) throw new Error("pass a staging Redis public hostname");
  const port = Number(option(args, "--redis-port"));
  await probeRedis(host, port, option(args, "--redis-cert"), option(args, "--redis-key"));
  process.stdout.write(
    `staging ${commit}: Machines, PROXY v2 port mapping, HTTPS and Redis visitor passed\n`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch((error: unknown) => {
    const message =
      error instanceof z.ZodError || error instanceof SyntaxError
        ? "invalid JSON or external response"
        : error instanceof Error
          ? error.message
          : "unexpected failure";
    process.stderr.write(`server deployment check: ${message}\n`);
    process.exitCode = 1;
  });
}
