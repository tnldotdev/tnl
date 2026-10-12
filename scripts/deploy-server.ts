import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import process from "node:process";
import { isDeepStrictEqual } from "node:util";

type Environment = "staging" | "production";
type Role = "control" | "ingress" | "relay-a" | "relay-b";
type Machine = {
  id: string;
  state: string;
  image_ref: { digest: string };
  config: {
    image?: string;
    env: Record<string, string>;
    metadata?: { fly_process_group?: string };
    services: { protocol: string; internal_port: number; ports: { port: number }[] }[];
  };
};

const roles: Role[] = ["control", "ingress", "relay-a", "relay-b"];
const branchIDs: Record<Environment, string> = {
  staging: "dfjnonfcohmw",
  production: "dsolzc3km9wq",
};

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
    throw new Error(
      `${command} ${args[0]} failed; check the image, database, or Fly Machine state`,
    );
  }
  return result.stdout.trim();
}

function machines(app: string): Machine[] {
  const data: unknown = JSON.parse(run("flyctl", ["machine", "list", "--app", app, "--json"]));
  if (
    !Array.isArray(data) ||
    !data.every((value: unknown) => {
      if (!value || typeof value !== "object") return false;
      const member = value as Partial<Machine>;
      return (
        typeof member.id === "string" &&
        typeof member.state === "string" &&
        typeof member.image_ref?.digest === "string" &&
        member.config !== undefined &&
        typeof member.config.env === "object" &&
        Array.isArray(member.config.services)
      );
    })
  )
    throw new Error(`${app}: invalid Machine inventory`);
  return data as Machine[];
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
    !url.hostname.endsWith(".pg.psdb.cloud") ||
    url.hostname.includes("pooler") ||
    !url.username.endsWith(`.${branchIDs[environment]}`)
  )
    throw new Error(`direct control database URL does not belong to ${environment}`);
}

function platformDigest(image: string): string {
  const index: unknown = JSON.parse(
    run("docker", ["buildx", "imagetools", "inspect", "--raw", image]),
  );
  if (
    !index ||
    typeof index !== "object" ||
    !("manifests" in index) ||
    !Array.isArray(index.manifests)
  ) {
    throw new Error("server image needs a multi-platform index");
  }
  const manifests = index.manifests as {
    digest?: string;
    platform?: { os?: string; architecture?: string };
  }[];
  const digests = manifests
    .filter((entry) => entry.platform?.os === "linux" && entry.platform.architecture === "amd64")
    .map((entry) => entry.digest);
  const [digest] = digests;
  if (digests.length !== 1 || !digest || !/^sha256:[a-f0-9]{64}$/.test(digest)) {
    throw new Error("server image needs one Linux amd64 platform");
  }
  return digest;
}

function deploy(environment: Environment, image: string, digest: string): void {
  const counts: unknown = JSON.parse(readFileSync("deploy/server/process-counts.json", "utf8"));
  if (!counts || typeof counts !== "object" || !(environment in counts)) {
    throw new Error(`missing ${environment} Machine counts`);
  }
  const expected = (counts as Record<Environment, Record<Role, number>>)[environment];
  // check every app before changing any of them.
  for (const role of roles) {
    const app = `tnl-${role}-${environment}`;
    const count = expected[role];
    if (!Number.isSafeInteger(count) || count < 1) throw new Error(`${app}: invalid Machine count`);
    check(app, role, count, machines(app));
    run("flyctl", ["config", "validate", "-c", `deploy/server/fly.${app}.toml`]);
  }
  const platformImage = `ghcr.io/tnldotdev/tnl@${digest}`;
  for (const role of roles) {
    const app = `tnl-${role}-${environment}`;
    const config = `deploy/server/fly.${app}.toml`;
    if (role === "control") {
      run("flyctl", [
        "deploy",
        "--config",
        config,
        "--image",
        image,
        "--update-only",
        "--strategy",
        "rolling",
        "--yes",
      ]);
    } else if (role === "ingress") {
      for (const member of machines(app)) {
        run("flyctl", [
          "deploy",
          "--config",
          config,
          "--image",
          image,
          "--update-only",
          "--only-machines",
          member.id,
          "--env",
          `TNLD_INGRESS_ID=${member.config.env.TNLD_INGRESS_ID}`,
          "--strategy",
          "rolling",
          "--yes",
        ]);
      }
    }
    const managed =
      role === "control"
        ? machines(app).filter((member) => member.config.metadata?.fly_process_group === "app")
        : [];
    const managedEnv = managed[0]?.config.env;
    if (
      role === "control" &&
      (!managedEnv || managed.some((member) => !isDeepStrictEqual(member.config.env, managedEnv)))
    ) {
      throw new Error(`${app}: managed control Machines must share one environment`);
    }
    // flyctl deploy --update-only skips manually created Machines. relay updates
    // are explicit to retain each Machine's identity, address, and UDP group.
    for (const member of machines(app).sort(
      (a, b) =>
        Number(a.config.metadata?.fly_process_group === "udp") -
        Number(b.config.metadata?.fly_process_group === "udp"),
    )) {
      const controlEnvDrift =
        role === "control" &&
        member.config.metadata?.fly_process_group !== "app" &&
        !isDeepStrictEqual(member.config.env, managedEnv);
      if (member.image_ref.digest !== digest || controlEnvDrift) {
        const updated = { ...member.config, image: platformImage };
        if (role === "control" && managedEnv) updated.env = managedEnv;
        run("flyctl", [
          "machine",
          "update",
          member.id,
          "--app",
          app,
          "--machine-config",
          JSON.stringify(updated),
          "--yes",
        ]);
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
    }
    const current = machines(app);
    check(app, role, expected[role], current);
    if (current.some((member) => member.image_ref.digest !== digest)) {
      throw new Error(`${app}: Machines are not all on the selected image`);
    }
  }
}

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
  const installed = run("docker", ["run", "--rm", image, "version"]);
  if (installed !== `tnld ${version} (${commit})`)
    throw new Error("image version or commit does not match deployment");
  const digest = platformDigest(image);
  run("docker", ["run", "--rm", "--env", "TNLD_DATABASE_DIRECT_URL", image, "migrate"]);
  deploy(environment, image, digest);
  process.stdout.write(`${environment} tnld ${version} deployed from ${image}\n`);
} catch (error) {
  process.stderr.write(
    `server deployment: ${error instanceof Error ? error.message : "unexpected failure"}\n`,
  );
  process.exitCode = 1;
}
