import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import { copyFile, cp, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { once } from "node:events";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import * as z from "zod";

const [outputArgument, control, variant = "host", linuxImage] = process.argv.slice(2);
assert(outputArgument && control);
assert(variant === "host" || variant === "linux-x64");
assert(variant === "host" || linuxImage);
const run = promisify(execFile);
assert.equal(process.versions.node, "24.20.0");
let input = "";
for await (const chunk of process.stdin) input += String(chunk);
const tokens = z
  .object({ valid: z.string(), rotated: z.string(), expired: z.string(), wrong: z.string() })
  .parse(JSON.parse(input));
const output = path.resolve(outputArgument);
const directory = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-vercel-invoke-")));
const fn = path.join(directory, ".vercel/output/functions/__fallback.func");
const responseSchema = z.object({
  ok: z.boolean(),
  instance: z.string().uuid(),
  call: z.number().int(),
  peak: z.number().int(),
  code: z.optional(z.string()),
});
const evidenceSchema = z.object({
  runtime: z.literal("24.20.0"),
  platform: z.string(),
  helpers: z.array(z.string()),
  ipc: z.array(z.string()),
  owners: z.array(
    z.object({ pid: z.number().int().positive(), executable: z.string(), alive: z.boolean() }),
  ),
});
const statsSchema = z.object({
  sessions: z.number().int(),
  prepared: z.array(z.string()),
  targets: z.number().int(),
  calls: z.record(z.string(), z.number().int()),
});
interface Host {
  child: ChildProcess;
  exited: Promise<unknown[]>;
  url: string;
  container?: string;
  stderr: () => string;
}
const hosts: Host[] = [];
const errors: unknown[] = [];
let report: unknown;
try {
  await cp(path.join(output, `${variant}/.vercel/output`), path.join(directory, ".vercel/output"), {
    recursive: true,
  });
  await copyFile(path.join(import.meta.dirname, "serve.ts"), path.join(directory, "serve.ts"));
  const warm = await start();
  const coldConcurrent = await Promise.all(Array.from({ length: 4 }, () => request(warm, "http")));
  assert(
    coldConcurrent.every((result) => result.ok && result.instance === coldConcurrent[0]?.instance),
  );
  assert(Math.max(...coldConcurrent.map((result) => result.peak)) > 1);
  const first = await evidence(warm);
  assert.equal(
    first.platform,
    variant === "linux-x64" ? "linux-x64" : `${process.platform}-${process.arch}`,
  );
  assert.deepEqual(first.helpers, ["context", "identity", "start"]);
  assert.equal(first.owners.length, 1);
  assert.equal(first.owners[0]?.alive, true);
  assert(
    first.ipc.length > 0 && first.ipc.every((operation) => operation === "/v1/connections/prepare"),
  );
  const incremental = await stats();
  assert.equal(incremental.sessions, 1);
  assert.deepEqual(incremental.prepared, ["api"]);

  const simultaneous = await Promise.all(Array.from({ length: 4 }, () => request(warm, "both")));
  assert(simultaneous.every((result) => result.ok));
  const both = await evidence(warm);
  assert.deepEqual(both.helpers, first.helpers, "warm requests must use IPC without helpers");
  assert.deepEqual(both.owners, first.owners, "HTTP and PostgreSQL must share one live owner");
  const prepared = await stats();
  assert.equal(prepared.sessions, 1);
  assert.deepEqual(prepared.prepared, ["api", "database"]);
  const warmAgain = await Promise.all(Array.from({ length: 4 }, () => request(warm, "prepare")));
  assert(warmAgain.every((result) => result.ok));
  const warmBudget = await evidence(warm);
  assert.deepEqual(warmBudget.helpers, first.helpers);
  assert.deepEqual(
    (await stats()).calls,
    prepared.calls,
    "verified warm IPC must add no control work",
  );
  assert.equal(warmBudget.ipc.length - both.ipc.length, 8);
  const targetsBeforeTraffic = (await stats()).targets;
  const warmTraffic = await Promise.all(Array.from({ length: 4 }, () => request(warm, "both")));
  assert(warmTraffic.every((result) => result.ok));
  const traffic = await stats();
  assert.deepEqual(traffic.calls, prepared.calls, "prepared streams must add no control work");
  // pg creates four target sockets; HTTP can reuse its verified keepalive pool.
  const targetDelta = traffic.targets - targetsBeforeTraffic;
  assert(targetDelta >= 4 && targetDelta <= 8);

  const rotated = await request(warm, "both", tokens.rotated);
  assert.equal(rotated.ok, true);
  const rotation = await evidence(warm);
  assert.deepEqual(rotation.helpers, [...first.helpers, "identity"]);
  assert.deepEqual(rotation.owners, first.owners);
  assert.equal((await stats()).sessions, 1);

  const cold = await start();
  const fresh = await Promise.all(Array.from({ length: 4 }, () => request(cold, "both")));
  assert(fresh.every((result) => result.ok));
  assert.notEqual(fresh[0]?.instance, coldConcurrent[0]?.instance);
  const second = await evidence(cold);
  assert.deepEqual(second.helpers, first.helpers);
  assert.equal(second.owners.length, 1);
  assert.equal(second.owners[0]?.alive, true);
  assert.notDeepEqual(
    [cold.container, second.owners[0]?.pid],
    [warm.container, first.owners[0]?.pid],
  );
  assert.equal((await stats()).sessions, 2);

  const negatives: Record<string, string[]> = {};
  for (const [name, token] of [
    ["missing", ""],
    ["expired", tokens.expired],
    ["wrong", tokens.wrong],
  ] as const) {
    const before = await stats();
    const results = await Promise.all([
      request(warm, "both", token),
      request(await start(), "both", token),
    ]);
    assert(results.every((result) => !result.ok));
    const expected =
      name === "missing" ? "sdk.workload_assertion_unavailable" : "sdk.connection_unavailable";
    assert(results.every((result) => result.code === expected));
    negatives[name] = results.map((result) => {
      assert(result.code);
      return result.code;
    });
    const after = await stats();
    assert.equal(after.sessions, before.sessions);
    assert.equal(after.targets, before.targets, "denied assertion reached a target");
    assert.deepEqual(after.prepared, before.prepared);
  }
  assert.equal(
    (await request(warm, "both")).ok,
    true,
    "bad assertions must not poison another request",
  );
  const isolated = await Promise.all([request(warm, "both"), request(warm, "both", tokens.wrong)]);
  assert.equal(isolated[0]?.ok, true);
  assert.equal(
    isolated[1]?.code,
    "sdk.connection_unavailable",
    "concurrent request contexts crossed",
  );
  await controlCall("revoke");
  // the production authorization cache is bounded to 30 seconds. let its real
  // deadline pass rather than modifying clocks or stored expiry timestamps.
  await new Promise((resolve) => setTimeout(resolve, 31_000));
  const beforeRevoked = await stats();
  const revoked = await request(warm, "both");
  assert.equal(revoked.ok, false);
  assert.equal(revoked.code, "sdk.connection_unavailable");
  assert.equal((await stats()).targets, beforeRevoked.targets);
  assert.equal(
    (await stats()).sessions,
    2,
    "revocation must not start an external/replacement session",
  );
  const final = await evidence(warm);
  assert.deepEqual(
    final.owners.map(({ pid }) => pid),
    first.owners.map(({ pid }) => pid),
  );
  report = {
    runtime: first.runtime,
    platform: first.platform,
    linuxImage: variant === "linux-x64" ? linuxImage : undefined,
    artifactOnly: true,
    externalHandle: false,
    requestContext: "@vercel/oidc",
    incremental: incremental.prepared,
    simultaneous: prepared.prepared,
    coldConcurrent: 4,
    warmConcurrent: 4,
    coldHelpers: first.helpers,
    warmHelperDelta: warmBudget.helpers.length - first.helpers.length,
    warmPrepareControlDelta: 0,
    warmStreamControlDelta: 0,
    warmTargetConnections: targetDelta,
    warmIPCDelta: warmBudget.ipc.length - both.ipc.length,
    rotationHelperDelta: rotation.helpers.length - warmBudget.helpers.length,
    ownersPerIsolate: [first.owners.length, second.owners.length],
    ownerPids: [first.owners[0]?.pid, second.owners[0]?.pid],
    pidNamespaces: [warm.container ?? "host", cold.container ?? "host"],
    controlBudgets: {
      coldHTTP: incremental.calls,
      both: prepared.calls,
      warmTraffic: traffic.calls,
    },
    concurrentContextIsolation: true,
    negatives,
    revoked: revoked.code,
    gaps: [
      "deployed Vercel token delivery",
      "freeze/thaw",
      "sandbox process and filesystem limits",
    ],
  };
} catch (error) {
  errors.push(error);
} finally {
  for (const host of hosts) {
    try {
      await fetch(`${host.url}/__fixture/shutdown`, { method: "POST" }).catch(() => {});
      const [code] = await Promise.race([
        host.exited,
        new Promise<never>((_, reject) => {
          setTimeout(() => reject(new Error("function cleanup did not join")), 30_000).unref();
        }),
      ]);
      assert.equal(code, 0, `function exited unsuccessfully: ${host.stderr()}`);
    } catch (error) {
      errors.push(error);
    } finally {
      if (host.container) await run("docker", ["rm", "--force", host.container]).catch(() => {});
      else host.child.kill("SIGKILL");
    }
  }
  await rm(directory, { recursive: true, force: true });
}
if (errors.length) throw new AggregateError(errors, "function qualification failed");
await writeFile(
  path.join(output, `${variant}-invocation.json`),
  `${JSON.stringify(report, null, 2)}\n`,
);
process.stdout.write(`${JSON.stringify(report)}\n`);

async function start(): Promise<Host> {
  const home = path.join(directory, `home-${hosts.length}`);
  await mkdir(home, { mode: 0o700 });
  const env: NodeJS.ProcessEnv = {
    PATH: path.dirname(process.execPath),
    HOME: home,
    TMPDIR: home,
    NODE_ENV: "production",
    VERCEL: "1",
    VERCEL_ENV: "production",
    TNL_WORKLOAD: "function",
    TNL_STATE_DIR: path.join(home, "state"),
    PGHOST: "direct-database.invalid",
    PGPORT: "1",
    GOMAXPROCS: "2",
  };
  for (const key of ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "DB_USER", "DB_PASSWORD", "DB_NAME"])
    if (process.env[key] !== undefined) env[key] = process.env[key];
  const container = variant === "linux-x64" ? `tnl-vercel-${randomUUID()}` : undefined;
  if (container) {
    assert(linuxImage && process.env.SSL_CERT_FILE);
    env.PATH = "/usr/local/bin:/usr/bin:/bin";
    env.HOME = env.TMPDIR = "/runtime";
    env.TNL_STATE_DIR = "/runtime/state";
    env.SSL_CERT_FILE = env.NODE_EXTRA_CA_CERTS = "/roots.pem";
  }
  const child = container
    ? spawn(
        "docker",
        [
          "run",
          "--rm",
          "--pull=never",
          "--init",
          "--name",
          container,
          "--platform=linux/amd64",
          "--network=host",
          "--read-only",
          "--tmpfs=/runtime:mode=0700",
          "--tmpfs=/tmp",
          "--workdir=/function",
          "--mount",
          `type=bind,src=${fn},dst=/function,readonly`,
          "--mount",
          `type=bind,src=${path.join(directory, "serve.ts")},dst=/serve.ts,readonly`,
          "--mount",
          `type=bind,src=${process.env.SSL_CERT_FILE},dst=/roots.pem,readonly`,
          ...Object.keys(env).flatMap((key) => ["--env", key]),
          linuxImage ?? "",
          "node",
          "/serve.ts",
          "/function",
          "container",
        ],
        {
          env: { ...process.env, ...env, PATH: process.env.PATH },
          stdio: ["ignore", "pipe", "pipe"],
        },
      )
    : spawn(process.execPath, [path.join(directory, "serve.ts"), fn], {
        cwd: fn,
        env,
        stdio: ["ignore", "pipe", "pipe"],
      });
  const exited = once(child, "exit");
  let stderr = "";
  child.stderr?.on("data", (data: Buffer) => {
    stderr += data.toString();
  });
  assert(child.stdout);
  const lines = createInterface({ input: child.stdout });
  try {
    const line = await Promise.race([
      once(lines, "line").then(([line]) => z.string().parse(line)),
      exited.then(() => {
        throw new Error(`emitted function exited before listening: ${stderr}`);
      }),
      new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("function startup timed out")), 15_000).unref();
      }),
    ]);
    const { port } = z.object({ port: z.number().int().min(1).max(65535) }).parse(JSON.parse(line));
    const host = {
      child,
      exited,
      url: `http://127.0.0.1:${port}`,
      stderr: () => stderr,
      ...(container ? { container } : {}),
    };
    hosts.push(host);
    return host;
  } catch (error) {
    if (container) await run("docker", ["rm", "--force", container]);
    child.kill("SIGKILL");
    await exited;
    throw error;
  } finally {
    lines.close();
  }
}
async function request(host: Host, protocol: string, token = tokens.valid) {
  const response = await fetch(`${host.url}/check?protocol=${protocol}`, {
    headers: token ? { "x-vercel-oidc-token": token } : {},
    signal: AbortSignal.timeout(60_000),
  }).catch((cause: unknown) => {
    throw new Error(`function request failed: ${host.stderr()}`, { cause });
  });
  const result = responseSchema.parse(await response.json());
  assert.equal(response.status, result.ok ? 200 : 503);
  return result;
}
async function evidence(host: Host) {
  return evidenceSchema.parse(await (await fetch(`${host.url}/__fixture/evidence`)).json());
}
async function stats() {
  return statsSchema.parse(await (await fetch(`${control}/stats`)).json());
}
async function controlCall(operation: string) {
  const response = await fetch(`${control}/${operation}`, {
    method: "POST",
    signal: AbortSignal.timeout(30_000),
  });
  assert.equal(response.status, 204);
}
