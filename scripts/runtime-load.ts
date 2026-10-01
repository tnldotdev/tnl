import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import * as z from "zod";
import { applyFault, faultSchema, type FaultEvents, type FaultRuntime } from "./runtime-faults.ts";
import { publisherServices } from "./runtime-network.ts";
import { parseJSON } from "./validation.ts";

const containerSchema = z.object({
  Id: z.string(),
  Name: z.string(),
  Config: z.object({ Labels: z.object({ "com.docker.compose.service": z.string() }) }),
  State: z.object({
    Running: z.boolean(),
    ExitCode: z.number().int(),
    OOMKilled: z.boolean(),
    Error: z.string(),
    FinishedAt: z.string(),
  }),
  NetworkSettings: z.object({
    Networks: z.record(z.string(), z.object({ IPAddress: z.string() })),
  }),
});

const results = resolve(z.string().min(1).parse(process.env.RESULTS));
process.env.RESULTS = results;
const composeProject = `tnl-separated-load-${randomUUID()}`;
process.env.COMPOSE_PROJECT_NAME = composeProject;
const routes = z.coerce
  .number()
  .int()
  .min(4)
  .max(10_000)
  .parse(process.env.PUBLIC_URLS ?? "4");
const haTopology = z.enum(["0", "1"]).parse(process.env.HA_TOPOLOGY ?? "1") === "1";
const replicatedRelays = process.env.SCENARIO === "control-restart";
// each publisher component owns striped pairs of public URLs. small smoke runs
// intentionally leave some publisher components without a public URL.
const activePublishers = publisherServices.filter((_, shard) => shard * 2 < routes);
const ingresses: readonly ("ingress-a" | "ingress-b")[] = haTopology
  ? ["ingress-a", "ingress-b"]
  : ["ingress-a"];
const appServices = ["app", "app-2", "app-3", "app-4"] as const;
if (existsSync(results) && readdirSync(results).length !== 0)
  throw new Error(
    "RESULTS must be a fresh or empty directory; preserve earlier experiment artifacts",
  );
mkdirSync(results, { recursive: true });
const composeArgs = [
  "compose",
  ...(haTopology ? ["--profile", "ha"] : []),
  ...(replicatedRelays ? ["--profile", "replicated-relays"] : []),
  "--ansi",
  "never",
  "--progress",
  "plain",
  "--file",
  "internal/tnldruntime/testdata/separated-load.compose.yaml",
];
function docker(args: readonly string[], quiet = false): string {
  return execFileSync("docker", args, {
    encoding: "utf8",
    // a fresh CI runner compiles the race binary and dependencies inside Docker.
    timeout: args.includes("build") ? 600_000 : 180_000,
    stdio: ["ignore", "pipe", quiet ? "pipe" : "inherit"],
  });
}
const compose = (args: readonly string[], quiet = false) =>
  docker([...composeArgs, ...args], quiet);
let logs: ChildProcess | undefined;
let dockerEvents: ChildProcess | undefined;
let stopping = false;
let coordinatorConnection: { readonly token: string; readonly endpoint: string } | undefined;
let faultTask: Promise<void> | undefined;
let faultError: unknown;
const faultState = { intentionalRelayExit: false };
let faultStarted = false;
let interrupted = false;
const externalFault = faultSchema.safeParse(process.env.SCENARIO).success;
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"])
  process.on(signal, () => {
    interrupted = true;
  });

async function eventRequest(name: string, body?: string): Promise<Response> {
  assert(coordinatorConnection, "coordinator connection is not configured");
  return fetch(`${coordinatorConnection.endpoint}/v1/events/${name}`, {
    method: body === undefined ? "GET" : "PUT",
    headers: { Authorization: `Bearer ${coordinatorConnection.token}` },
    ...(body === undefined ? {} : { body }),
    signal: AbortSignal.timeout(15_000),
  });
}

async function readEvent<Output>(
  name: string,
  schema: z.ZodType<Output>,
): Promise<Output | undefined> {
  const response = await eventRequest(name);
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`coordinator ${name}: HTTP ${response.status}`);
  return parseJSON(await response.text(), schema, `coordinator ${name}`);
}

async function event<Name extends keyof FaultEvents>(
  name: Name,
  value: FaultEvents[Name],
): Promise<void> {
  const response = await eventRequest(name, JSON.stringify(value));
  if (!response.ok) throw new Error(`coordinator ${name}: HTTP ${response.status}`);
}

function inspect(ids: readonly string[]): z.infer<typeof containerSchema>[] {
  return parseJSON(docker(["inspect", ...ids]), z.array(containerSchema), "Docker inspection");
}

function containerID(containers: ReadonlyMap<string, string>, service: string): string {
  const id = containers.get(service);
  assert(id, `${service} container is missing`);
  return id;
}

async function interruptibleSleep(ms: number): Promise<void> {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (stopping || interrupted) throw new Error("runtime workload interrupted");
    await sleep(Math.min(250, until - Date.now()));
  }
}

let status = 1;
try {
  compose(["down", "--volumes", "--remove-orphans"], true);
  docker(["volume", "create", "tnl-load-go-build"]);
  docker(["volume", "create", "tnl-load-go-modules"]);
  compose(["config", "--quiet"]);
  compose(["build", "coordinator"]);
  compose(["run", "--rm", "build"]);
  compose(["up", "--wait", "postgres"]);
  compose(["run", "--rm", "setup"]);
  const eventLog = openSync(join(results, "docker-exit-events.log"), "w");
  try {
    dockerEvents = spawn(
      "docker",
      [
        "events",
        "--filter",
        "type=container",
        "--filter",
        `label=com.docker.compose.project=${composeProject}`,
        ...["die", "kill", "oom"].flatMap((action) => ["--filter", `event=${action}`]),
        "--format",
        "{{.TimeNano}} {{.Action}} {{.Actor.Attributes.name}} exit={{.Actor.Attributes.exitCode}} signal={{.Actor.Attributes.signal}}",
      ],
      { stdio: ["ignore", eventLog, "inherit"] },
    );
    dockerEvents.on("error", (error) => console.error(`docker events: ${error.message}`));
  } finally {
    closeSync(eventLog);
  }
  compose([
    "up",
    "--detach",
    "control-a",
    ...(haTopology ? ["control-b"] : []),
    "ingress-a",
    ...(haTopology ? ["ingress-b"] : []),
    "relay-a",
    "relay-b",
    ...(replicatedRelays ? ["relay-a-2", "relay-b-2"] : []),
    ...publisherServices,
    "visitor-1",
    "visitor-2",
    "visitor-3",
    "visitor-4",
    ...appServices,
    "pebble",
    "coordinator",
  ]);
  logs = spawn("docker", [...composeArgs, "logs", "--follow", "--no-color"], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  const ids = compose(["ps", "--all", "--quiet"]).trim().split(/\s+/);
  const containers = new Map(
    inspect(ids).map((container) => [
      container.Config.Labels["com.docker.compose.service"],
      container.Id,
    ]),
  );
  coordinatorConnection = {
    endpoint: `http://${compose(["port", "coordinator", "8080"]).trim()}`,
    token: compose(["exec", "-T", "coordinator", "cat", "/load/coordinator-token"]).trim(),
  };
  const faultRuntime: FaultRuntime = {
    compose,
    inspect: (service) => {
      const [container] = inspect([containerID(containers, service)]);
      assert(container, `${service} inspection is missing`);
      return container;
    },
    readEvent: async (name) => Boolean(await readEvent(name, z.unknown())),
    event,
    sleep: interruptibleSleep,
    results,
    ingresses,
    activePublishers,
    network: {
      path: process.env.NETWORK_PATH,
      rtt: process.env.RTT,
      loss: process.env.LOSS,
      seed: process.env.SEED,
    },
    state: faultState,
  };
  const deadline = Date.now() + (process.env.HELD_MEASURE === "0s" ? 20 : 30) * 60_000;
  for (;;) {
    if (interrupted) throw new Error("runtime workload interrupted");
    if (faultError) throw faultError;
    if (Date.now() > deadline) throw new Error("runtime workload exceeded watchdog deadline");
    const states = inspect(ids);
    const coordinatorID = containerID(containers, "coordinator");
    const coordinator = states.find((c) => c.Id === coordinatorID);
    assert(coordinator, "coordinator inspection is missing");
    for (const container of states) {
      if (container.Id === coordinatorID) continue;
      if (container.State.Running) continue;
      if (
        container.Id === containerID(containers, "relay-a") &&
        faultState.intentionalRelayExit &&
        container.State.ExitCode === 137
      )
        continue;
      writeFileSync(
        join(results, "unexpected-component-exit.json"),
        JSON.stringify(
          {
            at: new Date().toISOString(),
            exited: container.Name,
            containers: states.map((state) => ({
              name: state.Name,
              service: state.Config.Labels["com.docker.compose.service"],
              ...state.State,
            })),
          },
          null,
          2,
        ),
      );
      throw new Error(`unexpected component exit: ${container.Name} (${container.State.ExitCode})`);
    }
    if (!coordinator.State.Running) {
      status = coordinator.State.ExitCode;
      break;
    }
    if (externalFault && !faultStarted) {
      const scenario = await readEvent("fault.request", faultSchema);
      if (scenario) {
        faultStarted = true;
        faultTask = applyFault(scenario, faultRuntime).catch((error) => {
          faultError = error;
        });
      }
    }
    await sleep(500);
  }
} catch (error) {
  console.error(error);
  status = 1;
} finally {
  stopping = true;
  if (dockerEvents && dockerEvents.exitCode === null && dockerEvents.signalCode === null)
    dockerEvents.kill("SIGTERM");
  if (faultTask) await faultTask;
  if (faultError) {
    console.error(faultError);
    status = 1;
  }
  const cleanup = (args: readonly string[]) => {
    try {
      return compose(args, true);
    } catch (error) {
      console.error(
        `cleanup ${args.join(" ")}: ${error instanceof Error ? error.message : String(error)}`,
      );
      status = 1;
      return "";
    }
  };
  const saveSnapshot = (name: string) => {
    const snapshot = cleanup(["ps", "--all", "--format", "json"]);
    try {
      writeFileSync(join(results, name), snapshot);
    } catch (error) {
      console.error(`save ${name}: ${error instanceof Error ? error.message : String(error)}`);
      status = 1;
    }
  };
  try {
    saveSnapshot("containers-before-cleanup.json");
    for (const services of [
      ["visitor-1", "visitor-2", "visitor-3", "visitor-4"],
      [...appServices, ...publisherServices],
      ["ingress-a", ...(haTopology ? ["ingress-b"] : []), "relay-a", "relay-b"],
      ["control-a", ...(haTopology ? ["control-b"] : []), "pebble", "coordinator"],
      ["postgres"],
    ])
      cleanup(["stop", ...services]);
    saveSnapshot("containers.json");
    if (logs && logs.exitCode === null && logs.signalCode === null) {
      const process = logs;
      const exited = new Promise<void>((resolve) => process.once("exit", () => resolve()));
      process.kill("SIGTERM");
      await exited;
    }
  } finally {
    cleanup(["down", "--volumes", "--remove-orphans"]);
  }
}
process.exitCode = status;
