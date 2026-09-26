import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import * as z from "zod";
import {
  impairmentEndpoints,
  netemOptions,
  publisherServices,
  type RuntimeService,
} from "./runtime-network.ts";
import { parseJSON } from "./validation.ts";

const faultSchema = z.enum([
  "relay-kill",
  "forwarding-blackhole",
  "publisher-blackhole",
  "udp-fallback",
  "latency",
  "packet-loss",
]);
type Fault = z.infer<typeof faultSchema>;
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
const qdiscsSchema = z.array(z.looseObject({ kind: z.string(), packets: z.optional(z.number()) }));
type FaultEvents = {
  "fault.applied": { Started: string; Exited: string };
  "fault.restored": string;
  "udp.cleaned": boolean;
};

const results = z.string().min(1).parse(process.env.RESULTS);
const routes = z.coerce
  .number()
  .int()
  .min(4)
  .max(10_000)
  .parse(process.env.ROUTES ?? "4");
const haTopology = z.enum(["0", "1"]).parse(process.env.HA_TOPOLOGY ?? "1") === "1";
const replicatedRelays = process.env.SCENARIO === "control-restart";
// Each publisher component owns striped pairs of routes. Small smoke runs
// intentionally leave some publisher components without a route.
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
    // A fresh CI runner compiles the race binary and dependencies inside Docker.
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
let intentionalRelayExit = false;
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

// Restore every owned mutation even when setup or evidence collection fails.
// Keep the original failure alongside cleanup failures.
async function withFaultCleanup(run: (undo: string[][]) => Promise<void>): Promise<void> {
  const undo: string[][] = [];
  const failures: unknown[] = [];
  try {
    await run(undo);
  } catch (error) {
    failures.push(error);
  }
  for (const command of undo.reverse()) {
    try {
      compose(command);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length) throw new AggregateError(failures, "runtime fault failed");
}

async function applyFault(scenario: Fault, containers: ReadonlyMap<string, string>): Promise<void> {
  const started = new Date().toISOString();
  const address = (service: RuntimeService) => {
    const [container] = inspect([containerID(containers, service)]);
    assert(container, `${service} inspection is missing`);
    const value = Object.values(container.NetworkSettings.Networks)[0]?.IPAddress;
    if (!value) throw new Error(`${service} has no IPv4 address`);
    return value;
  };
  const waitForEvent = async (name: "publishers.ready" | "fault.release") => {
    const deadline = Date.now() + 600_000;
    while (!(await readEvent(name, z.unknown()))) {
      if (Date.now() >= deadline) throw new Error("active-fault measurement exceeded watchdog");
      await interruptibleSleep(250);
    }
  };
  if (scenario === "relay-kill") {
    intentionalRelayExit = true;
    compose(["kill", "--signal", "SIGKILL", "relay-a"]);
    const [relay] = inspect([containerID(containers, "relay-a")]);
    assert(relay, "relay inspection is missing");
    const state = relay.State;
    if (state.Running || state.ExitCode !== 137)
      throw new Error("relay kill did not produce the expected process exit");
    await event("fault.applied", { Started: started, Exited: new Date().toISOString() });
    // Exceed the actual 30-second relay lease without changing production timers.
    await interruptibleSleep(31_000);
    compose(["start", "relay-a"]);
    intentionalRelayExit = false;
  } else if (["forwarding-blackhole", "publisher-blackhole", "udp-fallback"].includes(scenario)) {
    const services: readonly RuntimeService[] =
      scenario === "forwarding-blackhole" ? ingresses : activePublishers;
    const relays: RuntimeService[] =
      scenario === "udp-fallback" ? ["relay-a", "relay-b"] : ["relay-a"];
    const protocols =
      scenario === "publisher-blackhole"
        ? ["tcp", "udp"]
        : [scenario === "udp-fallback" ? "udp" : "tcp"];
    const rules: string[][] = [];
    await withFaultCleanup(async (undo) => {
      for (const service of services)
        for (const relay of relays)
          for (const protocol of protocols) {
            const rule = [
              "OUTPUT",
              "-d",
              address(relay),
              "-p",
              protocol,
              "--dport",
              scenario === "forwarding-blackhole" ? "8443" : "443",
              "-m",
              "comment",
              "--comment",
              "tnl-runtime-fault",
              "-j",
              "DROP",
            ];
            compose(["exec", "-T", service, "iptables", "-I", ...rule]);
            undo.push(["exec", "-T", service, "iptables", "-D", ...rule]);
            rules.push(rule);
          }
      await event("fault.applied", { Started: started, Exited: new Date().toISOString() });
      if (scenario === "udp-fallback") {
        await waitForEvent("publishers.ready");
        for (const service of publisherServices) {
          const sockets = compose(["exec", "-T", service, "ss", "-H", "-uan"]);
          writeFileSync(join(results, `${service}-udp-sockets-after-fallback.txt`), sockets);
          // Docker's embedded DNS listener belongs to this network namespace.
          const owned = sockets
            .trim()
            .split("\n")
            .filter((line) => line && !line.trim().split(/\s+/)[3]?.startsWith("127.0.0.11:"));
          if (owned.length) throw new Error(`${service} retained an abandoned QUIC socket`);
        }
        await event("udp.cleaned", true);
      }
      await waitForEvent("fault.release");
      for (const service of services) {
        const counters = compose([
          "exec",
          "-T",
          service,
          "iptables",
          "-L",
          "OUTPUT",
          "-n",
          "-v",
          "-x",
        ]);
        writeFileSync(join(results, `${scenario}-${service}-counters.txt`), counters);
        const dropped = counters.split("\n").filter((line) => line.includes("tnl-runtime-fault"));
        if (
          dropped.length !== rules.length / services.length ||
          dropped.some((line) => Number(line.trim().split(/\s+/)[0]) <= 0)
        )
          throw new Error(`${service} blackhole rule dropped no packets`);
      }
    });
  } else if (scenario === "latency" || scenario === "packet-loss") {
    const addresses = {
      "ingress-a": address("ingress-a"),
      "ingress-b": haTopology ? address("ingress-b") : address("ingress-a"),
      publishers: address("publishers"),
      "publishers-2": address("publishers-2"),
      "publishers-3": address("publishers-3"),
      "publishers-4": address("publishers-4"),
      "relay-a": address("relay-a"),
      "relay-b": address("relay-b"),
    };
    const endpoints = impairmentEndpoints(
      process.env.NETWORK_PATH,
      addresses,
      ingresses,
      activePublishers,
    );
    const options = netemOptions(scenario, process.env.RTT, process.env.LOSS, process.env.SEED);
    await withFaultCleanup(async (undo) => {
      const matched = new Set<RuntimeService>();
      for (const endpoint of endpoints) {
        const tc = (...args: string[]) => compose(["exec", "-T", endpoint.service, "tc", ...args]);
        tc(
          "qdisc",
          "add",
          "dev",
          "eth0",
          "root",
          "handle",
          "1:",
          "prio",
          "bands",
          "3",
          "priomap",
          ...Array.from({ length: 16 }, () => "0"),
        );
        undo.push(["exec", "-T", endpoint.service, "tc", "qdisc", "del", "dev", "eth0", "root"]);
        tc("qdisc", "add", "dev", "eth0", "parent", "1:3", "handle", "30:", "netem", ...options);
        for (const filter of endpoint.filters)
          tc(
            "filter",
            "add",
            "dev",
            "eth0",
            "parent",
            "1:",
            "protocol",
            "ip",
            "prio",
            "1",
            "u32",
            ...filter,
            "flowid",
            "1:3",
          );
      }
      writeFileSync(
        join(results, "network-impairment.json"),
        JSON.stringify(
          {
            scenario,
            path: process.env.NETWORK_PATH,
            rtt: process.env.RTT,
            loss: process.env.LOSS,
            seed: process.env.SEED,
            endpoints,
            options,
          },
          null,
          2,
        ),
      );
      await event("fault.applied", { Started: started, Exited: new Date().toISOString() });
      await waitForEvent("fault.release");
      for (const endpoint of endpoints) {
        const tc = (command: "qdisc" | "filter") =>
          compose([
            "exec",
            "-T",
            endpoint.service,
            "tc",
            "-j",
            "-s",
            command,
            "show",
            "dev",
            "eth0",
          ]);
        const evidence = {
          qdisc: parseJSON(tc("qdisc"), qdiscsSchema, "tc qdisc evidence"),
          filter: parseJSON(tc("filter"), z.array(z.unknown()), "tc filter evidence"),
          tcp: compose(["exec", "-T", endpoint.service, "ss", "-tin"]),
        };
        writeFileSync(
          join(results, `${endpoint.service}-netem.json`),
          JSON.stringify(evidence, null, 2),
        );
        if (evidence.qdisc.some((q) => q.kind === "netem" && (q.packets ?? 0) > 0))
          matched.add(endpoint.service);
      }
      // A healthy route may use only one relay. Require both directions of an
      // exercised path, while retaining zero counters for the unused alternate.
      if (
        (process.env.NETWORK_PATH === "forwarding"
          ? ingresses.some((service) => !matched.has(service))
          : activePublishers.some((service) => !matched.has(service))) ||
        !(["relay-a", "relay-b"] as const).some((service) => matched.has(service))
      )
        throw new Error("netem did not impair both directions of a visitor path");
    });
  } else {
    throw new Error(`unknown external fault: ${scenario}`);
  }
  await event("fault.restored", new Date().toISOString());
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
        "label=com.docker.compose.project=tnl-separated-load-test",
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
        intentionalRelayExit &&
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
        faultTask = applyFault(scenario, containers).catch((error) => {
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
  writeFileSync(
    join(results, "containers-before-cleanup.json"),
    cleanup(["ps", "--all", "--format", "json"]),
  );
  for (const services of [
    ["visitor-1", "visitor-2", "visitor-3", "visitor-4"],
    [...appServices, ...publisherServices],
    ["ingress-a", ...(haTopology ? ["ingress-b"] : []), "relay-a", "relay-b"],
    ["control-a", ...(haTopology ? ["control-b"] : []), "pebble", "coordinator"],
    ["postgres"],
  ])
    cleanup(["stop", ...services]);
  writeFileSync(join(results, "containers.json"), cleanup(["ps", "--all", "--format", "json"]));
  if (logs && logs.exitCode === null && logs.signalCode === null) {
    const process = logs;
    const exited = new Promise<void>((resolve) => process.once("exit", () => resolve()));
    process.kill("SIGTERM");
    await exited;
  }
  cleanup(["down", "--volumes", "--remove-orphans"]);
}
process.exitCode = status;
