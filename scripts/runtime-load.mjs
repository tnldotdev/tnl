import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { impairmentEndpoints, netemOptions } from "./runtime-network.mjs";

const results = process.env.RESULTS;
if (!results) throw new Error("RESULTS is required");
if (existsSync(results) && readdirSync(results).length !== 0)
  throw new Error(
    "RESULTS must be a fresh or empty directory; preserve earlier experiment artifacts",
  );
mkdirSync(results, { recursive: true });
const composeArgs = [
  "compose",
  "--ansi",
  "never",
  "--progress",
  "plain",
  "--file",
  "internal/tnldruntime/testdata/separated-load.compose.yaml",
];
function docker(args, quiet = false) {
  return execFileSync("docker", args, {
    encoding: "utf8",
    // A fresh CI runner compiles the race binary and dependencies inside Docker.
    timeout: args.includes("build") ? 600_000 : 180_000,
    stdio: ["ignore", "pipe", quiet ? "pipe" : "inherit"],
  });
}
const compose = (args, quiet = false) => docker([...composeArgs, ...args], quiet);
let logs;
let stopping = false;
let token;
let endpoint;
let faultTask;
let faultError;
let intentionalRelayExit = false;
let faultStarted = false;
let interrupted = false;
const externalFault = [
  "relay-kill",
  "forwarding-blackhole",
  "publisher-blackhole",
  "udp-fallback",
  "latency",
  "packet-loss",
].includes(process.env.SCENARIO);
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"])
  process.on(signal, () => {
    interrupted = true;
  });

async function event(name, value) {
  const response = await fetch(`${endpoint}/v1/events/${name}`, {
    method: value === undefined ? "GET" : "PUT",
    headers: { Authorization: `Bearer ${token}` },
    body: value === undefined ? undefined : JSON.stringify(value),
    signal: AbortSignal.timeout(15_000),
  });
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`coordinator ${name}: HTTP ${response.status}`);
  if (response.status === 204) return;
  return response.json();
}

async function interruptibleSleep(ms) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (stopping || interrupted) throw new Error("runtime workload interrupted");
    await sleep(Math.min(250, until - Date.now()));
  }
}

// Restore every owned mutation even when setup or evidence collection fails.
// Keep the original failure alongside cleanup failures.
async function withFaultCleanup(run) {
  const undo = [];
  const failures = [];
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

async function applyFault(scenario, containers) {
  const started = new Date().toISOString();
  const address = (service) => {
    const container = JSON.parse(docker(["inspect", containers[service]]))[0];
    const value = Object.values(container.NetworkSettings.Networks)[0].IPAddress;
    if (!value) throw new Error(`${service} has no IPv4 address`);
    return value;
  };
  const waitForEvent = async (name) => {
    const deadline = Date.now() + 600_000;
    while (!(await event(name))) {
      if (Date.now() >= deadline) throw new Error("active-fault measurement exceeded watchdog");
      await interruptibleSleep(250);
    }
  };
  if (scenario === "relay-kill") {
    intentionalRelayExit = true;
    compose(["kill", "--signal", "SIGKILL", "relay-a"]);
    const state = JSON.parse(docker(["inspect", containers["relay-a"]]))[0].State;
    if (state.Running || state.ExitCode !== 137)
      throw new Error("relay kill did not produce the expected process exit");
    await event("fault.applied", { Started: started, Exited: new Date().toISOString() });
    // Exceed the actual 30-second relay lease without changing production timers.
    await interruptibleSleep(31_000);
    compose(["start", "relay-a"]);
    intentionalRelayExit = false;
  } else if (["forwarding-blackhole", "publisher-blackhole", "udp-fallback"].includes(scenario)) {
    const service = scenario === "forwarding-blackhole" ? "ingress" : "publishers";
    const relays = scenario === "udp-fallback" ? ["relay-a", "relay-b"] : ["relay-a"];
    const protocols =
      scenario === "publisher-blackhole"
        ? ["tcp", "udp"]
        : [scenario === "udp-fallback" ? "udp" : "tcp"];
    const rules = [];
    await withFaultCleanup(async (undo) => {
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
        const sockets = compose(["exec", "-T", "publishers", "ss", "-H", "-uan"]);
        writeFileSync(join(results, "publisher-udp-sockets-after-fallback.txt"), sockets);
        // Docker's embedded DNS listener belongs to this network namespace.
        const owned = sockets
          .trim()
          .split("\n")
          .filter((line) => line && !line.trim().split(/\s+/)[3]?.startsWith("127.0.0.11:"));
        if (owned.length) throw new Error("abandoned QUIC attempt retained a UDP socket");
        await event("udp.cleaned", true);
      }
      await waitForEvent("fault.release");
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
      writeFileSync(join(results, `${scenario}-counters.txt`), counters);
      const dropped = counters.split("\n").filter((line) => line.includes("tnl-runtime-fault"));
      if (
        dropped.length !== rules.length ||
        dropped.some((line) => Number(line.trim().split(/\s+/)[0]) <= 0)
      )
        throw new Error("blackhole rule dropped no packets");
    });
  } else if (["latency", "packet-loss"].includes(scenario)) {
    const addresses = Object.fromEntries(
      ["ingress", "publishers", "relay-a", "relay-b"].map((service) => [service, address(service)]),
    );
    const endpoints = impairmentEndpoints(process.env.NETWORK_PATH, addresses);
    const options = netemOptions(scenario, process.env.RTT, process.env.LOSS, process.env.SEED);
    await withFaultCleanup(async (undo) => {
      const matched = new Set();
      for (const endpoint of endpoints) {
        const tc = (...args) => compose(["exec", "-T", endpoint.service, "tc", ...args]);
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
          ...Array(16).fill("0"),
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
        const evidence = {};
        for (const command of ["qdisc", "filter"])
          evidence[command] = JSON.parse(
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
            ]),
          );
        evidence.tcp = compose(["exec", "-T", endpoint.service, "ss", "-tin"]);
        writeFileSync(
          join(results, `${endpoint.service}-netem.json`),
          JSON.stringify(evidence, null, 2),
        );
        if (evidence.qdisc.some((q) => q.kind === "netem" && q.packets > 0))
          matched.add(endpoint.service);
      }
      // A healthy route may use only one relay. Require both directions of an
      // exercised path, while retaining zero counters for the unused alternate.
      if (
        !matched.has(endpoints[0].service) ||
        !["relay-a", "relay-b"].some((service) => matched.has(service))
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
  compose([
    "up",
    "--detach",
    "control",
    "ingress",
    "relay-a",
    "relay-b",
    "publishers",
    "visitor-1",
    "visitor-2",
    "visitor-3",
    "visitor-4",
    "app",
    "pebble",
    "coordinator",
  ]);
  logs = spawn("docker", [...composeArgs, "logs", "--follow", "--no-color"], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  const ids = compose(["ps", "--all", "--quiet"]).trim().split(/\s+/);
  const containers = {};
  for (const container of JSON.parse(docker(["inspect", ...ids])))
    containers[container.Config.Labels["com.docker.compose.service"]] = container.Id;
  endpoint = `http://${compose(["port", "coordinator", "8080"]).trim()}`;
  token = compose(["exec", "-T", "coordinator", "cat", "/load/coordinator-token"]).trim();
  const deadline = Date.now() + 20 * 60_000;
  for (;;) {
    if (interrupted) throw new Error("runtime workload interrupted");
    if (faultError) throw faultError;
    if (Date.now() > deadline) throw new Error("runtime workload exceeded 20 minutes");
    const states = JSON.parse(docker(["inspect", ...ids]));
    const coordinator = states.find((c) => c.Id === containers.coordinator);
    for (const container of states) {
      if (container.Id === containers.coordinator) continue;
      if (container.State.Running) continue;
      if (
        container.Id === containers["relay-a"] &&
        intentionalRelayExit &&
        container.State.ExitCode === 137
      )
        continue;
      throw new Error(`unexpected component exit: ${container.Name} (${container.State.ExitCode})`);
    }
    if (!coordinator.State.Running) {
      status = coordinator.State.ExitCode;
      break;
    }
    if (externalFault && !faultStarted) {
      const scenario = await event("fault.request");
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
  if (faultTask) await faultTask;
  if (faultError) {
    console.error(faultError);
    status = 1;
  }
  const cleanup = (args) => {
    try {
      return compose(args, true);
    } catch (error) {
      console.error(`cleanup ${args.join(" ")}: ${error.message}`);
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
    ["app", "publishers"],
    ["ingress", "relay-a", "relay-b"],
    ["control", "pebble", "coordinator"],
    ["postgres"],
  ])
    cleanup(["stop", ...services]);
  writeFileSync(join(results, "containers.json"), cleanup(["ps", "--all", "--format", "json"]));
  if (logs && logs.exitCode === null && logs.signalCode === null) {
    const exited = new Promise((resolve) => logs.once("exit", resolve));
    logs.kill("SIGTERM");
    await exited;
  }
  cleanup(["down", "--volumes", "--remove-orphans"]);
}
process.exitCode = status;
