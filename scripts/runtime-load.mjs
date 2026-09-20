import { spawn, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

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
    timeout: 180_000,
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
const externalFault = ["relay-kill", "forwarding-blackhole"].includes(process.env.SCENARIO);
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

async function applyFault(scenario, containers) {
  const started = new Date().toISOString();
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
  } else if (scenario === "forwarding-blackhole") {
    const relay = JSON.parse(docker(["inspect", containers["relay-a"]]))[0];
    const address = Object.values(relay.NetworkSettings.Networks)[0].IPAddress;
    if (!address) throw new Error("relay has no IPv4 address");
    const rule = [
      "OUTPUT",
      "-d",
      address,
      "-p",
      "tcp",
      "--dport",
      "8443",
      "-m",
      "comment",
      "--comment",
      "tnl-runtime-fault",
      "-j",
      "DROP",
    ];
    compose(["exec", "-T", "ingress", "iptables", "-I", ...rule]);
    try {
      await event("fault.applied", { Started: started, Exited: new Date().toISOString() });
      await interruptibleSleep(15_000);
      const counters = compose([
        "exec",
        "-T",
        "ingress",
        "iptables",
        "-L",
        "OUTPUT",
        "-n",
        "-v",
        "-x",
      ]);
      writeFileSync(join(results, "forwarding-blackhole-counters.txt"), counters);
      const dropped = counters.split("\n").find((line) => line.includes("tnl-runtime-fault"));
      if (!dropped || Number(dropped.trim().split(/\s+/)[0]) <= 0)
        throw new Error("blackhole rule dropped no packets");
    } finally {
      compose(["exec", "-T", "ingress", "iptables", "-D", ...rule]);
    }
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
