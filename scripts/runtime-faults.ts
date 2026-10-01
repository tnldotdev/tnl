import { writeFileSync } from "node:fs";
import { join } from "node:path";
import * as z from "zod";
import {
  impairmentEndpoints,
  netemOptions,
  publisherServices,
  type RuntimeService,
} from "./runtime-network.ts";
import { parseJSON } from "./validation.ts";

export const faultSchema = z.enum([
  "relay-kill",
  "forwarding-blackhole",
  "publisher-blackhole",
  "udp-fallback",
  "latency",
  "packet-loss",
]);
export type Fault = z.infer<typeof faultSchema>;
export type FaultEvents = {
  "fault.applied": { Started: string; Exited: string };
  "fault.restored": string;
  "udp.cleaned": boolean;
};

type FaultContainer = {
  readonly State: { readonly Running: boolean; readonly ExitCode: number };
  readonly NetworkSettings: {
    readonly Networks: Readonly<Record<string, { readonly IPAddress: string }>>;
  };
};

export type FaultRuntime = {
  readonly compose: (args: readonly string[]) => string;
  readonly inspect: (service: RuntimeService) => FaultContainer;
  readonly readEvent: (name: "publishers.ready" | "fault.release") => Promise<boolean>;
  readonly event: <Name extends keyof FaultEvents>(
    name: Name,
    value: FaultEvents[Name],
  ) => Promise<void>;
  readonly sleep: (ms: number) => Promise<void>;
  readonly results: string;
  readonly ingresses: readonly ("ingress-a" | "ingress-b")[];
  readonly activePublishers: readonly (typeof publisherServices)[number][];
  readonly network: {
    readonly path: string | undefined;
    readonly rtt: string | undefined;
    readonly loss: string | undefined;
    readonly seed: string | undefined;
  };
  readonly state: { intentionalRelayExit: boolean };
};

const qdiscsSchema = z.array(z.looseObject({ kind: z.string(), packets: z.optional(z.number()) }));
const droppedPacketsSchema = z.string().regex(/^\d+$/).transform(Number).pipe(z.int().positive());

// restore every owned mutation even when setup or evidence collection fails.
// keep the original failure alongside cleanup failures.
async function withFaultCleanup(
  compose: FaultRuntime["compose"],
  run: (undo: string[][]) => Promise<void>,
): Promise<void> {
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

export async function applyFault(scenario: Fault, runtime: FaultRuntime): Promise<void> {
  const { compose, inspect, event, sleep, results, ingresses, activePublishers, network, state } =
    runtime;
  const started = new Date().toISOString();
  const address = (service: RuntimeService) => {
    const container = inspect(service);
    const value = Object.values(container.NetworkSettings.Networks)[0]?.IPAddress;
    if (!value) throw new Error(`${service} has no IPv4 address`);
    return value;
  };
  const waitForEvent = async (name: "publishers.ready" | "fault.release") => {
    const deadline = Date.now() + 600_000;
    while (!(await runtime.readEvent(name))) {
      if (Date.now() >= deadline) throw new Error("active-fault measurement exceeded watchdog");
      await sleep(250);
    }
  };
  if (scenario === "relay-kill") {
    state.intentionalRelayExit = true;
    compose(["kill", "--signal", "SIGKILL", "relay-a"]);
    const relay = inspect("relay-a");
    if (relay.State.Running || relay.State.ExitCode !== 137)
      throw new Error("relay kill did not produce the expected process exit");
    await event("fault.applied", { Started: started, Exited: new Date().toISOString() });
    // exceed the actual 30-second relay lease without changing production timers.
    await sleep(31_000);
    compose(["start", "relay-a"]);
    state.intentionalRelayExit = false;
  } else if (["forwarding-blackhole", "publisher-blackhole", "udp-fallback"].includes(scenario)) {
    const services: readonly RuntimeService[] =
      scenario === "forwarding-blackhole" ? ingresses : activePublishers;
    const relays: RuntimeService[] =
      scenario === "udp-fallback" ? ["relay-a", "relay-b"] : ["relay-a"];
    const protocols =
      scenario === "publisher-blackhole"
        ? ["tcp", "udp"]
        : [scenario === "udp-fallback" ? "udp" : "tcp"];
    const rulesPerService = relays.length * protocols.length;
    await withFaultCleanup(compose, async (undo) => {
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
          }
      await event("fault.applied", { Started: started, Exited: new Date().toISOString() });
      if (scenario === "udp-fallback") {
        await waitForEvent("publishers.ready");
        for (const service of publisherServices) {
          const sockets = compose(["exec", "-T", service, "ss", "-H", "-uan"]);
          writeFileSync(join(results, `${service}-udp-sockets-after-fallback.txt`), sockets);
          // docker's embedded DNS listener belongs to this network namespace.
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
          dropped.length !== rulesPerService ||
          dropped.some(
            (line) => !droppedPacketsSchema.safeParse(line.trim().split(/\s+/)[0]).success,
          )
        )
          throw new Error(`${service} blackhole rule dropped no packets`);
      }
    });
  } else if (scenario === "latency" || scenario === "packet-loss") {
    const addresses = {
      "ingress-a": address("ingress-a"),
      "ingress-b": ingresses.includes("ingress-b") ? address("ingress-b") : address("ingress-a"),
      publishers: address("publishers"),
      "publishers-2": address("publishers-2"),
      "publishers-3": address("publishers-3"),
      "publishers-4": address("publishers-4"),
      "relay-a": address("relay-a"),
      "relay-b": address("relay-b"),
    };
    const endpoints = impairmentEndpoints(network.path, addresses, ingresses, activePublishers);
    const options = netemOptions(scenario, network.rtt, network.loss, network.seed);
    await withFaultCleanup(compose, async (undo) => {
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
            path: network.path,
            rtt: network.rtt,
            loss: network.loss,
            seed: network.seed,
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
      // a healthy public URL may use only one connected relay. require both directions of an
      // exercised path, while retaining zero counters for the unused alternate.
      if (
        (network.path === "forwarding"
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
