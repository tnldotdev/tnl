import { Gossip, PROBE_MS, parseMessage, type GossipMessage } from "../src/peers/gossip.ts";
import { HOST_PARENT, sameRun, type Host } from "../src/peers/host.ts";
import { MAX_MESSAGE_BYTES } from "../src/peers/report.ts";
import { HOST_TURN_MS, REPLACE_BEFORE_MS, hostTarget } from "../src/policy.ts";
import { distribution } from "./measure.ts";
import { capacityTarget } from "./recruitment.ts";
import { getHeapStatistics } from "node:v8";

export type CoordinationScenario = "growth" | "loss" | "partition" | "turnover";
export type CoordinationSettings = {
  hosts: number;
  durationMs: number;
  seed: number;
  scenario: CoordinationScenario;
  latencyMs: number;
  loss: number;
  discovery?: "shared" | "none";
  departure?: "current" | "insertion";
  policy?: "visitors" | "capacity";
  readerBytesPerSecond?: number;
  safeBytesPerSecondPerHost?: number;
};

// virtual time drives the production gossip implementation. this is not a
// browser, HTTP, control, or relay capacity test.
type Event = { at: number; order: number; run: () => void };
class Events {
  readonly #heap: Event[] = [];
  #order = 0;

  get nextAt() {
    return this.#heap[0]?.at ?? Infinity;
  }

  add(at: number, run: () => void) {
    const event = { at, order: this.#order++, run };
    let index = this.#heap.length;
    this.#heap.push(event);
    while (index > 0) {
      const parent = Math.floor((index - 1) / 2);
      const previous = this.#heap[parent];
      if (!previous || !this.#before(event, previous)) break;
      this.#heap[index] = previous;
      index = parent;
    }
    this.#heap[index] = event;
  }

  take() {
    const first = this.#heap[0];
    const last = this.#heap.pop();
    if (!first || !last || first === last) return first;
    let index = 0;
    while (true) {
      let child = index * 2 + 1;
      const left = this.#heap[child];
      if (!left) break;
      const right = this.#heap[child + 1];
      if (right && this.#before(right, left)) child++;
      const next = this.#heap[child];
      if (!next || !this.#before(next, last)) break;
      this.#heap[index] = next;
      index = child;
    }
    this.#heap[index] = last;
    return first;
  }

  #before(a: Event, b: Event) {
    return a.at < b.at || (a.at === b.at && a.order < b.order);
  }
}

export function seededRandom(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let n = Math.imul(state ^ (state >>> 15), state | 1);
    n ^= n + Math.imul(n ^ (n >>> 7), n | 61);
    return ((n ^ (n >>> 14)) >>> 0) / 4_294_967_296;
  };
}

type Node = {
  index: number;
  host: Host;
  view: Gossip | null;
  online: boolean;
  leaving: boolean;
  readers: number;
  endsAt: number;
  replacementStartsAt: number;
  confirmingUntil: number;
  pendingReplacement: boolean;
  replacement?: Node;
};

export type CoordinationSample = {
  elapsedMs: number;
  online: number;
  joins: number;
  departures: number;
  invitations: number;
  readyBeyondWindow: number;
  starting: number;
  rosterCoverage: ReturnType<typeof viewDistribution>;
  staleHosts: ReturnType<typeof viewDistribution>;
  audience: ReturnType<typeof viewDistribution>;
  freshAudienceCoverage: ReturnType<typeof viewDistribution>;
  hostTargets: ReturnType<typeof viewDistribution>;
  observedReady: ReturnType<typeof viewDistribution>;
  observedStarting: ReturnType<typeof viewDistribution>;
  observedDeficit: ReturnType<typeof viewDistribution>;
  retainedViews: number;
};

function ownedView(node: Node) {
  if (node.view === null) throw new Error("simulation accessed a retired host's gossip owner");
  return node.view;
}

function viewDistribution(values: readonly number[]) {
  const ordered = [...values].sort((a, b) => a - b);
  return {
    ...distribution(ordered),
    min: ordered[0] ?? null,
    p01: ordered[Math.ceil(ordered.length * 0.01) - 1] ?? null,
    p05: ordered[Math.ceil(ordered.length * 0.05) - 1] ?? null,
    max: ordered.at(-1) ?? null,
  };
}

export async function simulateCoordination(
  settings: CoordinationSettings,
  record?: (sample: CoordinationSample) => void,
) {
  if (
    !Number.isInteger(settings.hosts) ||
    settings.hosts < 3 ||
    settings.hosts > 1_000 ||
    !Number.isSafeInteger(settings.durationMs) ||
    settings.durationMs < 60_000 ||
    settings.durationMs > 3_600_000 ||
    !Number.isSafeInteger(settings.seed) ||
    !Number.isFinite(settings.latencyMs) ||
    settings.latencyMs < 1 ||
    settings.latencyMs > 1_000 ||
    !Number.isFinite(settings.loss) ||
    settings.loss < 0 ||
    settings.loss > 0.5 ||
    (settings.discovery !== undefined && !["shared", "none"].includes(settings.discovery)) ||
    (settings.departure !== undefined && !["current", "insertion"].includes(settings.departure)) ||
    (settings.policy !== undefined && !["visitors", "capacity"].includes(settings.policy)) ||
    (settings.policy === "capacity" &&
      (settings.readerBytesPerSecond === undefined ||
        !Number.isFinite(settings.readerBytesPerSecond) ||
        settings.readerBytesPerSecond < 0 ||
        settings.safeBytesPerSecondPerHost === undefined ||
        !Number.isFinite(settings.safeBytesPerSecondPerHost) ||
        settings.safeBytesPerSecondPerHost <= 0)) ||
    !["growth", "loss", "partition", "turnover"].includes(settings.scenario)
  )
    throw new Error("invalid coordination settings");
  const base = Date.UTC(2026, 10, 27);
  const releaseID = "a".repeat(64);
  let stopAt = base + settings.durationMs;
  let outcome: "completed" | "recruitment_limit" | "harness_memory_limit" = "completed";
  const heapLimitBytes = getHeapStatistics().heap_size_limit;
  // leave room for old-space pressure, young generations, and recording a
  // complete failed result. V8 can exhaust old space below heap_size_limit.
  const heapStopBytes = Math.floor(heapLimitBytes * 0.5);
  let eventCount = 0;
  const events = new Events();
  const random = seededRandom(settings.seed);
  const nodes: Node[] = [];
  const byOrigin = new Map<string, Node>();
  const samples: CoordinationSample[] = [];
  const pending = new Set<Promise<void>>();
  const failures: unknown[] = [];
  let now = base;
  let requests = 0;
  let failedRequests = 0;
  let bytes = 0;
  let maximumMessageBytes = 0;
  let joins = 0;
  let departures = 0;
  let invitations = 0;
  let earlyRetirements = 0;
  let surplusRetirements = 0;
  let failedStarts = 0;
  let introduced = 0;
  let discoveryRequests = 0;
  let failedDiscoveryRequests = 0;
  let discoveryBytes = 0;
  let discoveryCursor = 0;
  const faultAt = base + Math.min(300_000, settings.durationMs / 3);
  const healedAt = faultAt + 120_000;
  const faulted = new Set<number>();
  const startsAfter = base + 120_000;
  const cohort = (node: Node) => node.index % 2;
  const reachable = (from: Node, to: Node) =>
    from.online &&
    to.online &&
    !(
      settings.scenario === "partition" &&
      now >= faultAt &&
      now < healedAt &&
      cohort(from) !== cohort(to)
    );

  function allocateReaders() {
    const live = nodes.filter((node) => node.online && !node.leaving);
    const total = introduced * 50;
    for (const [index, node] of live.entries())
      node.readers = Math.floor(total / live.length) + Number(index < total % live.length);
  }

  function target(node: Node) {
    const tabs = ownedView(node).tabs(now);
    if (settings.policy !== "capacity") return hostTarget(tabs);
    // synthetic offered load follows this fixture's reader population. the live
    // system needs real load reports before it can use the candidate policy.
    return capacityTarget({
      countedReaderLeases: tabs,
      readerBytesPerSecond: ((settings.readerBytesPerSecond ?? 0) * tabs) / (settings.hosts * 50),
      safeBytesPerSecondPerHost: settings.safeBytesPerSecondPerHost ?? 0,
    });
  }

  function wire(message: GossipMessage, envelope?: Host, discovery = false) {
    const json = JSON.stringify(envelope ? { target: envelope, message } : message);
    const size = Buffer.byteLength(json);
    maximumMessageBytes = Math.max(maximumMessageBytes, size);
    if (size > MAX_MESSAGE_BYTES) throw new Error("gossip message exceeded the wire bound");
    bytes += size;
    if (discovery) discoveryBytes += size;
    // cross the actual JSON and validator boundary, rather than sharing objects.
    const value: unknown = JSON.parse(json);
    return parseMessage(envelope ? (value as { message: unknown }).message : value, releaseID, now);
  }

  function delay() {
    return Math.max(1, Math.round(settings.latencyMs * (0.5 + random())));
  }

  function send(
    from: Node,
    target: Host,
    message: GossipMessage,
    helper?: Host,
    timeoutMs?: number,
  ) {
    requests++;
    return new Promise<GossipMessage | undefined>((resolve) => {
      let completed = false;
      const finish = (reply?: GossipMessage) => {
        if (completed) return;
        completed = true;
        if (!reply) failedRequests++;
        resolve(reply);
      };
      const to = byOrigin.get(target.origin);
      const via = helper ? byOrigin.get(helper.origin) : undefined;
      const outbound = wire(message, helper ? target : undefined);
      events.add(now + (timeoutMs ?? (helper ? 2_400 : 1_800)), () => finish());
      if (!outbound || !to || !sameRun(to.host, target) || (helper && !via)) return;
      const path = via ? [from, via, to] : [from, to];
      const travel = delay() * (path.length - 1);
      const canSend = () =>
        path.every((node, i) => {
          const previous = path[i - 1];
          return i === 0 || (previous !== undefined && reachable(previous, node));
        });
      if (!canSend() || random() < settings.loss) return;
      events.add(now + travel, () => {
        if (completed || !canSend()) return;
        ownedView(to).receive(outbound, now);
        const reply = wire(ownedView(to).message(now, outbound));
        if (random() < settings.loss) return;
        events.add(now + travel, () => {
          if (canSend()) finish(reply);
        });
      });
    });
  }

  function start(index: number, donor?: Node): Node {
    const id = String(index + 1).padStart(22, "0");
    const label = (index + 1)
      .toString(2)
      .replaceAll("0", "a")
      .replaceAll("1", "b")
      .padStart(26, "a");
    const host = {
      origin: `https://p-${label}.${HOST_PARENT}`,
      publisherID: `pub_${id}`,
      runID: `srun_${id}`,
      runNumber: "1",
    };
    const endsAt = now + HOST_TURN_MS;
    const node: Node = {
      index,
      host,
      view: new Gossip(releaseID, host, now, { endsAt, copyFrom: donor?.host.runID }),
      online: true,
      leaving: false,
      readers: 0,
      endsAt,
      replacementStartsAt: endsAt - REPLACE_BEFORE_MS + Math.floor(random() * 5_000),
      confirmingUntil: 0,
      pendingReplacement: false,
    };
    nodes.push(node);
    byOrigin.set(host.origin, node);
    if (index < settings.hosts) introduced++;
    allocateReaders();
    if (donor?.online) {
      ownedView(node).receive(ownedView(donor).message(now), now);
      ownedView(donor).receive(ownedView(node).message(now), now);
    }
    joins++;
    events.add(now + Math.floor(random() * PROBE_MS), () => tick(node));
    if (settings.discovery !== "none")
      events.add(now + 27_000 + Math.floor(random() * 6_000), () => discover(node));
    events.add(endsAt, () => {
      if (now <= stopAt) leave(node, true);
    });
    return node;
  }

  function discover(node: Node) {
    if (!node.online || node.leaving || now >= stopAt) return;
    discoveryRequests++;
    // model a healthy shared-address lookup, not the Worker's isolate-local
    // candidate cache. this is an optimistic discovery fixture.
    const live = nodes.filter((peer) => peer.online && !peer.leaving);
    const selected = live[discoveryCursor++ % live.length];
    events.add(now + delay() * 2, () => {
      if (!node.online || node.leaving) return;
      if (!selected || !reachable(node, selected) || random() < settings.loss) {
        failedDiscoveryRequests++;
        return;
      }
      const report = wire(ownedView(selected).message(now), undefined, true);
      if (report) ownedView(node).receive(report, now);
      else failedDiscoveryRequests++;
    });
    events.add(now + 27_000 + Math.floor(random() * 6_000), () => discover(node));
  }

  function leave(node: Node, graceful: boolean) {
    if (!node.online || node.leaving) return;
    const finish = () => {
      node.online = false;
      // real browser shutdown releases its worker and roster. retain only the
      // run metadata needed to reject stale traffic, not the dead gossip owner.
      node.view = null;
      node.readers = 0;
      departures++;
      allocateReaders();
    };
    if (graceful) {
      node.leaving = true;
      allocateReaders();
      const message = ownedView(node).leave(now);
      // mirror peerServer.stop's three finite final reports and shared deadline.
      const hosts =
        settings.departure === "insertion"
          ? ownedView(node).hosts(now).slice(0, 3)
          : ownedView(node).departurePeers(now, node.replacement?.host);
      if (hosts.length) {
        const task = Promise.all(
          hosts.map((target) => send(node, target, message, undefined, 1_000)),
        ).then(finish);
        pending.add(task);
        void task
          .finally(() => pending.delete(task))
          .catch((error: unknown) => failures.push(error));
        return;
      }
    }
    finish();
  }

  function tick(node: Node) {
    if (!node.online || node.leaving || now >= stopAt) return;
    const view = ownedView(node);
    const departing = now >= node.replacementStartsAt;
    view.update({ departing });
    // a fixed reader population is redistributed on membership changes. real
    // leases, reader movement, and sampling have separate tests.
    view.observeTabs(node.readers, now);
    const task = view
      .probe(
        () => now,
        random,
        (target, message, helper) => send(node, target, message, helper),
      )
      .catch((error: unknown) => {
        failures.push(error);
      });
    pending.add(task);
    void task.finally(() => pending.delete(task)).catch((error: unknown) => failures.push(error));
    // mirror the worker's report callback, including surplus retirement without
    // an invitation. a confirmed successor and any other confirmation receipt
    // keep the donor available until the receipt expires.
    if (
      departing &&
      now >= node.confirmingUntil &&
      (node.replacement !== undefined || view.canRetire(now, target(node), view.hosts(now)))
    ) {
      earlyRetirements++;
      if (node.replacement === undefined) surplusRetirements++;
      leave(node, true);
      return;
    }
    if (settings.scenario === "turnover" && now >= startsAfter) {
      // model an available volunteer polling this donor. startup/confirmation is
      // an explicit 30 s fixture, not a measured browser or control operation.
      const offered = view.maybeStart(now, target(node), () => !node.pendingReplacement, random);
      if (offered) {
        invitations++;
        node.pendingReplacement = true;
        view.confirmStart(now + 180_000);
        events.add(now + 30_000, () => {
          node.pendingReplacement = false;
          if (now >= stopAt) return;
          if (!node.online || node.leaving) {
            failedStarts++;
            return;
          }
          ownedView(node).finishStart();
          const successor = start(nodes.length, node);
          // promotion.replacing is captured when the invitation is offered, not
          // reconstructed from the donor's state when startup finishes.
          if (departing) node.replacement = successor;
          node.confirmingUntil = now + 12_000;
        });
      }
    }
    events.add(now + PROBE_MS + Math.floor(random() * 1_000), () => tick(node));
  }

  function sample() {
    if (now > stopAt) return;
    const live = nodes.filter((node) => node.online);
    const identities = new Set(live.map((node) => node.host.runID));
    const coverage: number[] = [];
    const stale: number[] = [];
    const audience: number[] = [];
    const freshAudience: number[] = [];
    const targets: number[] = [];
    const ready: number[] = [];
    const starting: number[] = [];
    const deficits: number[] = [];
    for (const node of live) {
      const view = ownedView(node);
      const hosts = view.hosts(now);
      coverage.push((1 + hosts.filter((host) => identities.has(host.runID)).length) / live.length);
      stale.push(hosts.filter((host) => !identities.has(host.runID)).length);
      const tabs = view.tabs(now);
      audience.push(tabs);
      freshAudience.push(tabs / (introduced * 50));
      const desired = target(node);
      const available = view.readyBeyondWindow(now, hosts);
      const pendingStarts =
        Number(node.pendingReplacement) + hosts.filter((host) => host.startingUntil > now).length;
      targets.push(desired);
      ready.push(available);
      starting.push(pendingStarts);
      deficits.push(Math.max(0, desired - available - pendingStarts));
    }
    const snapshot: CoordinationSample = {
      elapsedMs: now - base,
      online: live.length,
      joins,
      departures,
      invitations,
      readyBeyondWindow: live.filter(
        (node) => !node.leaving && node.endsAt > now + REPLACE_BEFORE_MS,
      ).length,
      starting: live.filter((node) => node.pendingReplacement).length,
      rosterCoverage: viewDistribution(coverage),
      staleHosts: viewDistribution(stale),
      audience: viewDistribution(audience),
      freshAudienceCoverage: viewDistribution(freshAudience),
      hostTargets: viewDistribution(targets),
      observedReady: viewDistribution(ready),
      observedStarting: viewDistribution(starting),
      observedDeficit: viewDistribution(deficits),
      retainedViews: nodes.filter((node) => node.view !== null).length,
    };
    samples.push(snapshot);
    record?.(snapshot);
    if (now + 15_000 <= stopAt) events.add(now + 15_000, sample);
  }

  for (let i = 0; i < settings.hosts; i++)
    events.add(base + Math.floor((i / settings.hosts) * 60_000), () => {
      if (now >= stopAt) return;
      const live = nodes.filter((node) => node.online);
      start(i, live[Math.floor(random() * live.length)]);
    });
  if (settings.scenario === "loss") {
    events.add(faultAt, () => {
      for (const node of nodes)
        if (node.online && node.index % 4 === 0) {
          faulted.add(node.index);
          leave(node, false);
        }
    });
  }
  events.add(base + 15_000, sample);
  // drain microtasks after each event so an async probe's next step observes
  // this event's time, rather than the time at the end of the whole simulation.
  while (events.nextAt <= stopAt) {
    const event = events.take();
    if (!event) break;
    now = event.at;
    event.run();
    for (let i = 0; i < 12; i++) await Promise.resolve();
    if (failures.length) throw new AggregateError(failures, "coordination simulation failed");
    if (nodes.length > settings.hosts * 8) {
      outcome = "recruitment_limit";
      stopAt = now;
      sample();
      break;
    }
    if (++eventCount % 64 === 0 && getHeapStatistics().used_heap_size > heapStopBytes) {
      outcome = "harness_memory_limit";
      stopAt = now;
      sample();
      break;
    }
  }
  // no new probes are scheduled past stopAt. settle the finite in-flight work.
  now = stopAt;
  while (pending.size) {
    const event = events.take();
    if (!event) throw new Error("simulation retained an unresolved probe");
    now = event.at;
    event.run();
    for (let i = 0; i < 12; i++) await Promise.resolve();
  }
  if (failures.length) throw new AggregateError(failures, "coordination simulation failed");
  return {
    kind: "coordination-simulation" as const,
    outcome,
    simulatedMs: stopAt - base,
    settings,
    assumptions: {
      readers: settings.hosts * 50,
      readerPlacement: "instant redistribution; leases and sampling are not simulated",
      bootstrapSpreadMs: 60_000,
      replacementStartupMs: settings.scenario === "turnover" ? 30_000 : null,
      confirmationReceiptMs: 12_000,
      replacementJitterMs: [0, 5_000],
      retirement: "worker decision on each tick: confirmed successor or fresh surplus capacity",
      naturalExpiry: "graceful final reports; abrupt loss remains unannounced",
      departurePeers: settings.departure ?? "current",
      policy: settings.policy ?? "visitors",
      readerDemand:
        settings.policy === "capacity"
          ? "synthetic demand proportional to observed fixture readers; no live load measurements"
          : null,
      volunteerSupply: settings.scenario === "turnover" ? "available at each donor tick" : "none",
      requestTimeoutMs: 1_800,
      discovery:
        settings.discovery === "none"
          ? "none"
          : "optimistic fresh shared-address report every 27–33 s; not the Worker cache",
      transport: "virtual JSON exchanges; no browser, HTTP, control, or relay",
    },
    requests,
    failedRequests,
    jsonBytes: bytes,
    gossipJsonBytes: bytes - discoveryBytes,
    discoveryJsonBytes: discoveryBytes,
    discoveryRequests,
    failedDiscoveryRequests,
    maximumMessageBytes,
    joins,
    departures,
    invitations,
    earlyRetirements,
    surplusRetirements,
    failedStarts,
    abruptlyLost: faulted.size,
    harness: {
      heapLimitBytes,
      heapStopBytes,
      retainedViews: nodes.filter((node) => node.view !== null).length,
      retiredViewsRetained: nodes.filter((node) => !node.online && node.view !== null).length,
    },
    samples,
  };
}
