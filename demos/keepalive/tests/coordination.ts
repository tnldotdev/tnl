import { Gossip, PROBE_MS, parseMessage, type GossipMessage } from "../src/peers/gossip.ts";
import { HOST_PARENT, sameRun, type Host } from "../src/peers/host.ts";
import { MAX_MESSAGE_BYTES } from "../src/peers/report.ts";
import { HOST_TURN_MS, REPLACE_BEFORE_MS, hostTarget } from "../src/policy.ts";
import { distribution } from "./measure.ts";

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
    state += 0x6d2b79f5;
    let n = Math.imul(state ^ (state >>> 15), state | 1);
    n ^= n + Math.imul(n ^ (n >>> 7), n | 61);
    return ((n ^ (n >>> 14)) >>> 0) / 4_294_967_296;
  };
}

type Node = {
  index: number;
  host: Host;
  view: Gossip;
  online: boolean;
  leaving: boolean;
  readers: number;
  endsAt: number;
  pendingReplacement: boolean;
  replacement?: Node;
};

export type CoordinationSample = {
  elapsedMs: number;
  online: number;
  joins: number;
  departures: number;
  invitations: number;
  rosterCoverage: ReturnType<typeof distribution>;
  staleHosts: ReturnType<typeof distribution>;
  audience: ReturnType<typeof distribution>;
  freshAudienceCoverage: ReturnType<typeof distribution>;
  hostTargets: ReturnType<typeof distribution>;
};

export async function simulateCoordination(settings: CoordinationSettings) {
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
    !["growth", "loss", "partition", "turnover"].includes(settings.scenario)
  )
    throw new Error("invalid coordination settings");
  const base = Date.UTC(2026, 10, 27);
  const releaseID = "a".repeat(64);
  let stopAt = base + settings.durationMs;
  let outcome: "completed" | "recruitment_limit" = "completed";
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
        to.view.receive(outbound, now);
        const reply = wire(to.view.message(now, outbound));
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
      pendingReplacement: false,
    };
    nodes.push(node);
    byOrigin.set(host.origin, node);
    if (index < settings.hosts) introduced++;
    allocateReaders();
    if (donor?.online) {
      node.view.receive(donor.view.message(now), now);
      donor.view.receive(node.view.message(now), now);
    }
    joins++;
    events.add(now + Math.floor(random() * PROBE_MS), () => tick(node));
    if (settings.discovery !== "none")
      events.add(now + 27_000 + Math.floor(random() * 6_000), () => discover(node));
    events.add(endsAt, () => leave(node, false));
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
      const report = wire(selected.view.message(now), undefined, true);
      if (report) node.view.receive(report, now);
      else failedDiscoveryRequests++;
    });
    events.add(now + 27_000 + Math.floor(random() * 6_000), () => discover(node));
  }

  function leave(node: Node, graceful: boolean) {
    if (!node.online || node.leaving) return;
    const finish = () => {
      node.online = false;
      node.readers = 0;
      departures++;
      allocateReaders();
    };
    if (graceful) {
      node.leaving = true;
      allocateReaders();
      const message = node.view.leave(now);
      // mirror peerServer.stop's three finite final reports and shared deadline.
      const hosts =
        settings.departure === "insertion"
          ? node.view.hosts(now).slice(0, 3)
          : node.view.departurePeers(now, node.replacement?.host);
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
    const departing = now >= node.endsAt - REPLACE_BEFORE_MS;
    node.view.update({ departing });
    // a fixed reader population is redistributed on membership changes. real
    // leases, reader movement, and sampling have separate tests.
    node.view.observeTabs(node.readers, now);
    const task = node.view
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
    if (settings.scenario === "turnover" && now >= startsAfter) {
      // model an available volunteer polling this donor. startup/confirmation is
      // an explicit 30 s fixture, not a measured browser or control operation.
      const offered = node.view.maybeStart(
        now,
        hostTarget(node.view.tabs(now)),
        () => !node.pendingReplacement,
        random,
      );
      if (offered) {
        invitations++;
        node.pendingReplacement = true;
        node.view.confirmStart(now + 180_000);
        events.add(now + 30_000, () => {
          node.pendingReplacement = false;
          node.view.finishStart();
          if (!node.online || now >= stopAt) return;
          node.replacement = start(nodes.length, node);
          if (departing || now >= node.endsAt - REPLACE_BEFORE_MS) {
            // peerServer retains its confirmation receipt for 12 s; the donor
            // must stay available while the successor can replay confirmation.
            events.add(now + 12_000, () => {
              if (node.online && !node.leaving) {
                earlyRetirements++;
                leave(node, true);
              }
            });
          }
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
    for (const node of live) {
      const hosts = node.view.hosts(now);
      coverage.push((1 + hosts.filter((host) => identities.has(host.runID)).length) / live.length);
      stale.push(hosts.filter((host) => !identities.has(host.runID)).length);
      const tabs = node.view.tabs(now);
      audience.push(tabs);
      freshAudience.push(tabs / (introduced * 50));
      targets.push(hostTarget(tabs));
    }
    samples.push({
      elapsedMs: now - base,
      online: live.length,
      joins,
      departures,
      invitations,
      rosterCoverage: distribution(coverage),
      staleHosts: distribution(stale),
      audience: distribution(audience),
      freshAudienceCoverage: distribution(freshAudience),
      hostTargets: distribution(targets),
    });
    if (now + 15_000 <= stopAt) events.add(now + 15_000, sample);
  }

  for (let i = 0; i < settings.hosts; i++)
    events.add(base + Math.floor((i / settings.hosts) * 60_000), () => {
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
      departurePeers: settings.departure ?? "current",
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
    abruptlyLost: faulted.size,
    samples,
  };
}
