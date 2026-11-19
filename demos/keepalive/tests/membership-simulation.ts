import assert from "node:assert/strict";
import { parseArgs } from "node:util";
import {
  Gossip,
  HOST_PARENT,
  MAX_CHANGES,
  MAX_MESSAGE_BYTES,
  MAX_PEERS,
  parseMessage,
  type Change,
  type Host,
  type PeerTransport,
} from "../src/peers/gossip.ts";
import { HOST_TURN_MS } from "../src/policy.ts";

const { values } = parseArgs({
  options: {
    hosts: { type: "string", default: "5000" },
    seed: { type: "string", default: "17" },
    "proxy-sample": { type: "boolean" },
    "tab-drop": { type: "boolean" },
    "field-latency": { type: "boolean" },
  },
});
const count = Number(values.hosts);
assert(Number.isInteger(count) && count >= 100 && count <= 5_000, "Pass --hosts 100 through 5000.");
const seed = Number(values.seed);
assert(Number.isInteger(seed) && seed >= 0 && seed <= 0xffffffff, "Pass a 32-bit unsigned seed.");
const partition = Math.floor(count / 2);
assert(!values["field-latency"] || count >= 500, "Field timing requires at least 500 hosts.");
const releaseID = "a".repeat(64);
const tick = 2_500;
const certificateRounds = 12; // model the SDK's 30-second replacement callback.
const renewalRound = 121;
const epoch = Date.UTC(2026, 10, 19);
const oldCertificate = { fingerprint: "b".repeat(64), expiresAt: epoch + 24 * 60 * 60_000 };
const renewedCertificate = {
  fingerprint: "c".repeat(64),
  expiresAt: epoch + 90 * 24 * 60 * 60_000,
};
let now = epoch;
let nextHost = 0;
let direct = 0;
let indirect = 0;
let dropped = 0;
let maxBytes = 0;
let maxRecords = 0;
let sampledReplyRecords = 0;
let sampledEchoes = 0;
let certificateAttempts = 0;
let certificateTransfers = 0;
let renewalP50Seconds: number | undefined;
let renewalP90Seconds: number | undefined;
const byPublisher = new Map<string, Node>();
const encoder = new TextEncoder();
function randomStream(initial: number) {
  let state = initial >>> 0;
  return () => {
    state = (Math.imul(1664525, state) + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}
// keep churn and timer phases independent of the protocol's random choices.
const churnRandom = randomStream(seed);
const discoveryRandom = randomStream(seed ^ 0x7e6679e1);
type Node = {
  slot: number;
  peer: Gossip;
  host: Host;
  tabs: number;
  installed: boolean;
  advertiseAt?: number;
};
function create(slot: number, copiedFrom?: Host): Node {
  const number = ++nextHost;
  const id = String(number).padStart(22, "0");
  const label = number.toString(2).replaceAll("0", "a").replaceAll("1", "b").padStart(26, "a");
  const host = {
    origin: `https://p-${label}.${HOST_PARENT}`,
    publisherID: `pub_${id}`,
    runID: `srun_${id}`,
    runNumber: String(number),
  };
  const peer = new Gossip(releaseID, host, now, {
    endsAt: now + HOST_TURN_MS,
    certificate: oldCertificate,
    ...(copiedFrom === undefined ? {} : { name: "quiet-pine", copyFrom: copiedFrom.runID }),
  });
  const node = { slot, host, peer, tabs: 25 + (slot % 51), installed: false };
  byPublisher.set(host.publisherID, node);
  return node;
}
const nodes = Array.from({ length: count }, (_, i) => create(i));
const part = (node: Node) => Number(node.slot >= partition);
const sample = (offset: number, cap: number) => {
  const step = Math.max(1, Math.floor(count / cap));
  return nodes.filter(({ slot }) => (slot + offset) % step === 0).slice(0, cap);
};
type Trace = {
  event: string;
  round: number;
  expected: (view: Node, records: readonly Change[], live: readonly Change[]) => boolean;
  eligible: Set<number>;
  seen: Map<number, number>;
};
const traces: Trace[] = [];
const observers = sample(0, 60).map(({ slot }) => slot);
function follow(event: string, round: number, expected: Trace["expected"], eligible = observers) {
  traces.push({ event, round, expected, eligible: new Set(eligible), seen: new Map() });
}
if (values["field-latency"]) {
  // the right half starts separately; its real start time is different until it learns
  // the older experiment start through a bridge.
  const later = epoch + 12_500;
  for (const node of nodes.slice(partition)) {
    node.peer = new Gossip(releaseID, node.host, later, {
      endsAt: epoch + HOST_TURN_MS,
      certificate: oldCertificate,
    });
  }
  follow(
    "earlier experiment start across a healed split",
    30,
    (view) => view.peer.startedAt === epoch,
    observers.filter((slot) => slot >= partition),
  );
}

function timingSummary() {
  for (const trace of traces) {
    const latency = [...trace.seen.values()].sort((a, b) => a - b);
    const percentile = (p: number) => latency[Math.ceil(p * trace.eligible.size) - 1] ?? null;
    console.log(
      JSON.stringify({
        event: trace.event,
        measured: trace.eligible.size,
        saw: latency.length,
        p50Seconds: percentile(0.5),
        p90Seconds: percentile(0.9),
      }),
    );
  }
}

// seed two disjoint groups using only bounded messages, not injected rosters.
for (const node of nodes) {
  const min = part(node) * partition;
  const width = min === 0 ? partition : count - partition;
  for (const hop of [1, 13, 67]) {
    const other = nodes[min + ((node.slot - min + hop) % width)];
    if (other !== undefined) node.peer.receive(other.peer.message(now), now);
  }
}

function observe(stage: string, suspended: (node: Node) => boolean) {
  const population = nodes.filter((node) => !suspended(node));
  const tabs = population.reduce((total, node) => total + node.tabs, 0);
  const summaries = sample(0, 50).map((node) => {
    const { peer, installed } = node;
    maxRecords = Math.max(maxRecords, peer.size);
    const hosts = peer.hosts(now);
    const currentHosts = hosts.filter((report) => {
      const node = byPublisher.get(report.publisherID);
      return node !== undefined && !suspended(node);
    }).length;
    const reportAges = hosts
      .map(({ reportedAt }) => Math.max(0, now - reportedAt))
      .sort((a, b) => a - b);
    return {
      hosts: hosts.length + 1,
      currentHosts: currentHosts + Number(!suspended(node)),
      tabs: peer.tabSnapshot(now, hosts).total,
      reportAgeP95: reportAges[Math.floor(reportAges.length * 0.95)] ?? 0,
      saturated: peer.saturated(now),
      knowsRenewal:
        installed ||
        hosts.some(
          ({ certificate }) => certificate?.fingerprint === renewedCertificate.fingerprint,
        ),
    };
  });
  const quantile = (field: "hosts" | "currentHosts" | "tabs" | "reportAgeP95", p: number) =>
    summaries.map((summary) => summary[field]).sort((a, b) => a - b)[
      Math.floor(summaries.length * p)
    ];
  console.log(
    JSON.stringify({
      stage,
      elapsedSeconds: (now - epoch) / 1000,
      liveHosts: population.length,
      activeTabs: tabs,
      observedHostsP10: quantile("hosts", 0.1),
      observedHostsP50: quantile("hosts", 0.5),
      currentHostsKnownP50: quantile("currentHosts", 0.5),
      observedTabsP10: quantile("tabs", 0.1),
      observedTabsP50: quantile("tabs", 0.5),
      reportAgeP95Ms: quantile("reportAgeP95", 0.5),
      saturatedViews: summaries.filter(({ saturated }) => saturated).length,
      viewsWithRenewedCertificate: summaries.filter(({ knowsRenewal }) => knowsRenewal).length,
      hostsWithRenewalInstalled: population.filter(({ installed }) => installed).length,
    }),
  );
  return quantile("hosts", 0.5) ?? 0;
}

for (let round = 0; round <= 200; round++) {
  now = epoch + round * tick;
  const separated = round < 30 || (round >= 60 && round < 90);
  const suspended = (node: Node) => round >= 70 && round < 105 && node.slot % 17 === 0;
  const dropRound = values["tab-drop"] ? 146 : Infinity;
  if (round === dropRound) {
    for (const node of nodes) node.tabs = Math.max(1, Math.floor(node.tabs / 5));
  }
  if (round === renewalRound) {
    const donor = nodes[1];
    assert(donor !== undefined);
    donor.installed = true;
    donor.peer.update({ certificate: renewedCertificate });
    if (values["field-latency"]) {
      follow(
        "certificate hint",
        round,
        (view, _, live) =>
          view.installed ||
          live.some(
            ({ certificate }) => certificate?.fingerprint === renewedCertificate.fingerprint,
          ),
        observers.filter((slot) => slot !== donor.slot),
      );
    }
  }
  if (round === 30 || round === 90) {
    // a few proxy discoveries reconnect the groups; they don't give a roster.
    for (let i = 0; i < 12; i++) {
      const a = nodes[i * 3];
      const b = nodes[partition + i * 3];
      if (a !== undefined && b !== undefined) {
        a.peer.receive(b.peer.message(now), now);
        b.peer.receive(a.peer.message(now), now);
      }
    }
  }
  if (values["proxy-sample"] && round !== 0) {
    // an optional edge view knows every 53rd slot, not the whole population.
    // each browser asks it once per 30 seconds, offset by the browser's slot.
    const visible = [0, 1].map((side) =>
      nodes.filter(
        (candidate) =>
          candidate.slot % 53 === 0 &&
          !suspended(candidate) &&
          (!separated || part(candidate) === side),
      ),
    );
    for (const node of nodes) {
      if (node.slot % 12 !== round % 12 || suspended(node)) continue;
      const aliases = visible[part(node)] ?? [];
      const donor = aliases[Math.floor(discoveryRandom() * aliases.length)];
      if (donor !== undefined) node.peer.receive(donor.peer.message(now), now);
    }
  }
  if (round >= 40 && round < 120) {
    for (let i = 0; i < Math.ceil(count / 250); i++) {
      const slot = Math.floor(churnRandom() * count);
      const old = nodes[slot];
      const witness = nodes[(slot + 1) % count];
      if (old === undefined || witness === undefined || suspended(old)) continue;
      if (!suspended(witness) && (!separated || part(old) === part(witness)))
        witness.peer.receive(old.peer.leave(now), now);
      byPublisher.delete(old.host.publisherID);
      nodes[slot] = create(slot);
      if (!suspended(witness) && (!separated || part(old) === part(witness))) {
        witness.peer.receive(nodes[slot].peer.message(now), now);
        nodes[slot].peer.receive(witness.peer.message(now), now);
      }
    }
  }
  if (values["field-latency"] && round === 125) {
    const outgoing = nodes[106];
    const witness = nodes[107];
    const pending = nodes[53];
    const finishing = nodes[159];
    const tally = nodes[212];
    assert(outgoing && witness && pending && finishing && tally);
    witness.peer.receive(outgoing.peer.leave(now), now);
    byPublisher.delete(outgoing.host.publisherID);
    const joining = create(outgoing.slot, witness.host);
    nodes[outgoing.slot] = joining;
    witness.peer.receive(joining.peer.message(now), now);
    joining.peer.receive(witness.peer.message(now), now);
    follow(
      "joined run and host details",
      round,
      (_, records) =>
        records.some(
          (report) =>
            report.runID === joining.host.runID &&
            report.origin === joining.host.origin &&
            report.publisherID === joining.host.publisherID &&
            report.runNumber === joining.host.runNumber &&
            report.endsAt === epoch + 125 * tick + HOST_TURN_MS &&
            report.name === "quiet-pine" &&
            report.copyFrom === witness.host.runID,
        ),
      observers.filter((slot) => slot !== joining.slot),
    );
    follow("explicit stop", round, (_, records) =>
      records.some((report) => report.runID === outgoing.host.runID && report.left),
    );
    const started = pending.peer.maybeStart(now, Infinity, () => true);
    assert(started);
    follow(
      "pending start before its expiry",
      round,
      (_, records) =>
        records.some((report) => report.runID === pending.host.runID && report.startingUntil > now),
      observers.filter((slot) => slot !== pending.slot),
    );
    finishing.peer.update({ departing: true });
    follow(
      "finishing turn",
      round,
      (_, records) =>
        records.some(
          (report) => report.runID === finishing.host.runID && report.departing === true,
        ),
      observers.filter((slot) => slot !== finishing.slot),
    );
    tally.tabs = 187;
    follow(
      "new tab count",
      round,
      (_, records) =>
        records.some((report) => report.runID === tally.host.runID && report.tabs?.count === 187),
      observers.filter((slot) => slot !== tally.slot),
    );
  }
  if (values["field-latency"] && (round === 70 || round === 105)) {
    // restrict the observers to hosts already holding the run's report at each boundary.
    // an unknown host can't provide evidence of either detecting or recovering it.
    const paused = nodes[0];
    assert(paused);
    const currentlyCounts = (live: readonly Change[]) =>
      live.some(({ runID }) => runID === paused.host.runID);
    const eligible = observers.filter((slot) => {
      const node = nodes[slot];
      if (node === undefined || suspended(node) || node === paused) return false;
      return round === 70
        ? currentlyCounts(node.peer.hosts(now))
        : node.peer.roster(now).some(({ runID }) => runID === paused.host.runID) &&
            !currentlyCounts(node.peer.hosts(now));
    });
    follow(
      round === 70 ? "suspended host no longer counted" : "resumed host counted again",
      round,
      (_, __, live) => (round === 70 ? !currentlyCounts(live) : currentlyCounts(live)),
      eligible,
    );
  }
  if (round >= renewalRound) {
    for (const node of nodes) {
      if (suspended(node)) continue;
      if (node.installed) {
        if (node.advertiseAt !== undefined && node.advertiseAt <= round) {
          node.peer.update({ certificate: renewedCertificate });
          delete node.advertiseAt;
        }
        continue;
      }
      if ((node.slot + seed) % certificateRounds !== round % certificateRounds) continue;
      const report = node.peer
        .hosts(now)
        .find(({ certificate }) => certificate?.fingerprint === renewedCertificate.fingerprint);
      if (report === undefined) continue;
      certificateAttempts++;
      const donor = byPublisher.get(report.publisherID);
      // model the mutual membership check and exact-alias proof, not TLS or issuance.
      if (
        donor === undefined ||
        !donor.installed ||
        suspended(donor) ||
        (separated && part(donor) !== part(node)) ||
        !donor.peer.hosts(now).some(({ runID }) => runID === node.host.runID)
      )
        continue;
      node.installed = true;
      node.advertiseAt = round + 1 + ((node.slot * 7 + seed) % certificateRounds);
      certificateTransfers++;
    }
    const installed = nodes.filter((node) => node.installed).length;
    if (installed >= count * 0.5) renewalP50Seconds ??= ((round - renewalRound) * tick) / 1_000;
    if (installed >= count * 0.9) renewalP90Seconds ??= ((round - renewalRound) * tick) / 1_000;
  }
  const delivery: (() => void)[][] = [[], [], [], [], [], [], [], []];
  let phase = 0;
  const clock = () => now + phase * 250;
  const sends = [];
  for (const sender of nodes) {
    if (suspended(sender)) continue;
    const initial =
      seed ^ Math.imul(sender.slot + 1, 0x85ebca6b) ^ Math.imul(round + 1, 0xc2b2ae35);
    const random = randomStream(initial);
    const linkRandom = randomStream(initial ^ 0x27d4eb2f);
    const leaseCount =
      round - dropRound < 16 && round >= dropRound
        ? 25 + (sender.slot % 51)
        : round - dropRound < 24 && round >= dropRound
          ? sender.tabs +
            Math.round(((25 + (sender.slot % 51) - sender.tabs) * (24 + dropRound - round)) / 8)
          : sender.tabs;
    sender.peer.observeTabs(leaseCount, now);
    const send: PeerTransport = (target, message, via) => {
      if (via === undefined) direct++;
      else indirect++;
      const recipient = byPublisher.get(target.publisherID);
      const helper = via === undefined ? undefined : byPublisher.get(via.publisherID);
      const canReach = (node: Node) =>
        !suspended(node) && (!separated || part(node) === part(sender));
      if (
        recipient === undefined ||
        !canReach(recipient) ||
        (via !== undefined && (helper === undefined || !canReach(helper))) ||
        linkRandom() < 0.02
      ) {
        dropped++;
        return Promise.resolve(undefined);
      }
      const at = phase + 1 + Math.floor(linkRandom() * 3);
      const queue = delivery[at];
      assert(queue !== undefined);
      return new Promise((resolve) => {
        queue.push(() => {
          recipient.peer.receive(message, clock());
          const reply = recipient.peer.message(clock(), message);
          if (sender.slot % 251 === 0) {
            const sent = new Map(
              [message.from, ...message.changes].map((report) => [report.runID, report.seq]),
            );
            sampledReplyRecords += reply.changes.length;
            sampledEchoes += reply.changes.filter(
              (report) => report.seq <= (sent.get(report.runID) ?? 0),
            ).length;
            for (const measured of [message, reply]) {
              const bytes = encoder.encode(JSON.stringify(measured)).byteLength;
              maxBytes = Math.max(maxBytes, bytes);
              assert(measured.changes.length <= MAX_CHANGES && bytes <= MAX_MESSAGE_BYTES);
              assert(parseMessage(measured, releaseID, clock()) !== undefined);
            }
          }
          resolve(reply);
        });
      });
    };
    sends.push(sender.peer.probe(clock, random, send));
  }
  for (phase = 1; phase < delivery.length; phase++) {
    for (const deliver of delivery[phase] ?? []) deliver();
    // continuations can schedule the one indirect probe in a later phase.
    await Promise.resolve();
    await Promise.resolve();
  }
  await Promise.all(sends);
  if (values["field-latency"]) {
    for (const slot of observers) {
      const node = nodes[slot];
      if (node === undefined || suspended(node)) continue;
      const pending = traces.filter(
        (trace) => trace.round <= round && trace.eligible.has(slot) && !trace.seen.has(slot),
      );
      if (pending.length === 0) continue;
      const records = node.peer.roster(now);
      const live = node.peer.hosts(now);
      for (const trace of pending) {
        if (trace.expected(node, records, live))
          trace.seen.set(slot, ((round - trace.round) * tick) / 1_000);
      }
    }
  }
  if (
    [15, 29, 50, 89, 106, 125, 160, 200].includes(round) ||
    (values["tab-drop"] && [146, 170, 182].includes(round))
  ) {
    const observed = observe(
      {
        15: "isolated",
        29: "isolated before join",
        50: "joined and churning",
        89: "partition with suspension",
        106: "after partition and suspension",
        125: "after churn",
        146: "tab drop",
        160: "400 seconds",
        170: "60 seconds after tab drop",
        182: "90 seconds after tab drop",
        200: "500 seconds",
      }[round] ?? "",
      suspended,
    );
    if (round === 29)
      assert(observed <= count / 2 + 1, "A partition should not see the other group.");
  }
}
assert(maxRecords <= MAX_PEERS);
timingSummary();
console.log(
  JSON.stringify({
    seed,
    count,
    proxySample: values["proxy-sample"] ?? false,
    tabDrop: values["tab-drop"] ?? false,
    serviceRuns: nextHost,
    direct,
    indirect,
    dropped,
    maxBytes,
    maxRecords,
    sampledEchoes,
    sampledReplyRecords,
    certificateAttempts,
    certificateTransfers,
    renewalP50Seconds: renewalP50Seconds ?? null,
    renewalP90Seconds: renewalP90Seconds ?? null,
  }),
);
