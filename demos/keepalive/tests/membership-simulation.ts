import assert from "node:assert/strict";
import { parseArgs } from "node:util";
import {
  Gossip,
  HOST_PARENT,
  MAX_CHANGES,
  MAX_MESSAGE_BYTES,
  MAX_PEERS,
  parseMessage,
  type Host,
  type PeerTransport,
} from "../src/peers/gossip.ts";
import { HOST_TURN_MS } from "../src/policy.ts";

const { values } = parseArgs({
  options: { hosts: { type: "string", default: "5000" }, "proxy-sample": { type: "boolean" } },
});
const count = Number(values.hosts);
assert(Number.isInteger(count) && count >= 100 && count <= 5_000, "Pass --hosts 100 through 5000.");
const partition = Math.floor(count / 2);
const releaseID = "a".repeat(64);
const tick = 2_500;
const epoch = Date.UTC(2026, 10, 19);
const oldCertificate = { fingerprint: "b".repeat(64), expiresAt: epoch + 24 * 60 * 60_000 };
const renewedCertificate = {
  fingerprint: "c".repeat(64),
  expiresAt: epoch + 90 * 24 * 60 * 60_000,
};
let now = epoch;
let randomState = 17;
let nextHost = 0;
let direct = 0;
let indirect = 0;
let dropped = 0;
let maxBytes = 0;
let maxRecords = 0;
const byPublisher = new Map<string, Node>();
const encoder = new TextEncoder();
const random = () => {
  randomState = (1664525 * randomState + 1013904223) >>> 0;
  return randomState / 2 ** 32;
};
type Node = { slot: number; peer: Gossip; host: Host; tabs: number };
function create(slot: number): Node {
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
  });
  const node = { slot, host, peer, tabs: 25 + (slot % 51) };
  byPublisher.set(host.publisherID, node);
  return node;
}
const nodes = Array.from({ length: count }, (_, i) => create(i));
const part = (node: Node) => Number(node.slot >= partition);
const sample = (offset: number, cap: number) => {
  const step = Math.max(1, Math.floor(count / cap));
  return nodes.filter(({ slot }) => (slot + offset) % step === 0).slice(0, cap);
};

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
  const summaries = sample(0, 50).map(({ peer }) => {
    maxRecords = Math.max(maxRecords, peer.size);
    const hosts = peer.hosts(now);
    const reportAges = hosts
      .map(({ reportedAt }) => Math.max(0, now - reportedAt))
      .sort((a, b) => a - b);
    return {
      hosts: hosts.length + 1,
      tabs: peer.tabSnapshot(now, hosts).total,
      reportAgeP95: reportAges[Math.floor(reportAges.length * 0.95)] ?? 0,
      saturated: peer.saturated(now),
      knowsRenewal: hosts.some(
        ({ certificate }) => certificate?.fingerprint === renewedCertificate.fingerprint,
      ),
    };
  });
  const quantile = (field: "hosts" | "tabs" | "reportAgeP95", p: number) =>
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
      observedTabsP10: quantile("tabs", 0.1),
      observedTabsP50: quantile("tabs", 0.5),
      reportAgeP95Ms: quantile("reportAgeP95", 0.5),
      saturatedViews: summaries.filter(({ saturated }) => saturated).length,
      viewsWithRenewedCertificate: summaries.filter(({ knowsRenewal }) => knowsRenewal).length,
    }),
  );
  return quantile("hosts", 0.5) ?? 0;
}

for (let round = 0; round <= 160; round++) {
  now = epoch + round * tick;
  const separated = round < 30 || (round >= 60 && round < 90);
  const suspended = (node: Node) => round >= 70 && round < 105 && node.slot % 17 === 0;
  if (round === 121) nodes[1]?.peer.update({ certificate: renewedCertificate });
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
      const donor = aliases[Math.floor(random() * aliases.length)];
      if (donor !== undefined) node.peer.receive(donor.peer.message(now), now);
    }
  }
  if (round >= 40 && round < 120) {
    for (let i = 0; i < Math.ceil(count / 250); i++) {
      const slot = Math.floor(random() * count);
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
  const delivery: (() => void)[][] = [[], [], [], [], [], [], [], []];
  let phase = 0;
  const clock = () => now + phase * 250;
  const sends = [];
  for (const sender of nodes) {
    if (suspended(sender)) continue;
    sender.peer.observeTabs(sender.tabs, now);
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
        random() < 0.02
      ) {
        dropped++;
        return Promise.resolve(undefined);
      }
      const at = phase + 1 + Math.floor(random() * 3);
      const queue = delivery[at];
      assert(queue !== undefined);
      return new Promise((resolve) => {
        queue.push(() => {
          recipient.peer.receive(message, clock());
          resolve(recipient.peer.message(clock()));
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
  for (const { peer } of sample(round, 16)) {
    const message = peer.message(clock());
    const bytes = encoder.encode(JSON.stringify(message)).byteLength;
    maxBytes = Math.max(maxBytes, bytes);
    assert(message.changes.length <= MAX_CHANGES && bytes <= MAX_MESSAGE_BYTES);
    assert(parseMessage(message, releaseID, clock()) !== undefined);
  }
  if ([15, 29, 50, 89, 106, 125, 160].includes(round)) {
    const observed = observe(
      {
        15: "isolated",
        29: "isolated before join",
        50: "joined and churning",
        89: "partition with suspension",
        106: "after partition and suspension",
        125: "after churn",
        160: "settled",
      }[round] ?? "",
      suspended,
    );
    if (round === 29)
      assert(observed <= count / 2 + 1, "A partition should not see the other group.");
  }
}
assert(maxRecords <= MAX_PEERS);
console.log(
  JSON.stringify({
    seed: 17,
    count,
    proxySample: values["proxy-sample"] ?? false,
    serviceRuns: nextHost,
    direct,
    indirect,
    dropped,
    maxBytes,
    maxRecords,
  }),
);
