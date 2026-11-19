import { describe, expect, it } from "vitest";
import { STARTUP_MS } from "../src/policy.ts";
import {
  Gossip,
  HOST_PARENT,
  KEEP_MS,
  MAX_CHANGES,
  MAX_MESSAGE_BYTES,
  MAX_PEERS,
  QUIET_MS,
  SUSPECT_MS,
  parseMessage,
  type GossipMessage,
  type Host,
  type PeerTransport,
} from "../src/peers/gossip.ts";

const epoch = Date.UTC(2026, 10, 18);
const release = "a".repeat(64);

function host(n: number, run = n): Host {
  const label = run.toString(2).replaceAll("0", "a").replaceAll("1", "b").padStart(26, "a");
  return {
    origin: `https://p-${label}.${HOST_PARENT}`,
    publisherID: "pub_" + String(n).padStart(22, "0"),
    runID: "srun_" + String(run).padStart(22, "0"),
    runNumber: String(run),
  };
}

function network() {
  let now = epoch;
  let seed = 17;
  const nodes = new Map<string, Gossip>();
  const blocked = new Set<string>();
  const transfers: string[] = [];
  const clock = () => now;
  const random = () => {
    seed = (1664525 * seed + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };
  const create = (id: number, run = id) => {
    const identity = host(id, run);
    const gossip = new Gossip(release, identity, now);
    nodes.set(identity.publisherID, gossip);
    return gossip;
  };
  const send: PeerTransport = async (target, message, via) => {
    transfers.push(via === undefined ? "direct" : "indirect");
    if (blocked.has(target.publisherID) || (via !== undefined && blocked.has(via.publisherID))) {
      return;
    }
    const recipient = nodes.get(target.publisherID);
    recipient?.receive(message, now);
    return recipient?.message(now);
  };
  return {
    create,
    clock,
    random,
    send,
    blocked,
    transfers,
    advance: (ms: number) => {
      now += ms;
    },
    exchange(a: Gossip, b: Gossip) {
      a.receive(b.message(now), now);
      b.receive(a.message(now), now);
    },
    probe: (a: Gossip) => a.probe(clock, random, send),
  };
}

describe("gossip", () => {
  it("repairs a split and carries the earliest known start to every host", async () => {
    const net = network();
    const a = net.create(1);
    const b = net.create(2);
    net.exchange(a, b);
    net.advance(5_000);
    const c = net.create(3);
    const d = net.create(4);
    net.exchange(c, d);
    expect(d.startedAt).toBe(epoch + 5_000);
    expect(a.hosts(net.clock())).toHaveLength(1);
    net.exchange(b, c);
    for (let i = 0; i < 12; i++) {
      net.advance(2_000);
      for (const peer of [a, b, c, d]) await net.probe(peer);
    }
    for (const peer of [a, b, c, d]) {
      expect(peer.startedAt).toBe(epoch);
      expect(peer.hosts(net.clock())).toHaveLength(3);
    }
  });

  it("uses a second path when direct probes fail and recovers after suspension", async () => {
    const net = network();
    const a = net.create(1);
    const b = net.create(2);
    const c = net.create(3);
    net.exchange(a, b);
    net.exchange(a, c);
    const directFails: PeerTransport = (target, message, via) =>
      via === undefined ? Promise.resolve(undefined) : net.send(target, message, via);
    await a.probe(net.clock, () => 0, directFails);
    expect(net.transfers).toEqual(["indirect"]);
    net.blocked.add(host(2).publisherID);
    await a.probe(net.clock, () => 0, net.send);
    expect(a.hosts(net.clock())).toHaveLength(2);
    net.advance(SUSPECT_MS);
    expect(a.hosts(net.clock()).map((peer) => peer.runID)).toEqual([host(3).runID]);
    net.blocked.clear();
    await a.probe(net.clock, () => 0, net.send);
    expect(a.hosts(net.clock())).toHaveLength(2);
  });

  it("ignores delayed reports from an old run, and preserves a departure", () => {
    const net = network();
    const a = net.create(1);
    const b = net.create(2);
    const old = b.message(net.clock());
    a.receive(old, net.clock());
    a.receive(b.leave(net.clock()), net.clock());
    a.receive(old, net.clock());
    expect(a.hosts(net.clock())).toEqual([]);
    const restartedHost = { ...host(2, 12), origin: host(2).origin };
    const restarted = new Gossip(release, restartedHost, net.clock());
    a.receive(restarted.message(net.clock()), net.clock());
    a.receive(old, net.clock());
    expect(a.hosts(net.clock()).map((peer) => peer.runID)).toEqual([restartedHost.runID]);
  });

  it("holds one local start, honors a peer's start, and retries after an abandoned start", () => {
    const net = network();
    const a = net.create(1);
    const b = net.create(2);
    net.exchange(a, b);
    expect(a.maybeStart(net.clock(), 3, () => true)).toBe(true);
    expect(a.maybeStart(net.clock(), 3, () => true)).toBe(false);
    net.exchange(a, b);
    expect(b.maybeStart(net.clock(), 3, () => true)).toBe(false);
    for (let i = 0; i < Math.ceil(STARTUP_MS / 10_000); i++) {
      net.advance(10_000);
      net.exchange(a, b);
    }
    expect(b.maybeStart(net.clock(), 3, () => true)).toBe(true);
    b.finishStart();
    expect(b.maybeStart(net.clock(), 3, () => true)).toBe(false);
  });

  it("bounds its memory and each exchange, and forgets quiet hosts", () => {
    const net = network();
    const a = net.create(1);
    for (let i = 2; i <= 10_000; i++) {
      const message: GossipMessage = {
        releaseID: release,
        startedAt: epoch,
        changes: [],
        from: { ...host(i), seq: 1, left: false, startingUntil: 0 },
      };
      a.receive(message, net.clock());
    }
    expect(a.size).toBe(MAX_PEERS);
    const first = a.message(net.clock());
    expect(first.changes).toHaveLength(MAX_CHANGES);
    expect(a.message(net.clock()).changes).not.toEqual(first.changes);
    expect(new TextEncoder().encode(JSON.stringify(first)).byteLength).toBeLessThan(
      MAX_MESSAGE_BYTES,
    );
    net.advance(QUIET_MS);
    expect(a.hosts(net.clock())).toHaveLength(0);
    net.advance(KEEP_MS);
    expect(a.message(net.clock()).changes).toEqual([]);
  });

  it("ignores unrelated releases, unsafe addresses, bad clocks and oversized messages", () => {
    const a = new Gossip(release, host(1), epoch);
    const message = a.message(epoch);
    expect(parseMessage(message, release, epoch)).toEqual(message);
    expect(parseMessage(message, "b".repeat(64), epoch)).toBeUndefined();
    expect(parseMessage({ ...message, startedAt: epoch + 60_000 }, release, epoch)).toBeUndefined();
    expect(
      parseMessage(
        { ...message, from: { ...message.from, origin: "https://other.test" } },
        release,
        epoch,
      ),
    ).toBeUndefined();
    expect(
      parseMessage(
        { ...message, changes: Array(MAX_CHANGES + 1).fill(message.from) },
        release,
        epoch,
      ),
    ).toBeUndefined();
  });
});
