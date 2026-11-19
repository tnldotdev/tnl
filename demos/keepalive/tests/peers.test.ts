import { describe, expect, it, vi } from "vitest";
import { STARTUP_MS } from "../src/policy.ts";
import {
  Gossip,
  HOST_PARENT,
  KEEP_MS,
  MAX_CHANGES,
  MAX_MESSAGE_BYTES,
  MAX_PEERS,
  PEERS_PATH,
  SUSPECT_MS,
  parseMessage,
  type Change,
  type GossipMessage,
  type Host,
  type PeerTransport,
} from "../src/peers/gossip.ts";
import { peerServer } from "../src/peers/http.ts";
import { REMOTE_TAB_REPORT_MS } from "../src/peers/presence.ts";

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

function report(n: number, details: Partial<Change> = {}): Change {
  return {
    ...host(n),
    seq: 1,
    reportedAt: epoch,
    left: false,
    startingUntil: 0,
    ...details,
  };
}

function message(from: Change, ...changes: Change[]): GossipMessage {
  return { releaseID: release, startedAt: epoch, from, changes };
}

function certificate(fingerprint: string, expiresAt = epoch + 60_000) {
  return { fingerprint: fingerprint.repeat(64), expiresAt };
}

function fillRoster(view: Gossip, count: number, first = 2) {
  for (let i = first; i < first + count; i++) view.receive(message(report(i)), epoch);
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
    return recipient?.message(now, message);
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
  it("fits full reports and an indirect check inside the wire budget", () => {
    const max = Number.MAX_SAFE_INTEGER;
    const full = (n: number) =>
      report(n, {
        seq: max,
        reportedAt: max,
        runNumber: "9223372036854775807",
        name: "silver-stone",
        startingUntil: max,
        endsAt: max,
        departing: false,
        tabs: { count: 512, observedAt: max },
        copyFrom: host(1).runID,
        certificate: certificate("f", max),
      });
    const view = new Gossip(release, host(1), max, full(1));
    for (let i = 2; i < MAX_CHANGES + 2; i++) view.receive(message(full(i)), max);
    const batch = view.message(max);
    expect(batch.changes).toHaveLength(MAX_CHANGES);
    const bytes = new TextEncoder().encode(JSON.stringify({ target: host(2), message: batch }));
    expect(bytes.byteLength).toBeLessThanOrEqual(MAX_MESSAGE_BYTES);
  });

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

  it("keeps room for 5,000 active hosts plus churn and reclaims expired records", () => {
    const net = network();
    const a = net.create(1);
    const report = (i: number, stopped = false): GossipMessage => ({
      releaseID: release,
      startedAt: epoch,
      changes: [],
      from: { ...host(i), seq: 1, reportedAt: net.clock(), left: stopped, startingUntil: 0 },
    });
    const active = 4_999;
    const stopped = MAX_PEERS - active;
    for (let i = 2; i < 2 + stopped; i++) a.receive(report(i, true), net.clock());
    net.advance(60_000);
    for (let i = 2 + stopped; i < 2 + MAX_PEERS; i++) a.receive(report(i), net.clock());
    expect(a.size).toBe(MAX_PEERS);
    expect(a.hosts(net.clock())).toHaveLength(active);
    expect(a.saturated(net.clock())).toBe(false);
    a.receive(report(2 + MAX_PEERS), net.clock());
    expect(a.saturated(net.clock())).toBe(true);
    const first = a.message(net.clock());
    expect(first.changes).toHaveLength(MAX_CHANGES);
    expect(a.message(net.clock()).changes).not.toEqual(first.changes);
    expect(new TextEncoder().encode(JSON.stringify(first)).byteLength).toBeLessThan(
      MAX_MESSAGE_BYTES,
    );
    net.advance(KEEP_MS - 60_000);
    expect(a.hosts(net.clock())).toHaveLength(active);
    a.receive(report(2 + MAX_PEERS), net.clock());
    expect(a.size).toBe(active + 1);
    net.advance(KEEP_MS);
    expect(a.message(net.clock()).changes).toEqual([]);
    expect(a.saturated(net.clock())).toBe(false);
  });

  it("uses fresh forwarded reports without mistaking a minute without contact for departure", () => {
    const net = network();
    const a = net.create(1);
    const b = net.create(2);
    const c = net.create(3);
    net.exchange(a, b);
    net.exchange(b, c);
    net.advance(61_000);
    expect(a.hosts(net.clock())).toEqual([expect.objectContaining({ runID: host(2).runID })]);
    net.exchange(b, c);
    const forwarded = b.message(net.clock());
    a.receive(forwarded, net.clock());
    net.advance(KEEP_MS - 1);
    a.receive(forwarded, net.clock());
    expect(a.hosts(net.clock())).toHaveLength(2);
    net.advance(1);
    a.receive(forwarded, net.clock());
    expect(a.hosts(net.clock())).toHaveLength(0);
  });

  it("shares recent tab reports while keeping space for ordinary rotation", () => {
    const net = network();
    const observer = net.create(1);
    const peers = Array.from({ length: MAX_CHANGES * 7 }, (_, i) => net.create(i + 2));
    for (const peer of peers) observer.receive(peer.message(net.clock()), net.clock());
    for (let i = 0; i < peers.length; i++) observer.message(net.clock());
    net.advance(10_000);
    const fresh = peers.slice(-24);
    for (const peer of fresh) {
      peer.observeTabs(54, net.clock());
      observer.receive(peer.message(net.clock()), net.clock());
    }
    const first = observer.message(net.clock());
    expect(first.changes.filter(({ tabs }) => tabs?.count === 54).length).toBeGreaterThanOrEqual(8);
    expect(first.changes.some(({ tabs }) => tabs === undefined)).toBe(true);
    const repeated = new Set(first.changes.map(({ publisherID }) => publisherID));
    expect(repeated.size).toBe(MAX_CHANGES);
  });

  it("counts remote observations once without giving relayed observations a new deadline", () => {
    const view = new Gossip(release, host(1), epoch);
    const remote = report(2, { tabs: { count: 4, observedAt: epoch } });
    const duplicatePublisher = { ...remote, origin: host(3).origin };
    const duplicateOrigin = { ...remote, publisherID: host(4).publisherID };
    view.observeTabs(2, epoch);
    expect(view.tabSnapshot(epoch, [remote, duplicatePublisher, duplicateOrigin])).toEqual({
      local: 2,
      total: 6,
    });

    view.receive(message(remote), epoch);
    const beforeExpiry = epoch + REMOTE_TAB_REPORT_MS - 1;
    const relayed = { ...remote, seq: 2, reportedAt: beforeExpiry };
    view.receive(message(report(3, { reportedAt: beforeExpiry }), relayed), beforeExpiry);
    expect(view.tabSnapshot(beforeExpiry)).toEqual({ local: 0, total: 4 });
    view.receive(
      message(report(3, { seq: 2, reportedAt: beforeExpiry + 1 }), relayed),
      beforeExpiry + 1,
    );
    expect(view.tabSnapshot(beforeExpiry + 1)).toEqual({ local: 0, total: 0 });
  });

  it("puts a new stop ahead of repeats, with fewer sends first and newest first within a tier", () => {
    const view = new Gossip(release, host(1), epoch);
    fillRoster(view, 8);
    expect(view.message(epoch).changes[0]).toEqual(report(9));
    view.receive(message(report(10)), epoch);
    expect(view.message(epoch).changes[0]).toEqual(report(10));

    const stop = report(9, { seq: 2, left: true });
    view.receive(message(stop), epoch);
    const tally = report(10, { seq: 2, tabs: { count: 3, observedAt: epoch } });
    view.receive(message(tally), epoch);
    const batch = view.message(epoch).changes;
    expect(batch.slice(0, 4)).toEqual([stop, tally, report(2), report(8)]);
    expect(batch.filter(({ publisherID }) => publisherID === stop.publisherID)).toEqual([stop]);
  });

  it("does not reset a stop's three priority sends on duplicate or older reports", () => {
    const view = new Gossip(release, host(1), epoch);
    const first = report(3);
    const second = report(4);
    view.receive(message(first, second), epoch);
    for (let i = 0; i < 3; i++) view.message(epoch);

    const stop = report(2, { seq: 2, left: true });
    view.receive(message(stop), epoch);
    for (let i = 0; i < 3; i++) {
      view.receive(message(first, report(2), stop), epoch);
      // move ordinary rotation to the second report without using a stop retry.
      expect(view.message(epoch, message(stop, second)).changes).toEqual([first]);
      expect(view.message(epoch).changes[0]).toEqual(stop);
    }
    view.receive(message(first, stop, report(2)), epoch);
    expect(view.message(epoch, message(stop, second)).changes).toEqual([first]);
    expect(view.message(epoch).changes).toEqual([second, stop, first]);
  });

  it("reserves one ordinary slot for the best certificate by expiry then fingerprint", () => {
    const view = new Gossip(release, host(1), epoch, { certificate: certificate("f") });
    fillRoster(view, MAX_CHANGES * 3);
    const earlierExpiry = report(9_000, { certificate: certificate("0", epoch + 59_000) });
    const tieLoser = report(9_001, { certificate: certificate("e") });
    const best = report(9_002, { certificate: certificate("d") });
    view.receive(message(earlierExpiry, tieLoser, best), epoch);
    fillRoster(view, MAX_CHANGES, 300);
    const batch = view.message(epoch).changes;
    expect(batch).toHaveLength(MAX_CHANGES);
    expect(new Set(batch.map(({ publisherID }) => publisherID)).size).toBe(MAX_CHANGES);
    expect(batch.filter((peer) => peer.certificate !== undefined)).toEqual([best]);

    const refreshed = { ...best, seq: 2, reportedAt: epoch + 1 };
    view.receive(message(refreshed), epoch + 1);
    view.message(epoch + 1); // sends the refresh from the fresh queue
    expect(
      view.message(epoch + 2).changes.filter((peer) => peer.certificate !== undefined),
    ).toEqual([refreshed]);
  });

  it("uses ordinary slots when self wins, or the best peer is already selected or known", () => {
    const best = report(2, { certificate: certificate("a") });
    const selected = new Gossip(release, host(1), epoch);
    fillRoster(selected, MAX_CHANGES, 3);
    selected.receive(message(best), epoch);
    const batch = selected.message(epoch).changes;
    expect(batch).toHaveLength(MAX_CHANGES);
    expect(batch.filter((peer) => peer.certificate !== undefined)).toEqual([best]);
    expect(new Set(batch.map(({ publisherID }) => publisherID)).size).toBe(MAX_CHANGES);

    const view = new Gossip(release, host(1), epoch, { certificate: certificate("a") });
    fillRoster(view, MAX_CHANGES * 3, 3);
    view.receive(message(best), epoch);
    fillRoster(view, MAX_CHANGES, 300);
    const selfWins = view.message(epoch);
    expect(selfWins.from.certificate).toEqual(best.certificate);
    expect(selfWins.changes).toHaveLength(MAX_CHANGES);
    expect(selfWins.changes).not.toContain(best);

    view.update({ certificate: certificate("b") });
    const requesterKnowsBest = view.message(epoch, message(best));
    expect(requesterKnowsBest.changes).toHaveLength(MAX_CHANGES);
    expect(requesterKnowsBest.changes).not.toContain(best);
    expect(view.message(epoch).changes).toContain(best);
  });

  it("reselects the certificate holder after suspicion grace, recovery, and expiration", async () => {
    const view = new Gossip(release, host(1), epoch);
    const ordinary = MAX_CHANGES * 6;
    fillRoster(view, ordinary);
    const suspect = report(9_000, { certificate: certificate("a", epoch + 20_000) });
    const fallback = report(9_001, { certificate: certificate("b", epoch + 19_000) });
    const ended = report(9_002, {
      certificate: certificate("c", epoch + 30_000),
      endsAt: epoch + 1,
    });
    const stopped = report(9_003, { certificate: certificate("d"), left: true });
    view.receive(message(suspect, fallback, ended, stopped), epoch);
    fillRoster(view, MAX_CHANGES * 2, 300);

    await view.probe(
      () => epoch + 1,
      () => (ordinary + 0.5) / view.size,
      async () => undefined,
    );
    const advertised = (now: number) =>
      view.message(now).changes.filter((peer) => peer.certificate !== undefined);
    expect(advertised(epoch + SUSPECT_MS)).toEqual([suspect]);
    expect(advertised(epoch + SUSPECT_MS + 1)).toEqual([fallback]);
    view.receive(message(suspect), epoch + SUSPECT_MS + 1);
    expect(advertised(epoch + SUSPECT_MS + 1)).toEqual([suspect]);
    expect(advertised(epoch + 20_000)).toEqual([]);
  });

  it("suppresses only same-or-older reports for exact runs and keeps the sender report", () => {
    const view = new Gossip(release, host(1), epoch);
    const known = report(2, { seq: 5 });
    const newer = report(3, { seq: 2, left: true });
    const older = report(4);
    const otherRun = report(5);
    view.receive(message(known, newer, older, otherRun), epoch);

    const request = message(
      known,
      { ...known, seq: 1 },
      { ...newer, seq: 1, left: false },
      { ...older, seq: 4 },
      { ...otherRun, ...host(5, 6) },
      report(1, { seq: 100 }),
    );
    const reply = view.message(epoch, request);
    expect(reply.from).toEqual(report(1, { seq: 2 }));
    expect(reply.changes).toEqual([otherRun, newer]);
  });

  it("fills filtered batches without consuming priority retries for suppressed reports", () => {
    const view = new Gossip(release, host(1), epoch);
    const initial = message(report(2));
    view.receive(initial, epoch);
    expect(view.message(epoch, initial).changes).toEqual([]);
    fillRoster(view, MAX_CHANGES * 6, 3);
    const known = report(2, { seq: 2, left: true });
    const request = message(known);
    view.receive(request, epoch);
    for (let i = 0; i < 4; i++) {
      const reply = view.message(epoch, request);
      expect(reply.changes).toHaveLength(MAX_CHANGES);
      expect(reply.changes).not.toContain(known);
    }
    expect(view.message(epoch).changes[0]).toEqual(known);
  });

  it("filters echoed reports from HTTP POST replies", async () => {
    const lifetime = new AbortController();
    const local = host(1);
    const page = "https://keepthisalive.com";
    const peer = peerServer(release, [page], async () => new Response(), lifetime.signal, {
      proxyOrigin: page,
      proof: "",
    });
    vi.stubGlobal("fetch", async () => new Response(null, { status: 503 }));
    try {
      const now = Date.now();
      await peer.start(
        local,
        now,
        undefined,
        undefined,
        () => {},
        () => false,
      );
      const post = (request: GossipMessage) =>
        peer.fetch(
          new Request(new URL(PEERS_PATH, local.origin), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ...request, startedAt: now }),
          }),
        );
      const sender = report(2, { reportedAt: now });
      const newest = report(3, { seq: 2, reportedAt: now });
      const known = report(4, { reportedAt: now });
      const first = await post(message(sender, newest, known));
      expect(first.status).toBe(200);
      expect(parseMessage(await first.json(), release, now)?.changes).toEqual([]);

      const reply = await post(message(sender, { ...newest, seq: 1 }, known));
      expect(reply.status).toBe(200);
      expect(parseMessage(await reply.json(), release, now)).toMatchObject({
        from: local,
        changes: [newest],
      });
    } finally {
      lifetime.abort();
      await peer.stop();
      vi.unstubAllGlobals();
    }
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
