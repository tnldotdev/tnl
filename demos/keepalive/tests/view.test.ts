import { expect, it, vi } from "vitest";
import {
  Gossip,
  HOST_PARENT,
  MAX_CHANGES,
  PEERS_PATH,
  SUSPECT_MS,
  parseMessage,
  type Host,
  type HostHistory,
} from "../src/peers/gossip.ts";
import { hostBranches, visibleBranches, type Branch } from "../src/page/host-tree.ts";
import { peerServer } from "../src/peers/http.ts";
import { PRESENCE_PATH } from "../src/peers/presence.ts";
import {
  MAX_TREE_HOSTS,
  TREE_PATH,
  presenceSummary,
  treeHost,
  treeSample,
} from "../src/peers/view.ts";
import * as z from "zod";

const pageOrigin = "https://keepthisalive.com";
const release = "a".repeat(64);
function host(n: number): Host {
  return {
    origin: `https://p-${n.toString(2).replaceAll("0", "a").replaceAll("1", "b").padStart(26, "a")}.${HOST_PARENT}`,
    publisherID: `pub_${String(n).padStart(22, "0")}`,
    runID: `srun_${String(n).padStart(22, "0")}`,
    runNumber: String(n),
  };
}

it("retains an unreachable donor and archives a former run without counting it", async () => {
  const now = Date.now();
  const seed = new Gossip(release, host(1), now, { endsAt: now + 60_000 });
  const relay = new Gossip(release, host(2), now, { copyFrom: seed.self.runID });
  relay.receive(seed.message(now), now);
  await relay.probe(
    () => now,
    () => 0,
    async () => undefined,
  );
  expect(relay.presenceView(now + SUSPECT_MS).hosts).toBe(1);
  expect(relay.hostHistory(now + SUSPECT_MS)).toContainEqual(
    expect.objectContaining({ runID: seed.self.runID, unreachable: true, left: false }),
  );
  const restart = new Gossip(release, { ...seed.self, runID: host(3).runID, runNumber: "3" }, now);
  relay.receive(restart.message(now + SUSPECT_MS), now + SUSPECT_MS);
  expect(relay.hostHistory(now + SUSPECT_MS)).toContainEqual(
    expect.objectContaining({ runID: seed.self.runID, left: true }),
  );
  expect(relay.message(now + SUSPECT_MS).changes.map(({ runID }) => runID)).not.toContain(
    seed.self.runID,
  );
  const later = now + 10 * 60_000;
  expect(relay.presenceView(later).hosts).toBe(1);
  expect(relay.hostHistory(later)).toHaveLength(3);
});

it("shows the ancestry and children of the current host; expanding adds rows in place", () => {
  const entry = (id: number, previous?: number): HostHistory => ({
    runID: host(id).runID,
    copyFrom: previous === undefined ? undefined : host(previous).runID,
    left: id === 1,
  });
  const history = [
    ...Array.from({ length: 105 }, (_, i) => entry(i + 100)),
    ...Array.from({ length: 17 }, (_, i) => entry(i + 1, i || undefined)),
    entry(18, 17),
    entry(19, 17),
    entry(20, 18),
  ];
  const focus = host(17).runID;
  const sample = treeSample(history, focus);
  expect(sample).toHaveLength(MAX_TREE_HOSTS);
  const roots = hostBranches(sample, focus);
  expect(roots[0]?.host.runID).toBe(host(1).runID);
  const first = visibleBranches(roots, focus, 16);
  const flatten = (branches: readonly Branch[]): string[] =>
    branches.flatMap(({ host, children }) => [host.runID, ...flatten(children)]);
  expect(flatten(first.branches)).toEqual(Array.from({ length: 19 }, (_, i) => host(i + 1).runID));
  expect(first.more).toBe(true);
  const full = visibleBranches(roots, focus, MAX_TREE_HOSTS);
  expect(full.more).toBe(false);
  expect(flatten(full.branches).slice(0, 20)).toEqual([
    ...Array.from({ length: 18 }, (_, i) => host(i + 1).runID),
    host(20).runID,
    host(19).runID,
  ]);
  expect(new Set(flatten(full.branches)).size).toBe(MAX_TREE_HOSTS);
});

it("breaks cycles and keeps branches whose earlier host is missing", () => {
  const a = { runID: host(1).runID, left: false, copyFrom: host(2).runID };
  const b = { runID: host(2).runID, left: false, copyFrom: host(1).runID };
  const c = { runID: host(3).runID, left: false, copyFrom: host(99).runID };
  const branches = hostBranches([a, b, c], a.runID);
  expect(branches).toEqual([
    { host: b, children: [{ host: a, children: [] }] },
    { host: c, children: [] },
  ]);
});

it("counts more hosts than fit in gossip without sending the roster to the visitor", async () => {
  const lifetime = new AbortController();
  const now = Date.now();
  const local = host(1);
  const remoteCount = MAX_TREE_HOSTS + 5;
  const peer = peerServer(release, [pageOrigin], async () => new Response(), lifetime.signal);
  vi.stubGlobal("fetch", async () => new Response(null, { status: 503 }));
  try {
    await peer.start(
      local,
      now,
      undefined,
      undefined,
      (view) => {
        for (let i = 2; i < 2 + remoteCount; i++) {
          const remote = new Gossip(release, host(i), now, { endsAt: now + 5_000 });
          remote.observeTabs(5, now);
          view.receive(remote.message(now), now);
        }
        expect(view.message(now).changes).toHaveLength(MAX_CHANGES);
      },
      () => false,
    );
    const reply = await peer.fetch(
      new Request(new URL(PRESENCE_PATH, local.origin), {
        method: "POST",
        headers: { Origin: pageOrigin },
        body: JSON.stringify({ tab: crypto.randomUUID(), releaseID: release }),
      }),
    );
    const summary = presenceSummary.parse(await reply.json());
    expect(summary).toMatchObject({
      host: local,
      tabs: 1 + 5 * remoteCount,
      hosts: 1 + remoteCount,
    });
    expect(summary.fallback).toHaveLength(3);
    expect(new Set(summary.fallback.map(({ origin }) => origin)).size).toBe(3);
    const tree = await peer.fetch(new Request(new URL(TREE_PATH, local.origin)));
    const sample = z
      .object({ hostRunID: z.string(), hosts: z.array(treeHost) })
      .parse(await tree.json());
    expect(sample.hostRunID).toBe(local.runID);
    expect(sample.hosts.map(({ runID }) => runID)).toContain(local.runID);
    expect(sample.hosts).toHaveLength(MAX_TREE_HOSTS);
  } finally {
    lifetime.abort();
    await peer.stop();
    vi.unstubAllGlobals();
  }
});

it("carries a joined service run and its stop through two HTTP peers", async () => {
  const lifetime = new AbortController();
  const now = Date.now();
  const observer = host(1);
  const bridge = host(2);
  const joining = host(3);
  const details = { name: "quiet-pine", copyFrom: bridge.runID, endsAt: now + 60_000 };
  const peers = new Map(
    [observer, bridge, joining].map(({ origin }) => [
      origin,
      peerServer(release, [pageOrigin], async () => new Response(), lifetime.signal),
    ]),
  );
  const send = async (to: Host, batch?: unknown) => {
    const peer = peers.get(to.origin);
    if (peer === undefined) throw new Error("missing peer");
    const reply = await peer.fetch(
      new Request(
        new URL(PEERS_PATH, to.origin),
        batch === undefined ? undefined : { method: "POST", body: JSON.stringify(batch) },
      ),
    );
    expect(reply.ok).toBe(true);
    const parsed = parseMessage(await reply.json(), release, Date.now());
    if (parsed === undefined) throw new Error("invalid peer reply");
    return parsed;
  };
  vi.stubGlobal("fetch", async () => new Response(null, { status: 503 }));
  try {
    for (const [origin, peer] of peers) {
      const identity = [observer, bridge, joining].find((candidate) => candidate.origin === origin);
      if (identity === undefined) throw new Error("missing host");
      await peer.start(
        identity,
        now + (identity === joining ? 0 : 500),
        undefined,
        undefined,
        () => {},
        () => false,
        identity === joining ? details : undefined,
      );
    }
    const first = await send(joining);
    await send(bridge, first);
    await send(observer, await send(bridge, await send(observer)));
    let seen = await send(observer);
    expect(seen.startedAt).toBe(first.startedAt);
    expect(seen.changes).toContainEqual(
      expect.objectContaining({ ...joining, ...details, left: false }),
    );

    const peer = peers.get(joining.origin);
    if (peer === undefined) throw new Error("missing joining peer");
    await peer.stop();
    await send(bridge, await send(joining));
    await send(observer, await send(bridge, await send(observer)));
    await send(observer, first); // a delayed live report must not undo the stop.
    seen = await send(observer);
    expect(seen.changes).toContainEqual(
      expect.objectContaining({ runID: joining.runID, left: true }),
    );
  } finally {
    lifetime.abort();
    await Promise.all([...peers.values()].map((peer) => peer.stop()));
    vi.unstubAllGlobals();
  }
});

it("weights just the stable sample at a surge and counts all reporters again after a departure", async () => {
  const lifetime = new AbortController();
  const now = Date.now(),
    local = host(1);
  const peer = peerServer(release, [pageOrigin], async () => new Response(), lifetime.signal);
  vi.stubGlobal("fetch", async () => new Response(null, { status: 503 }));
  let gossip: Gossip | undefined;
  const remotes = Array.from({ length: 40 }, (_, i) => new Gossip(release, host(i + 2), now));
  function crowd(perHost: number) {
    if (!gossip) throw new Error("counting host is not ready");
    for (const remote of remotes) {
      remote.observeTabs(perHost, now);
      gossip.receive(remote.message(now), now);
    }
  }
  const beat = async (suffix: string) => {
    const res = await peer.fetch(
      new Request(new URL(PRESENCE_PATH, local.origin), {
        method: "POST",
        headers: { Origin: pageOrigin },
        body: JSON.stringify({
          tab: "00000000-0000-4000-8000-00000000000" + suffix,
          releaseID: release,
        }),
      }),
    );
    expect(res.status).toBe(200);
    return presenceSummary.parse(await res.json());
  };
  try {
    await peer.start(
      local,
      now,
      undefined,
      undefined,
      (v) => {
        gossip = v;
      },
      () => false,
    );
    for (const suffix of ["0", "1", "2", "3"]) await beat(suffix);
    crowd(500);
    expect(await beat("0")).toMatchObject({ tabs: 20004, sampling: true });
    crowd(350);
    expect(await beat("0")).toMatchObject({ tabs: 14004, sampling: true });
    expect(await beat("1")).toMatchObject({ tabs: 14004, sampling: true });
    expect(await beat("4")).toMatchObject({ tabs: 14008, sampling: true });
    // a returning full-count tab renews a single lease, including across the switch.
    crowd(200);
    expect(await beat("5")).toMatchObject({ tabs: 8006, sampling: false });
    expect(await beat("0")).toMatchObject({ tabs: 8006, sampling: false });
    const peers = await peer.fetch(new Request(new URL(PEERS_PATH, local.origin)));
    expect(parseMessage(await peers.json(), release, Date.now())?.audience).toMatchObject({
      tabs: 8006,
      sampling: false,
    });
  } finally {
    lifetime.abort();
    await peer.stop();
    vi.unstubAllGlobals();
  }
});
