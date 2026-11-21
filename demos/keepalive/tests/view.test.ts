import { expect, it, vi } from "vitest";
import {
  Gossip,
  HOST_PARENT,
  MAX_CHANGES,
  PEERS_PATH,
  parseMessage,
  type Host,
} from "../src/peers/gossip.ts";
import { peerServer } from "../src/peers/http.ts";
import { PRESENCE_PATH } from "../src/peers/presence.ts";
import { MAX_TREE_HOSTS, TREE_PATH, presenceSummary, treeHost } from "../src/peers/view.ts";
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
