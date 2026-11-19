import { expect, it, vi } from "vitest";
import { Gossip, HOST_PARENT, MAX_CHANGES, type Host } from "../src/peers/gossip.ts";
import { peerServer } from "../src/peers/http.ts";
import { PRESENCE_PATH } from "../src/peers/presence.ts";
import { MAX_TREE_HOSTS, TREE_PATH, presenceSummary, treeHost } from "../src/peers/view.ts";
import * as z from "zod";

it("counts more hosts than fit in gossip without sending the roster to the visitor", async () => {
  const lifetime = new AbortController();
  const pageOrigin = "https://keepthisalive.com";
  const release = "a".repeat(64);
  const now = Date.now();
  const host = (n: number): Host => ({
    origin: `https://p-${n.toString(2).replaceAll("0", "a").replaceAll("1", "b").padStart(26, "a")}.${HOST_PARENT}`,
    publisherID: `pub_${String(n).padStart(22, "0")}`,
    runID: `srun_${String(n).padStart(22, "0")}`,
    runNumber: String(n),
  });
  const local = host(1);
  const remoteCount = MAX_TREE_HOSTS + 5;
  const peer = peerServer(release, [pageOrigin], async () => new Response(), lifetime.signal, {
    proxyOrigin: pageOrigin,
    proof: `${"a".repeat(64)}.${now}.${"b".repeat(64)}`,
  });
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
