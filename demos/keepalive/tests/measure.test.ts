import { expect, it, vi } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { observeInfrastructure } from "./infra-samples.ts";
import { copyTransfers, distribution, periodic, probeHost } from "./measure.ts";
import { HOST_PARENT } from "../src/peers/gossip.ts";
import { digest } from "../src/release.ts";

const host = {
  origin: `https://p-${"a".repeat(26)}.${HOST_PARENT}`,
  publisherID: `pub_${"b".repeat(22)}`,
  runID: `srun_${"c".repeat(22)}`,
  runNumber: "2",
};
const bytes = new TextEncoder().encode("pinned");
const asset = { path: "/index.html", size: bytes.length, sha256: await digest(bytes) };

it("counts only complete, pinned bytes from the exact live run", async () => {
  for (const [run, body, status, ok] of [
    [host.runID, "pinned", 200, true],
    ["old", "pinned", 200, false],
    [host.runID, "edited", 200, false],
    [host.runID, "pinned!", 200, false],
    [host.runID, "pinned", 503, false],
  ] as const) {
    const get = vi.fn(
      async () => new Response(body, { status, headers: { "X-Keepalive-Run": run } }),
    );
    expect(await probeHost(host, asset, new AbortController().signal, get)).toBe(ok);
    expect(get).toHaveBeenCalledWith(
      new URL(asset.path, host.origin),
      expect.objectContaining({ redirect: "manual", credentials: "omit" }),
    );
  }
});

it("does not count an unrelated visit or turn incomplete transfers into a successful copy", () => {
  const transfers = copyTransfers({ id: "test", assets: [asset] }, "https://start.test");
  transfers.request("page", "https://start.test/index.html", "GET");
  transfers.finish("page", 999);
  transfers.request("partial", `${host.origin}${asset.path}`, "GET");
  transfers.fail("partial");
  transfers.request("copied", "https://start.test/__keepalive/artifact/index.html", "GET");
  transfers.response("copied", 200);
  transfers.finish("copied", 45);
  expect(transfers.snapshot()).toEqual({
    encodedHttpBytesObserved: 45,
    completeTransfers: 1,
    completeWireSample: false,
    interruptedTransfers: 1,
    decodedManifestBytes: 6,
  });
  expect(distribution([])).toEqual({ count: 0, p50: null, p95: null, p99: null });
});

it("joins an in-flight observation on stop", async () => {
  const events: string[] = [];
  const stop = periodic(
    1000,
    async (signal) => {
      events.push("start");
      await new Promise<void>((done) =>
        signal.addEventListener("abort", () => done(), { once: true }),
      );
      events.push("end");
    },
    () => {
      throw new Error("unexpected skipped observation");
    },
  );
  await stop();
  expect(events).toEqual(["start", "end"]);
});

it("emits a gap rather than zero for missing metrics and discards backend labels", async () => {
  const dir = await mkdtemp(join(tmpdir(), "keepalive-metrics-"));
  try {
    const config = join(dir, "config.json");
    await writeFile(
      config,
      JSON.stringify({
        endpoint: "http://localhost/api/v1/query",
        queries: { relay: "ready", locks: "missing" },
      }),
    );
    vi.stubGlobal("fetch", async (input: URL) =>
      Response.json({
        status: "success",
        data: {
          resultType: "vector",
          result:
            input.searchParams.get("query") === "ready"
              ? [{ metric: { instance: "private" }, value: [15, "4"] }]
              : [],
        },
      }),
    );
    const rows: Record<string, unknown>[] = [];
    const sampled = Promise.withResolvers<void>();
    const stop = await observeInfrastructure(config, (_, fields) => {
      rows.push(fields);
      if (rows.length === 2) sampled.resolve();
    });
    try {
      await sampled.promise;
    } finally {
      await stop();
    }
    expect(rows).toContainEqual({ name: "relay", value: 4, sourceAtMs: 15_000 });
    expect(rows).toContainEqual({ name: "locks", value: null });
  } finally {
    vi.unstubAllGlobals();
    await rm(dir, { recursive: true, force: true });
  }
});
