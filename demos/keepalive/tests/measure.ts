import { setTimeout as delay } from "node:timers/promises";
import { HOST_PARENT, hostOrigin, type Host } from "../src/peers/host.ts";
import { ARTIFACT_PREFIX, readAssetResponse, type Asset, type Release } from "../src/release.ts";

export type RecordSample = (event: string, fields: Record<string, unknown>) => void;

export function distribution(values: readonly number[]) {
  const sorted = [...values].sort((a, b) => a - b);
  const at = (q: number) => sorted[Math.ceil(sorted.length * q) - 1] ?? null;
  return { count: sorted.length, p50: at(0.5), p95: at(0.95), p99: at(0.99) };
}

// Chromium's encodedDataLength counts received HTTP bytes, not decoded file
// size or TCP/TLS framing. missing and interrupted requests are not zero bytes.
export function copyTransfers(release: Release, startOrigin: string, parent = HOST_PARENT) {
  const assets = new Map(release.assets.map((a) => [a.path, a.size]));
  const pending = new Map<string, { path: string; status?: number }>();
  const completed = new Set<string>();
  let received = 0,
    interrupted = 0;
  return {
    request(id: string, raw: string, method: string) {
      const url = URL.parse(raw);
      if (!url || method !== "GET" || url.search) return;
      const path = hostOrigin(url.origin, parent)
        ? url.pathname
        : url.origin === startOrigin && url.pathname.startsWith(ARTIFACT_PREFIX + "/")
          ? url.pathname.slice(ARTIFACT_PREFIX.length)
          : undefined;
      if (path && assets.has(path)) pending.set(id, { path });
    },
    response(id: string, status: number) {
      const entry = pending.get(id);
      if (entry) entry.status = status;
    },
    finish(id: string, bytes: number) {
      const entry = pending.get(id);
      if (!entry) return;
      pending.delete(id);
      if (!Number.isFinite(bytes) || bytes <= 0) {
        interrupted++;
        return;
      }
      received += bytes;
      if (entry.status === 200) completed.add(entry.path);
    },
    fail(id: string) {
      if (pending.delete(id)) interrupted++;
    },
    snapshot() {
      return {
        encodedHttpBytesObserved: received,
        completeTransfers: completed.size,
        completeWireSample: completed.size === assets.size && !interrupted && !pending.size,
        interruptedTransfers: interrupted + pending.size,
        decodedManifestBytes: [...assets.values()].reduce((a, b) => a + b, 0),
      };
    },
  };
}

export async function probeHost(
  host: Host,
  asset: Asset,
  signal: AbortSignal,
  get = fetch,
  parent = HOST_PARENT,
) {
  if (!hostOrigin(host.origin, parent)) throw new Error("invalid publisher address");
  const timeout = AbortSignal.any([signal, AbortSignal.timeout(6_000)]);
  try {
    const response = await get(new URL(asset.path, host.origin), {
      signal: timeout,
      redirect: "manual",
      credentials: "omit",
      cache: "no-store",
    });
    if (response.status !== 200 || response.headers.get("X-Keepalive-Run") !== host.runID) {
      await response.body?.cancel();
      return false;
    }
    await readAssetResponse(asset, response, timeout);
    return true;
  } catch {
    return false;
  }
}

// run at the requested start rate, dropping busy slots instead of accumulating
// work or sending a burst after a slow request. stop joins the active sample.
export function periodic(
  interval: number,
  sample: (signal: AbortSignal) => Promise<void>,
  skipped: (n: number) => void,
) {
  const lifetime = new AbortController();
  const { signal } = lifetime;
  const done = (async () => {
    let due = performance.now();
    while (!signal.aborted) {
      await sample(signal);
      if (signal.aborted) break;
      due += interval;
      const missed = Math.max(0, Math.ceil((performance.now() - due) / interval));
      if (missed) {
        skipped(missed);
        due += missed * interval;
      }
      await delay(Math.max(0, due - performance.now()), undefined, { signal }).catch((e) => {
        if (!signal.aborted) throw e;
      });
    }
  })();
  // handle a sample error immediately, but propagate it to the joined caller.
  void done.catch(() => {});
  return async () => {
    lifetime.abort();
    await done;
  };
}
