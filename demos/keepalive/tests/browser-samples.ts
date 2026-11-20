import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import type { Browser, Page } from "playwright";
import { parseHost, type Host } from "../src/peers/gossip.ts";
import { STARTUP_MS } from "../src/policy.ts";
import type { Asset, Release } from "../src/release.ts";
import { copyTransfers, periodic, probeHost, type RecordSample } from "./measure.ts";

// these marks use the page's monotonic clock. convert milestones to epoch
// milliseconds in the browser before comparing them to the harness timeline.
function readTurn() {
  function mark(name: string) {
    return performance.getEntriesByName(`keepalive ${name}`, "mark").at(-1) as
      | PerformanceMark
      | undefined;
  }
  function time(name: string) {
    const entry = mark(name);
    return entry ? Math.round(performance.timeOrigin + entry.startTime) : null;
  }
  const outcome: unknown = mark("ended")?.detail;
  const published: unknown = mark("published")?.detail;
  return {
    published,
    outcome:
      outcome === "failed" ||
      outcome === "expired" ||
      outcome === "stopped" ||
      outcome === "completed"
        ? outcome
        : null,
    volunteeredAt: time("volunteered"),
    invitedAt: time("invited"),
    copyStartedAt: time("copying"),
    copyVerifiedAt: time("copied"),
    publishedAt: time("published"),
    endedAt: time("ended"),
    verificationMs:
      performance.getEntriesByName("keepalive verify", "measure").at(-1)?.duration ?? null,
  };
}

export async function observeTurn(
  page: Page,
  turn: number,
  release: Release,
  startOrigin: string,
  asset: Asset,
  click: () => Promise<void>,
  emit: RecordSample,
) {
  const session = await page.context().newCDPSession(page);
  const transfers = copyTransfers(release, startOrigin);
  session.on("Network.requestWillBeSent", (e) =>
    transfers.request(e.requestId, e.request.url, e.request.method),
  );
  session.on("Network.responseReceived", (e) => transfers.response(e.requestId, e.response.status));
  session.on("Network.loadingFinished", (e) => transfers.finish(e.requestId, e.encodedDataLength));
  session.on("Network.loadingFailed", (e) => transfers.fail(e.requestId));
  let verifiedAt: number | null = null;
  let outcome = "incomplete";
  try {
    await session.send("Network.enable");
    await click();
    await page.waitForFunction(
      () =>
        Boolean(
          performance.getEntriesByName("keepalive invited").length ||
          performance.getEntriesByName("keepalive copying").length ||
          performance.getEntriesByName("keepalive ended").length,
        ),
      undefined,
      { timeout: STARTUP_MS },
    );
    await page.waitForFunction(
      () =>
        Boolean(
          performance.getEntriesByName("keepalive published").length ||
          performance.getEntriesByName("keepalive ended").length,
        ),
      undefined,
      { timeout: STARTUP_MS + 16_000 },
    );
    const local = await page.evaluate(readTurn);
    const host = parseHost(local.published);
    assert(host && !local.outcome, "turn did not publish");
    const deadline = AbortSignal.timeout(
      Math.max(
        1,
        Math.min(
          STARTUP_MS,
          (local.invitedAt ?? local.volunteeredAt ?? Date.now()) + STARTUP_MS - Date.now(),
        ),
      ),
    );
    while (!(await probeHost(host, asset, deadline))) {
      emit("startup_probe_miss", { turn });
      if (deadline.aborted) {
        outcome = "probe_failed";
        throw new Error("publisher did not serve the pinned asset before the startup deadline");
      }
      await delay(250);
    }
    verifiedAt = Date.now();
    await page.locator(".host-activity").waitFor({ timeout: STARTUP_MS });
    outcome = "verified";
    return host;
  } finally {
    const local = await page.evaluate(readTurn).catch(() => null);
    const { published: _host, outcome: ended, ...times } = local ?? {};
    const invited = local?.invitedAt;
    emit("turn", {
      turn,
      ...times,
      verifiedAt,
      outcome: ended ?? outcome,
      invitationToVerifiedMs: verifiedAt !== null && invited != null ? verifiedAt - invited : null,
      ...transfers.snapshot(),
    });
    await session.detach().catch(() => {
      if (!page.isClosed()) throw new Error("could not detach copy observer");
    });
  }
}

// an isolated, inert tab makes real Chromium requests from the public origin.
// the synthetic document is local; only the checked HTML and asset hit the proxy.
export async function visitorProbe(browser: Browser, site: URL, files: readonly Asset[]) {
  const page = await browser.newPage({ serviceWorkers: "block" });
  const shell = new URL("/__keepalive/measurement-tab", site).href;
  try {
    await page.route(shell, (route) =>
      route.fulfill({ contentType: "text/html", body: "<!doctype html><title>probe</title>" }),
    );
    await page.goto(shell);
  } catch (error) {
    await page.close();
    throw error;
  }
  return {
    close: () => page.close(),
    async sample() {
      return page.evaluate(async (assets) => {
        const start = performance.now();
        let status: number | null = null;
        for (const asset of assets) {
          try {
            const response = await fetch(asset.path === "/index.html" ? "/" : asset.path, {
              cache: "no-store",
              credentials: "omit",
              redirect: "error",
              signal: AbortSignal.timeout(6_000),
            });
            status = response.status;
            if (status !== 200 || !response.body) {
              await response.body?.cancel();
              return { ok: false, status, reason: "status", ms: performance.now() - start };
            }
            const bytes = new Uint8Array(asset.size);
            const reader = response.body.getReader();
            let offset = 0;
            for (;;) {
              const chunk = await reader.read();
              if (chunk.done) break;
              if (chunk.value.length > bytes.length - offset) {
                await reader.cancel();
                return { ok: false, status, reason: "integrity", ms: performance.now() - start };
              }
              bytes.set(chunk.value, offset);
              offset += chunk.value.length;
            }
            if (
              offset !== asset.size ||
              Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) =>
                b.toString(16).padStart(2, "0"),
              ).join("") !== asset.sha256
            )
              return { ok: false, status, reason: "integrity", ms: performance.now() - start };
          } catch {
            return { ok: false, status: null, reason: "network", ms: performance.now() - start };
          }
        }
        return { ok: true, status, reason: "verified", ms: performance.now() - start };
      }, files);
    },
  };
}

// count only independently verified test participants in this sampling round;
// a persistent URL answering for a different run is a miss.
export function observeHosts(hosts: ReadonlyMap<number, Host>, asset: Asset, emit: RecordSample) {
  return periodic(
    20_000,
    async (signal) => {
      const pending = [...hosts];
      const verified = new Set<string>();
      const count = pending.length;
      const beganAt = Date.now();
      const check = async () => {
        for (let entry = pending.pop(); entry && !signal.aborted; entry = pending.pop()) {
          const [turn, host] = entry;
          const ok = await probeHost(host, asset, signal);
          if (!signal.aborted) {
            if (ok) verified.add(host.publisherID);
            emit("host_probe", { turn, ok });
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(8, count) }, check));
      if (!signal.aborted)
        emit("hosts", { beganAt, participants: count, verifiedHosts: verified.size });
    },
    (slots) => emit("host_probe_skipped", { slots }),
  );
}
