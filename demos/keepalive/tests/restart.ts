import assert from "node:assert/strict";
import { setTimeout as delay } from "node:timers/promises";
import type { BrowserContext } from "playwright";
import { noReachableHost } from "../src/network.ts";
import { PEERS_PATH, type Host } from "../src/peers/host.ts";
import { readPeers } from "../src/peers/http.ts";
import { MAX_MANIFEST_BYTES, RELEASE_PATH, parseRelease, readJSON } from "../src/release.ts";
import { observeTurn } from "./browser-samples.ts";
import { probeHost, type RecordSample } from "./measure.ts";

export async function verifyRestart(options: {
  site: string;
  start: string;
  parent: string;
  control: string;
  releaseID: string;
  openSeed: () => Promise<BrowserContext>;
  openVolunteer: () => Promise<BrowserContext>;
  emit: RecordSample;
}) {
  const { site, start, parent, control, releaseID, emit } = options;
  async function pinned(origin: string) {
    const signal = AbortSignal.timeout(10_000);
    const r = await fetch(new URL(RELEASE_PATH, origin), {
      redirect: "error",
      cache: "no-store",
      signal,
    });
    assert.equal(r.headers.get("X-Keepalive-Host-Parent"), parent, "unexpected publisher hostname");
    const manifest = await parseRelease(await readJSON(r, MAX_MANIFEST_BYTES, signal));
    assert.equal(manifest.id, releaseID, "release changed");
    return manifest;
  }
  const checked = () => Promise.all([pinned(site), pinned(start)]);
  const [manifest] = await checked();
  const html = manifest.assets.find((a) => a.path === "/index.html");
  const js = manifest.assets.find((a) => a.path === "/app.js");
  assert(html && js);
  const assets = [html, js] as const;
  async function empty() {
    const r = await fetch(new URL(PEERS_PATH, site), {
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(16_000),
    });
    await r.body?.cancel();
    return noReachableHost(r);
  }
  async function join(context: BrowserContext, turn: number) {
    const seed = turn !== 3;
    let orders = 0;
    const installed = new Set<string>();
    context.on("request", (req) => {
      const u = new URL(req.url());
      if (
        req.method() === "POST" &&
        u.origin === control &&
        u.pathname.endsWith("/certificate-issuances")
      )
        orders++;
    });
    context.on("response", (res) => {
      const u = new URL(res.url());
      if (
        res.ok() &&
        res.request().method() === "POST" &&
        u.origin === control &&
        u.pathname.endsWith("certificate-installed")
      )
        installed.add(u.pathname);
    });
    await checked();
    const page = await context.newPage();
    assert.equal((await page.goto(seed ? start : site))?.status(), 200);
    const host = await observeTurn(
      page,
      turn,
      manifest,
      start,
      assets[0],
      () =>
        page
          .getByRole("button", { name: seed ? "start hosting" : "i'll keep it alive", exact: true })
          .click(),
      emit,
      parent,
    );
    async function prove(h: Host) {
      for (const asset of assets)
        assert(
          await probeHost(h, asset, AbortSignal.timeout(6_000), fetch, parent),
          "exact run did not serve pinned bytes",
        );
      const report = await readPeers(h.origin, releaseID, undefined, undefined, parent);
      assert(
        report &&
          report.from.runID === h.runID &&
          report.from.origin === h.origin &&
          report.from.certificate,
      );
      return report.from.certificate;
    }
    const certificate = await prove(host);
    // a matching successful install confirms the observer saw the publisher worker.
    const operation = seed ? "certificate-installed" : "supplied-certificate-installed";
    assert(
      [...installed].some((path) => path.endsWith(`/runs/${host.runID}/${operation}`)),
      "missing certificate installation observation",
    );
    if (turn > 1) assert.equal(orders, 0, "unexpected request for managed issuance");
    emit("certificate", {
      turn,
      runID: host.runID,
      fingerprint: certificate.fingerprint,
      issuanceRequests: orders,
    });
    return { host, certificate, page, issuanceRequests: () => orders };
  }
  assert(await empty(), "expected an explicitly empty test fleet");
  const first = await options.openSeed();
  const original = await (async () => {
    try {
      const result = await join(first, 1);
      assert(
        result.certificate.expiresAt > Date.now() + 24 * 3600_000,
        "test requires a certificate outside the renewal window",
      );
      await result.page.getByRole("button", { name: "stop", exact: true }).click();
      await result.page.getByRole("button", { name: "host again", exact: true }).waitFor();
      return result;
    } finally {
      await first.close();
    }
  })();
  const deadline = AbortSignal.timeout(60_000);
  while (!(await empty())) await delay(500, undefined, { signal: deadline });
  const reopened = await options.openSeed();
  try {
    const second = await join(reopened, 2);
    assert.notEqual(second.host.runID, original.host.runID);
    assert.equal(second.host.publisherID, original.host.publisherID);
    assert.equal(second.certificate.fingerprint, original.certificate.fingerprint);
    const volunteer = await options.openVolunteer();
    try {
      const third = await join(volunteer, 3);
      assert.notEqual(third.host.publisherID, second.host.publisherID);
      assert.equal(third.certificate.fingerprint, second.certificate.fingerprint);
      const newOrders = second.issuanceRequests() + third.issuanceRequests();
      assert.equal(newOrders, 0);
      emit("restart_passed", {
        releaseID,
        parent,
        verifiedRuns: 3,
        restartAndVolunteerIssuanceRequests: newOrders,
      });
    } finally {
      await volunteer.close();
    }
  } finally {
    await reopened.close();
  }
}
