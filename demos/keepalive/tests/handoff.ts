import assert from "node:assert/strict";
import { openSync, closeSync, writeSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";
import { chromium, type Page } from "playwright";
import { readPeers } from "../src/peers/http.ts";
import { HOST_TURN_MS, REPLACE_BEFORE_MS } from "../src/policy.ts";
import { hostOrigin, type Host } from "../src/peers/gossip.ts";
import {
  MAX_MANIFEST_BYTES,
  RELEASE_PATH,
  WASM_PATH,
  readJSON,
  parseRelease,
  type Release,
  type Asset,
} from "../src/release.ts";
import { observeTurn, observeHosts, visitorProbe } from "./browser-samples.ts";
import { observeInfrastructure } from "./infra-samples.ts";
import { periodic, distribution, type RecordSample } from "./measure.ts";

const { values } = parseArgs({
  options: {
    site: { type: "string" },
    start: { type: "string" },
    "peer-proxy": { type: "string" },
    report: { type: "string" },
    metrics: { type: "string" },
    "visitor-interval-ms": { type: "string", default: "2000" },
  },
});
assert(values.site && values.start, "Pass --site and --start for a site with no hosts.");
const site = new URL(values.site);
const start = new URL(values.start);
const interval = Number(values["visitor-interval-ms"]);
assert(
  Number.isSafeInteger(interval) && interval >= 250 && interval <= 60_000,
  "visitor interval must be 250–60000 ms",
);
const run = randomUUID();
const file = values.report ? openSync(values.report, "wx", 0o600) : undefined;
let phase = "setup";
const handoffMs: number[] = [];
const handoffBytes: number[] = [];
const emit: RecordSample = (event, fields) => {
  if (
    event === "turn" &&
    fields.outcome === "verified" &&
    typeof fields.invitationToVerifiedMs === "number"
  ) {
    handoffMs.push(fields.invitationToVerifiedMs);
    if (fields.completeWireSample === true && typeof fields.encodedHttpBytesObserved === "number")
      handoffBytes.push(fields.encodedHttpBytesObserved);
  }
  const line = JSON.stringify({ schema: 1, run, at: Date.now(), phase, event, ...fields }) + "\n";
  if (file === undefined) process.stdout.write(line);
  else writeSync(file, line);
};
const browser = await chromium.launch({ channel: "chrome" });
let release: Release;
let asset: Asset;
let visitors: Awaited<ReturnType<typeof visitorProbe>> | undefined;
const hosts = new Map<number, Host>();
const stopSampling: (() => Promise<void>)[] = [];
const latencies: number[] = [];
let visitorFailures = 0,
  omitted = 0,
  turnID = 0;
let complete = false;
const failures: unknown[] = [];
let duringCopy: Promise<Awaited<ReturnType<typeof visitorSample>>> | undefined;

async function begin(page: Page, name: string) {
  const turn = ++turnID;
  const host = await observeTurn(
    page,
    turn,
    release,
    start.origin,
    asset,
    () => page.getByRole("button", { name, exact: true }).click(),
    emit,
  );
  hosts.set(turn, host);
  return turn;
}

async function stop(page: Page, turn: number) {
  await page.getByRole("button", { name: "stop", exact: true }).click();
  await page.getByRole("button", { name: /^(host|volunteer) again$/ }).waitFor();
  hosts.delete(turn);
  emit("stop", { turn });
}

async function openSite(page: Page) {
  const response = await page.goto(site.href);
  if (response?.ok()) return;
  await page.waitForFunction(async () => (await fetch("/", { cache: "no-store" })).ok);
  await page.reload();
}

async function join(proxy?: { server: string }, downloading?: () => void) {
  const page = await browser.newPage(proxy === undefined ? {} : { proxy });
  await openSite(page);
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === WASM_PATH) downloading?.();
  });
  let sender: string | undefined;
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.pathname === WASM_PATH && hostOrigin(url.origin) && response.ok()) sender = url.origin;
  });
  const turn = await begin(page, "i'll keep it alive");
  assert(sender, "browser did not copy the publisher WASM from a peer");
  return { page, sender, turn };
}

async function visitorSample() {
  assert(visitors);
  const beganAt = Date.now(),
    beganPhase = phase;
  const sample = await visitors.sample();
  if (sample.ok) latencies.push(sample.ms);
  else visitorFailures++;
  emit("visitor", { beganAt, phase: beganPhase, ...sample });
  return sample;
}

try {
  const empty = await fetch(site, { redirect: "manual", signal: AbortSignal.timeout(10_000) });
  await empty.body?.cancel();
  assert.equal(empty.status, 503, "Use an empty test deployment.");
  const signal = AbortSignal.timeout(10_000);
  release = await parseRelease(
    await readJSON(
      await fetch(new URL(RELEASE_PATH, site), { redirect: "error", signal }),
      MAX_MANIFEST_BYTES,
      signal,
    ),
  );
  const html = release.assets.find((a) => a.path === "/index.html"),
    script = release.assets.find((a) => a.path === "/app.js");
  assert(html && script, "pinned page and script required");
  asset = html;
  visitors = await visitorProbe(browser, site, [html, script]);
  emit("start", {
    release: release.id,
    visitorIntervalMs: interval,
    infrastructure: Boolean(values.metrics),
  });
  if (values.metrics) stopSampling.push(await observeInfrastructure(values.metrics, emit));
  stopSampling.push(observeHosts(hosts, asset, emit));
  async function currentReport() {
    const report = await readPeers(site.origin, release.id);
    assert(report, "Expected a peer report from a running host.");
    return report;
  }
  const first = await browser.newPage();
  await first.goto(start.href);
  phase = "seed";
  const seed = await begin(first, "start hosting");
  const bootstrapReport = await currentReport();
  const startedAt = bootstrapReport.startedAt;
  const initialCertificate = bootstrapReport.from.certificate;
  assert(initialCertificate, "The bootstrap host did not advertise its installed certificate.");
  assert(
    initialCertificate.expiresAt > Date.now() + 24 * 60 * 60_000,
    "Use a fresh bootstrap certificate so a volunteer is expected to inherit it.",
  );
  assert((await visitorSample()).ok, "visitor failed before first copy");
  // sample only during expected availability. intentional outages get their own phase.
  const stopVisitors = periodic(
    interval,
    async () => {
      await visitorSample();
    },
    (slots) => {
      omitted += slots;
      emit("visitor_skipped", { slots });
    },
  );
  stopSampling.push(stopVisitors);
  phase = "first_copy";
  const second = await join(values["peer-proxy"] ? { server: values["peer-proxy"] } : undefined);
  const session = await second.page.context().newCDPSession(second.page);
  phase = "frozen_host";
  await session.send("Page.setWebLifecycleState", { state: "frozen" });
  try {
    assert((await visitorSample()).ok, "The site failed with a host frozen.");
  } finally {
    await session.send("Page.setWebLifecycleState", { state: "active" });
  }
  phase = "replacement_wait";
  await stop(first, seed);
  assert((await visitorSample()).ok, "The first copy did not take over.");
  const secondHost = (await currentReport()).from;
  assert.notEqual(secondHost.runID, bootstrapReport.from.runID);
  assert.equal(
    secondHost.certificate?.fingerprint,
    initialCertificate.fingerprint,
    "The second host did not install the bootstrap certificate.",
  );
  assert(secondHost.endsAt !== undefined);
  // wait for the real replacement window; don't shorten the browser's turn.
  await second.page.waitForFunction(
    (at) => Date.now() >= at,
    secondHost.endsAt - REPLACE_BEFORE_MS + 7_000,
    { timeout: HOST_TURN_MS, polling: 500 },
  );
  phase = "replacement";
  const third = await join(undefined, () => {
    if (!duringCopy) {
      duringCopy = visitorSample();
      void duringCopy.catch(() => {});
    }
  });
  assert((await duringCopy)?.ok, "a visitor failed during the handoff");
  assert.equal(third.sender, secondHost.origin, "The second host did not supply the new copy.");
  await second.page.getByRole("button", { name: "volunteer again" }).waitFor();
  hosts.delete(second.turn);
  const visitor = await browser.newPage();
  await openSite(visitor);
  assert.equal(
    (await currentReport()).startedAt,
    startedAt,
    "The clock should survive the handoffs.",
  );
  assert.equal(
    (await currentReport()).from.certificate?.fingerprint,
    initialCertificate.fingerprint,
    "The third host did not install the same certificate.",
  );
  // close the active host without its stop button as well.
  await stopVisitors();
  await third.page.close();
  phase = "last_host_gone";
  hosts.delete(third.turn);
  await visitor.waitForFunction(
    async () => (await fetch("/", { cache: "no-store" })).status === 503,
  );
  const restartedAt = Date.now();
  emit("outage", { status: 503 });
  phase = "reseed";
  const reseed = await begin(first, "host again");
  await openSite(visitor);
  assert(
    (await currentReport()).startedAt >= restartedAt,
    "The clock should reset after all hosts stop.",
  );
  await stop(first, reseed);
  assert.equal(visitorFailures, 0, "there were unplanned visitor failures");
  complete = true;
} catch (error) {
  failures.push(error);
} finally {
  try {
    const stops = await Promise.allSettled([...stopSampling.map((stop) => stop()), duringCopy]);
    for (const result of stops) if (result.status === "rejected") failures.push(result.reason);
    emit("summary", {
      complete: complete && failures.length === 0,
      visitorSuccessMs: distribution(latencies),
      verifiedHandoffMs: distribution(handoffMs),
      completeHandoffHttpBytes: distribution(handoffBytes),
      visitorFailures,
      skippedVisitorSamples: omitted,
    });
  } finally {
    try {
      await browser.close();
    } finally {
      if (file !== undefined) closeSync(file);
    }
  }
}
if (failures.length) throw new AggregateError(failures, "Keepalive handoff did not complete");
