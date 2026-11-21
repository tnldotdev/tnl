import assert from "node:assert/strict";
import { parseArgs } from "node:util";
import { chromium, type Page } from "playwright";
import { readPeers } from "../src/peers/http.ts";
import { HOST_TURN_MS, REPLACE_BEFORE_MS } from "../src/policy.ts";
import { hostOrigin } from "../src/peers/gossip.ts";
import { RELEASE_PATH, WASM_PATH, releaseSchema } from "../src/release.ts";

const { values } = parseArgs({
  options: {
    site: { type: "string" },
    start: { type: "string" },
    "peer-proxy": { type: "string" },
  },
});
assert(values.site && values.start, "Pass --site and --start for a site with no hosts.");
const site = new URL(values.site);
const start = new URL(values.start);
const browser = await chromium.launch({ channel: "chrome" });

async function hosting(page: Page) {
  await page.locator(".host-activity").waitFor({ timeout: 150_000 });
}

async function stop(page: Page) {
  await page.getByRole("button", { name: "stop", exact: true }).click();
  await page.getByRole("button", { name: /^(host|volunteer) again$/ }).waitFor();
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
  const copy = page.waitForResponse(
    (response) => {
      const url = new URL(response.url());
      return url.pathname === WASM_PATH && hostOrigin(url.origin) && response.ok();
    },
    { timeout: 90_000 },
  );
  await page.getByRole("button", { name: "i'll keep it alive" }).click();
  const sender = new URL((await copy).url()).origin;
  await hosting(page);
  console.log(
    await page.evaluate(() => {
      const measure = (name: string) =>
        Math.round(performance.getEntriesByName(name).at(-1)?.duration ?? 0);
      const copy = measure("keepalive copy");
      const verify = measure("keepalive verify");
      return {
        downloadMs: copy - verify,
        verifyMs: verify,
        startupMs: measure("keepalive startup"),
      };
    }),
  );
  return { page, sender };
}

async function visitorSample(path: string) {
  const start = performance.now();
  const response = await fetch(new URL(path, site), { cache: "no-store" });
  await response.arrayBuffer();
  return { status: response.status, ms: Math.round(performance.now() - start) };
}

try {
  assert.equal((await fetch(site)).status, 503, "Use an empty test deployment.");
  const release = releaseSchema.parse(await (await fetch(new URL(RELEASE_PATH, site))).json());
  async function currentReport() {
    const report = await readPeers(site.origin, release.id);
    assert(report, "Expected a peer report from a running host.");
    return report;
  }
  const first = await browser.newPage();
  await first.goto(start.href);
  await first.getByRole("button", { name: "start hosting" }).click();
  await hosting(first);
  const bootstrapReport = await currentReport();
  const startedAt = bootstrapReport.startedAt;
  const initialCertificate = bootstrapReport.from.certificate;
  assert(initialCertificate, "The bootstrap host did not advertise its installed certificate.");
  assert(
    initialCertificate.expiresAt > Date.now() + 24 * 60 * 60_000,
    "Use a fresh bootstrap certificate so a volunteer is expected to inherit it.",
  );
  console.log("visitor before copy", await visitorSample("/"));
  const second = await join(values["peer-proxy"] ? { server: values["peer-proxy"] } : undefined);
  const session = await second.page.context().newCDPSession(second.page);
  await session.send("Page.setWebLifecycleState", { state: "frozen" });
  try {
    assert.equal((await visitorSample("/")).status, 200, "The site failed with a host frozen.");
  } finally {
    await session.send("Page.setWebLifecycleState", { state: "active" });
  }
  await stop(first);
  assert((await visitorSample("/")).status === 200, "The first copy did not take over.");
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
  let copyingDone = false;
  let copyStarted!: () => void;
  const copyStartedPromise = new Promise<void>((resolve) => {
    copyStarted = resolve;
  });
  async function sampleVisitors() {
    await copyStartedPromise;
    const samples = [];
    while (!copyingDone && samples.length < 20) {
      samples.push(await visitorSample("/"));
      if (!copyingDone) await new Promise((resolve) => setTimeout(resolve, 500));
    }
    return samples;
  }
  const [third, samples] = await Promise.all([
    join(undefined, copyStarted).finally(() => {
      copyingDone = true;
      copyStarted();
    }),
    sampleVisitors(),
  ]);
  console.log("visitors during handoff", samples);
  assert(
    samples.every(({ status }) => status === 200),
    "A visitor failed during the handoff.",
  );
  assert.equal(third.sender, secondHost.origin, "The second host did not supply the new copy.");
  await second.page.getByRole("button", { name: "volunteer again" }).waitFor();
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
  await third.page.close();
  await visitor.waitForFunction(
    async () => (await fetch("/", { cache: "no-store" })).status === 503,
  );
  const restartedAt = Date.now();
  await first.getByRole("button", { name: "host again" }).click();
  await hosting(first);
  await openSite(visitor);
  assert(
    (await currentReport()).startedAt >= restartedAt,
    "The clock should reset after all hosts stop.",
  );
  await stop(first);
  console.log("Browser copies, automatic replacement, final-host outage, and restart passed.");
} finally {
  await browser.close();
}
