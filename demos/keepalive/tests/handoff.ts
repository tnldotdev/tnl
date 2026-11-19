import assert from "node:assert/strict";
import { parseArgs } from "node:util";
import { chromium, type Page } from "playwright";
import { readPeers } from "../src/hosting/peer-http.ts";
import { hostOrigin } from "../src/peers.ts";
import { RELEASE_PATH, WASM_PATH, releaseSchema } from "../src/release.ts";

const { values } = parseArgs({
  options: {
    site: { type: "string" },
    start: { type: "string" },
    "peer-proxy": { type: "string" },
  },
});
assert(
  values.site && values.start && values["peer-proxy"],
  "Pass --site and --start for a site with no hosts, plus --peer-proxy for a different public IP.",
);
const site = new URL(values.site);
const start = new URL(values.start);
const browser = await chromium.launch({ channel: "chrome" });

async function hosting(page: Page) {
  await page.getByRole("status").getByText("This tab is hosting.").waitFor({ timeout: 150_000 });
}

async function stop(page: Page) {
  await page.getByRole("button", { name: "stop", exact: true }).click();
  await page.getByRole("status").getByText("This tab stopped hosting.").waitFor();
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
  async function startTime() {
    const report = await readPeers(site.origin, release.id);
    assert(report, "Expected a peer report from a running host.");
    return report.startedAt;
  }
  const first = await browser.newPage();
  await first.goto(start.href);
  await first.getByRole("button", { name: "start hosting" }).click();
  await hosting(first);
  const startedAt = await startTime();
  console.log("visitor before copy", await visitorSample("/"));
  await first.getByRole("button", { name: "find my replacement" }).click();
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
  const [second, samples] = await Promise.all([
    join({ server: values["peer-proxy"] }, copyStarted).finally(() => {
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
  await first.getByRole("status").getByText("is serving now. Thanks for hosting.").waitFor();
  const third = await join();
  assert.notEqual(third.sender, second.sender, "The first host supplied both copies.");
  const session = await second.page.context().newCDPSession(second.page);
  await session.send("Page.setWebLifecycleState", { state: "frozen" });
  assert.equal((await visitorSample("/")).status, 200, "The site failed with a host frozen.");
  await session.send("Page.setWebLifecycleState", { state: "active" });
  await second.page.close();
  const visitor = await browser.newPage();
  await openSite(visitor);
  await visitor.getByRole("heading", { name: "can we keep this alive?" }).waitFor();
  assert.equal(await startTime(), startedAt, "The clock should survive the handoffs.");
  await stop(third.page);
  await visitor.waitForFunction(
    async () => (await fetch("/", { cache: "no-store" })).status === 503,
  );
  const restartedAt = Date.now();
  await first.getByRole("button", { name: "start hosting" }).click();
  await hosting(first);
  await openSite(visitor);
  await visitor.getByRole("heading", { name: "can we keep this alive?" }).waitFor();
  assert((await startTime()) >= restartedAt, "The clock should reset after all hosts stop.");
  await stop(first);
  console.log("Two browser handoffs, final-host outage, and restart passed.");
} finally {
  await browser.close();
}
