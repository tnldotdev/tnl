import assert from "node:assert/strict";
import { parseArgs } from "node:util";
import { chromium, type Page } from "playwright";
import { hostOrigin } from "../src/peers.ts";
import { WASM_PATH } from "../src/release.ts";

const { values } = parseArgs({
  options: { site: { type: "string" }, start: { type: "string" } },
});
assert(values.site && values.start, "Pass --site and --start for an empty test deployment.");
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

async function join() {
  const page = await browser.newPage();
  await openSite(page);
  const copy = page.waitForResponse(
    (response) => {
      const url = new URL(response.url());
      return url.pathname === WASM_PATH && hostOrigin(url.origin) && response.ok();
    },
    { timeout: 90_000 },
  );
  await page.getByRole("button", { name: "i’ll keep it alive" }).click();
  const sender = new URL((await copy).url()).origin;
  await hosting(page);
  return { page, sender };
}

try {
  assert.equal((await fetch(site)).status, 503, "Use an empty test deployment.");
  const first = await browser.newPage();
  await first.goto(start.href);
  await first.getByRole("button", { name: "start hosting" }).click();
  await hosting(first);
  const second = await join();
  await stop(first);
  const third = await join();
  assert.notEqual(third.sender, second.sender, "The first host supplied both copies.");
  await stop(second.page);
  const visitor = await browser.newPage();
  await openSite(visitor);
  await visitor.getByRole("heading", { name: "can we keep this alive?" }).waitFor();
  await stop(third.page);
  await visitor.waitForFunction(
    async () => (await fetch("/", { cache: "no-store" })).status === 503,
  );
  await first.getByRole("button", { name: "start hosting" }).click();
  await hosting(first);
  await openSite(visitor);
  await visitor.getByRole("heading", { name: "can we keep this alive?" }).waitFor();
  await stop(first);
  console.log("Two browser handoffs, final-host outage, and restart passed.");
} finally {
  await browser.close();
}
