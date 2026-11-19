import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { chromium } from "playwright";
import { PULSE_SECONDS } from "../src/hosting/activity.ts";
import { HOST_PARENT, type Change } from "../src/peers/gossip.ts";
import { siteHeaders } from "../src/edge/proxy.ts";
import { contentType, releaseSchema, WASM_PATH } from "../src/release.ts";

const dist = "demos/keepalive/dist";
const output = `${dist}/screenshots/ui`;
const release = releaseSchema.parse(JSON.parse(await readFile(`${dist}/release.json`, "utf8")));
const assets = new Map(
  await Promise.all(
    [...release.assets.map(({ path }) => path), "/start.html"].map(
      async (path) => [path, await readFile(`${dist}/site${path}`)] as const,
    ),
  ),
);
const apex = "https://keepthisalive.com";
const start = "https://start.keepthisalive.com";
const now = Math.floor(Date.now() / 1_000) * 1_000;
const startedAt = now - (((2 * 24 + 4) * 60 + 17) * 60 + 32) * 1_000;
const id = (key: string) => `srun_${key.repeat(22)}`;
function host(key: string, name: string, count: number, details: Partial<Change> = {}): Change {
  return {
    origin: `https://p-${key.repeat(26)}.${HOST_PARENT}`,
    publisherID: `pub_${key.repeat(22)}`,
    runID: id(key),
    runNumber: String(key.charCodeAt(0)),
    name,
    seq: 1,
    left: false,
    startingUntil: 0,
    endsAt: now + 402_000,
    tabs: { count, observedAt: now },
    ...details,
  };
}
const a = host("a", "quiet-pine", 0, { left: true, endsAt: now - 5_000 });
const b = host("b", "silver-birch", 42, { copyFrom: a.runID });
const self = host("c", "still-water", 54, { copyFrom: a.runID });
const roster = [
  self,
  a,
  b,
  host("d", "clear-fern", 47, { copyFrom: self.runID }),
  host("e", "soft-reed", 44, { copyFrom: self.runID }),
];
const proof = `${"a".repeat(64)}.${now}.${"b".repeat(64)}`;
const config = {
  controlURL: "https://control.tnl.dev",
  siteOrigin: apex,
  startHost: new URL(start).hostname,
  networkProof: proof,
};
const browser = await chromium.launch({ channel: "chrome" });
type Mode =
  | "visitor"
  | "hosting"
  | "waiting"
  | "checking"
  | "download"
  | "starting"
  | "slow"
  | "unavailable";

try {
  await mkdir(output, { recursive: true });
  async function fixture(
    name: string,
    mode: Mode,
    options: {
      width?: number;
      bootstrap?: boolean;
      seconds?: number;
      expanded?: boolean;
      finish?: "stop" | "expired";
      attention?: "background" | "muted";
    } = {},
  ) {
    const {
      width = 900,
      bootstrap = false,
      seconds = 402,
      expanded = false,
      finish,
      attention,
    } = options;
    const page = await browser.newPage({ viewport: { width, height: 800 }, deviceScaleFactor: 2 });
    await page.clock.setFixedTime(new Date(now));
    const errors: string[] = [];
    page.on("pageerror", (error) => {
      console.error(`${name}: ${error.message}`);
      errors.push(error.message);
    });
    const selected = Promise.withResolvers<void>();
    const workerState = {
      type: "hosting",
      origin: self.origin,
      since: now,
      endsAt: now + seconds * 1000,
      startedAt: bootstrap ? now : startedAt,
      hosts: bootstrap ? 1 : 4,
      runID: self.runID,
      tabs: bootstrap ? 1 : 187,
      localTabs: bootstrap ? 1 : 54,
      roster: bootstrap ? [{ ...self, copyFrom: undefined, endsAt: now + seconds * 1000 }] : roster,
    };
    const requests = seconds >= 600 ? 0 : 219;
    await page.addInitScript(
      ({ mode, workerState, requests, now, wasmPath, quiet }) => {
        const stats = { notes: 0, ready: false, locks: 0, releases: 0 };
        let hidden = false;
        let stopped: (() => void) | undefined;
        Object.defineProperty(document, "visibilityState", {
          get: () => (hidden ? "hidden" : "visible"),
        });
        Object.defineProperty(document, "hidden", { get: () => hidden });
        Object.defineProperty(navigator, "wakeLock", {
          value: {
            async request() {
              stats.locks++;
              return {
                released: false,
                async release() {
                  this.released = true;
                  stats.releases++;
                },
              };
            },
          },
        });
        const NativeAudio = window.AudioContext;
        window.AudioContext = class extends NativeAudio {
          override async resume() {
            await super.resume();
            stats.ready = true;
          }
          override createOscillator() {
            stats.notes++;
            return super.createOscillator();
          }
        };
        Object.assign(window, {
          stats,
          previewHide(value: boolean) {
            hidden = value;
            document.dispatchEvent(new Event("visibilitychange"));
          },
          previewStop: () => stopped?.(),
        });
        const NativeWorker = window.Worker;
        window.Worker = class extends NativeWorker {
          constructor(url: string | URL, options?: WorkerOptions) {
            super(
              options?.name === "keepalive"
                ? URL.createObjectURL(new Blob([""], { type: "text/javascript" }))
                : url,
              options,
            );
          }
          override postMessage(message: { type: string }) {
            if (message.type === "start" && mode !== "starting") {
              stopped = () =>
                this.dispatchEvent(
                  new MessageEvent("message", {
                    data: { type: "stopped", expired: true, requests },
                  }),
                );
              queueMicrotask(() => {
                this.dispatchEvent(new MessageEvent("message", { data: workerState }));
                this.dispatchEvent(
                  new MessageEvent("message", {
                    data: {
                      type: "activity",
                      requests,
                      second: now / 1_000,
                      pulse: requests === 0 ? quiet : "______|__||____|___|||____|___",
                    },
                  }),
                );
              });
            }
          }
        };
        if (mode === "download") {
          const original = window.fetch.bind(window);
          window.fetch = (input, init) => {
            if (typeof input !== "string" || !input.endsWith(wasmPath))
              return original(input, init);
            return Promise.resolve(
              new Response(
                new ReadableStream({
                  start(controller) {
                    // let the preceding assets' throttled progress update settle.
                    setTimeout(() => controller.enqueue(new Uint8Array(8_950_000)), 150);
                  },
                }),
              ),
            );
          };
        }
      },
      { mode, workerState, requests, now, wasmPath: WASM_PATH, quiet: "_".repeat(PULSE_SECONDS) },
    );
    await page.route("**/*", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname;
      const headers = {
        ...siteHeaders(),
        "Access-Control-Allow-Origin": request.headers().origin ?? apex,
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-Keepalive-Ready",
      };
      const ok = (json: unknown) =>
        route.fulfill({
          status: 200,
          headers: { ...headers, "Content-Type": "application/json" },
          json,
        });
      if (request.method() === "OPTIONS") return route.fulfill({ status: 204, headers });
      if (path === "/__keepalive/release") return ok(release);
      if (path === "/__keepalive/config")
        return mode === "unavailable" ? route.fulfill({ status: 503, headers }) : ok(config);
      if (path === "/__keepalive/network-proof") return ok(proof);
      if (path === "/__keepalive/peers" || path === "/__keepalive/presence") {
        if (bootstrap) return route.fulfill({ status: 503, headers });
        const from = roster.find((peer) => peer.origin === url.origin) ?? b;
        return ok({
          releaseID: release.id,
          startedAt,
          from,
          changes: roster.filter((peer) => peer !== from),
        });
      }
      if (path === "/__keepalive/wait") {
        if (attention !== undefined) await selected.promise;
        return ok(mode === "waiting" ? null : "12345678-1234-4234-8234-123456789abc");
      }
      if (path === "/__keepalive/upload") {
        if (mode === "checking")
          return new Promise<void>((resolve) => {
            page.once("close", () => resolve());
          });
        return route.fulfill({ status: mode === "slow" ? 422 : 204, headers });
      }
      const file =
        path === "/"
          ? bootstrap
            ? "/start.html"
            : "/index.html"
          : path.replace(/^\/__keepalive\/artifact/, "");
      const body = assets.get(file);
      if (body !== undefined)
        return route.fulfill({
          status: 200,
          headers: { ...headers, "Content-Type": contentType(file) ?? "application/octet-stream" },
          body,
        });
      return route.fulfill({ status: 404, headers });
    });
    await page.goto(bootstrap ? start : apex);
    const status = page.getByRole("status");
    const age = page.locator(".experiment-age strong");
    if (!bootstrap) await age.getByText("2d 04h 17m 32s", { exact: true }).waitFor();
    const warns = () =>
      page.evaluate(() => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })));
    type FixtureWindow = typeof window & {
      stats: { notes: number; ready: boolean; locks: number; releases: number };
      previewHide: (value: boolean) => void;
      previewStop: () => void;
    };
    const stats = () => page.evaluate(() => (window as FixtureWindow).stats);
    const hidden = (value: boolean) =>
      page.evaluate((value) => (window as FixtureWindow).previewHide(value), value);
    const startHosting = page.getByRole("button", {
      name: bootstrap ? "start hosting" : "i'll keep it alive",
    });
    const soundToggle = page.getByRole("button", { name: /^sound:/ });
    await startHosting.waitFor();
    assert.equal(await soundToggle.count(), 0);
    if (mode !== "visitor") await startHosting.click();
    if (attention !== undefined) {
      await status.getByText("Waiting to host…").waitFor();
      if (attention === "muted") {
        await page.getByRole("button", { name: "sound: on" }).click();
        await page.getByRole("button", { name: "sound: off" }).waitFor();
        await page.reload();
        await startHosting.waitFor();
        assert.equal(await soundToggle.count(), 0);
        await startHosting.click();
        await page.getByRole("button", { name: "sound: off" }).waitFor();
      }
      assert.equal(await warns(), false);
      assert.equal((await stats()).locks, 0);
      if (attention === "background")
        await page.waitForFunction(() => (window as FixtureWindow).stats.ready);
      await hidden(true);
      selected.resolve();
    }
    const messages = {
      visitor: "You can help keep it online.",
      hosting: "This tab is hosting.",
      waiting: "Waiting to host…",
      checking: "Checking your upload…",
      download: "Downloading files to serve visitors…",
      starting: "Starting to host…",
      slow: "This connection isn't fast enough to host right now.",
      unavailable: "Hosting isn't available right now. Try again later.",
    };
    await status.getByText(messages[mode], { exact: true }).waitFor();
    assert.equal(await soundToggle.count(), mode === "waiting" ? 1 : 0);
    if (mode === "download")
      await page
        .getByRole("progressbar")
        .getByText(/\[#+-+\]/)
        .waitFor();
    if (mode === "hosting") {
      await page
        .getByText(
          `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")} left in your turn`,
        )
        .waitFor({ timeout: 5_000 })
        .catch(async (error: unknown) => {
          throw new Error(`${name}: ${await page.locator("main").innerText()}`, { cause: error });
        });
      await page
        .getByText(bootstrap ? "serving 1 of ~1 tab" : "serving 54 of ~187 tabs", { exact: true })
        .waitFor();
      await page.getByText(`${requests} requests`, { exact: true }).waitFor();
      const stop = page.getByRole("button", { name: "stop", exact: true });
      assert.equal(await stop.count(), 1, await page.locator(".actions").innerText());
      await page.waitForFunction(
        () => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
        undefined,
        { polling: 50, timeout: 5_000 },
      );
      if (attention !== undefined) {
        const before = await stats();
        assert.equal(before.notes, attention === "background" ? 3 : 0);
        assert.equal(before.locks, 0);
        await hidden(false);
        await page.waitForFunction(() => (window as FixtureWindow).stats.locks === 1);
        await hidden(true);
        await page.waitForFunction(() => (window as FixtureWindow).stats.releases === 1);
        await hidden(false);
        await page.waitForFunction(() => (window as FixtureWindow).stats.locks === 2);
      } else assert.equal((await stats()).notes, 0);
    }
    if (expanded) {
      await page.getByText("hosts", { exact: true }).click();
      await page.getByText("how it spread", { exact: true }).waitFor();
      await page.getByText("still-water (you)", { exact: true }).waitFor();
      assert.ok((await page.locator(".host-tree li").count()) <= 8);
    }
    if (finish === "stop") {
      await page.getByRole("button", { name: "stop", exact: true }).click();
      await status.getByText("Stopping…").waitFor();
      await page.waitForFunction(() =>
        window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
      );
    } else if (finish === "expired") {
      await page.evaluate(() => (window as FixtureWindow).previewStop());
      await status.getByText("Your turn is over. Thanks for hosting.").waitFor();
      await page.getByText("219 requests handled").waitFor();
      await page.waitForFunction(() =>
        window.dispatchEvent(new Event("beforeunload", { cancelable: true })),
      );
      if (attention !== undefined)
        await page.waitForFunction(() => (window as FixtureWindow).stats.releases === 2);
    }
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),
      false,
    );
    assert.deepEqual(errors, []);
    await page.screenshot({
      path: `${output}/${name}.png`,
      fullPage: true,
      animations: "disabled",
    });
    await page.close();
  }

  await fixture("visitor", "visitor");
  await fixture("hosting", "hosting", { attention: "background" });
  await fixture("hosts", "hosting", { width: 360, expanded: true, attention: "muted" });
  await fixture("bootstrap", "hosting", { bootstrap: true, seconds: 3_600 });
  await fixture("first-turn", "hosting", { seconds: 600 });
  await fixture("final-seconds", "hosting", { seconds: 3 });
  await fixture("stopping", "hosting", { finish: "stop" });
  await fixture("finished", "hosting", { finish: "expired", attention: "background" });
  await fixture("waiting", "waiting");
  await fixture("checking", "checking");
  await fixture("downloading", "download");
  await fixture("starting", "starting");
  await fixture("slow", "slow", { width: 360 });
  await fixture("unavailable", "unavailable", { bootstrap: true });
  console.log(`Captured 14 Chrome states with simulated hosts in ${output}`);
} finally {
  await browser.close();
}
