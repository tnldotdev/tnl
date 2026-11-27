import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { chromium } from "playwright";
import { beforeAll, expect, test } from "vitest";
import { hostWordsEsbuild } from "../scripts/host-words.ts";
import { startPage } from "../scripts/page.ts";
import { siteHeaders } from "../src/edge/proxy.ts";
import { Gossip } from "../src/peers/gossip.ts";
import { pageHost as host } from "./page-host.ts";
import { HEARTBEAT_MS } from "../src/peers/presence.ts";
import { UPLOAD_BYTES } from "../src/policy.ts";
import { ARTIFACT_PREFIX, digest, WASM_PATH, WORKER_PATH, type Release } from "../src/release.ts";
import { pageBundle } from "./page-bundle.ts";

let site:
  | {
      files: Map<string, Buffer>;
      initial: Set<string>;
      turn: string;
      tree: string;
      release: Release;
    }
  | undefined;
beforeAll(async () => {
  const { files, chunks, initial } = await pageBundle();
  const worker = await build({
    entryPoints: [fileURLToPath(new URL("./page-worker.ts", import.meta.url))],
    bundle: true,
    format: "esm",
    write: false,
    plugins: [hostWordsEsbuild],
  });
  const code = worker.outputFiles[0]?.contents;
  const turn = chunks.find((chunk) =>
    chunk.moduleIds.some((id) => id.endsWith("/page/turn.tsx")),
  )?.fileName;
  const tree = chunks.find((chunk) =>
    chunk.moduleIds.some((id) => id.endsWith("/page/hosts.tsx")),
  )?.fileName;
  if (!code || !turn || !tree) throw new Error("Missing fixture worker or optional chunks.");
  files.set(WORKER_PATH, Buffer.from(code));
  files.set(WASM_PATH, Buffer.from("unused by the fixture worker"));
  const assets = await Promise.all(
    [...files].map(async ([path, bytes]) => ({
      path,
      size: bytes.length,
      sha256: await digest(bytes),
    })),
  );
  const release = { id: await digest(new TextEncoder().encode(JSON.stringify(assets))), assets };
  site = { files, initial, turn: `/${turn}`, tree: `/${tree}`, release };
});

async function fixture(options: { bootstrap?: boolean; javaScriptEnabled?: boolean } = {}) {
  const built = site;
  if (!built) throw new Error("Missing built fixture.");
  const browser = await chromium.launch({ channel: "chrome" });
  try {
    const page = await browser.newPage({ javaScriptEnabled: options.javaScriptEnabled ?? true });
    page.setDefaultTimeout(5_000);
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => {
      if (message.text().includes("Content Security Policy")) errors.push(message.text());
    });
    const state = {
      now: Date.now(),
      checkins: 0,
      uploads: 0,
      treeReads: 0,
      peers: 0,
      workers: 0,
      released: 0,
      unavailable: options.bootstrap ?? false,
      presenceFailure: false,
      failTree: false,
      failTurn: false,
      corrupt: "",
      holdTurn: false,
      turnRequested: false,
    };
    const copied = new Set<string>();
    const scripts = new Set<string>();
    const heldTurn = Promise.withResolvers<void>();
    const close = async () => {
      heldTurn.resolve();
      await browser.close();
    };
    page.on("worker", () => state.workers++);
    await page.addInitScript(() => localStorage.setItem("keepalive.host-name", "quiet-pine"));
    await page.clock.install({ time: state.now });
    await page.route("**/*", async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname.endsWith(".js") && url.origin !== host.origin) scripts.add(url.pathname);
      const json = (value: unknown) =>
        route.fulfill({
          status: 200,
          contentType: "application/json",
          headers: { "Access-Control-Allow-Origin": "*" },
          body: JSON.stringify(value),
        });
      if (route.request().method() === "OPTIONS") {
        await route.fulfill({
          status: 204,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "X-Keepalive-Ready, X-Keepalive-Release",
            "Access-Control-Allow-Methods": "GET, POST",
          },
        });
      } else if (url.pathname === "/__keepalive/release") await json(built.release);
      else if (url.pathname === "/__keepalive/audience") await route.fulfill({ status: 204 });
      else if (url.pathname === "/__keepalive/peers") {
        state.peers++;
        if (state.unavailable)
          await route.fulfill({ status: 503, headers: { "X-Keepalive-No-Reachable-Host": "1" } });
        else await json(new Gossip(built.release.id, host, state.now - 60_000).message(state.now));
      } else if (url.pathname === "/__keepalive/presence") {
        state.checkins++;
        if (state.unavailable || state.presenceFailure)
          await route.fulfill({ status: 503, headers: { "Access-Control-Allow-Origin": "*" } });
        else
          await json({
            host,
            startedAt: state.now - 60_000,
            tabs: 12,
            hosts: 2,
            saturated: false,
            fallback: [],
          });
      } else if (url.pathname === "/__keepalive/tree") {
        state.treeReads++;
        await json({
          hostRunID: host.runID,
          hosts: [{ ...host, name: "quiet-pine", left: false }],
        });
      } else if (url.pathname === "/__keepalive/wait")
        await json("00000000-0000-4000-8000-000000000001");
      else if (url.pathname === "/__keepalive/upload") {
        expect(route.request().postDataBuffer()?.length).toBe(UPLOAD_BYTES);
        state.uploads++;
        await route.fulfill({ status: 204, headers: { "Access-Control-Allow-Origin": "*" } });
      } else if (url.pathname === "/__keepalive/config") {
        await json({
          controlURL: "https://control.example.test",
          siteOrigin: "https://keepalive.example.test",
          startHost: "start.example.test",
        });
      } else if (url.pathname === "/__keepalive/certificate") {
        await route.fulfill({ status: 404, headers: { "Access-Control-Allow-Origin": "*" } });
      } else if (url.pathname === "/__keepalive/invitation") {
        state.released++;
        await route.fulfill({ status: 204, headers: { "Access-Control-Allow-Origin": "*" } });
      } else {
        const path =
          url.pathname === "/" ? "/index.html" : url.pathname.replace(ARTIFACT_PREFIX, "");
        if (path === built.turn && url.origin !== host.origin) {
          state.turnRequested = true;
          if (state.failTurn) {
            await route.fulfill({ status: 503 });
            return;
          }
          if (state.holdTurn) await heldTurn.promise;
        }
        if (path === built.tree && state.failTree) {
          await route.abort();
          return;
        }
        let body = built.files.get(path);
        if (body === undefined) {
          if (path !== "/favicon.svg") errors.push(`Unexpected request: ${url.href}`);
          await route.fulfill({ status: 404 });
          return;
        }
        if (url.origin === host.origin || url.pathname.startsWith(ARTIFACT_PREFIX)) {
          copied.add(path);
          if (path === state.corrupt) body = Buffer.alloc(body.length, 1);
        }
        if (url.pathname === "/" && options.bootstrap)
          body = Buffer.from(startPage(body.toString(), "keepalive.example.test"));
        await route.fulfill({
          body,
          headers: {
            ...siteHeaders(
              path.endsWith(".html")
                ? "text/html"
                : path.endsWith(".css")
                  ? "text/css"
                  : "text/javascript",
            ),
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
    });
    return {
      page,
      state,
      scripts,
      copied,
      errors,
      built,
      releaseTurn: () => heldTurn.resolve(),
      close,
      async advance(milliseconds: number) {
        state.now += milliseconds;
        await page.clock.runFor(milliseconds);
      },
      async open() {
        await page.goto("https://keepalive.example.test");
      },
    };
  } catch (error) {
    await browser.close();
    throw error;
  }
}

test("the production page checks in, expands hosts, volunteers and stops under CSP", async () => {
  const f = await fixture();
  try {
    await f.open();
    await f.page.getByRole("button", { name: "i'll keep it alive" }).waitFor();
    expect(f.state.checkins).toBe(1);
    expect(f.state.treeReads).toBe(0);
    expect(f.scripts).toEqual(f.built.initial);
    await f.page.getByText("hosts", { exact: true }).click();
    await f.page.getByText("quiet-pine", { exact: true }).waitFor();
    expect(f.state.treeReads).toBe(1);
    await f.page.getByText("hosts", { exact: true }).click();
    await f.advance(HEARTBEAT_MS / 2);
    expect(f.state.checkins).toBe(1);
    expect(f.state.treeReads).toBe(1);
    // renew even in a background tab; countdown ticks do not renew the query.
    await f.page.evaluate(() => {
      Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await f.advance(HEARTBEAT_MS / 2 + 1_000);
    await expect.poll(() => f.state.checkins).toBe(2);
    await f.page.getByRole("button", { name: "i'll keep it alive" }).click();
    await f.page.getByText("15:00 left in your turn").waitFor();
    await f.page.getByText("7 requests", { exact: true }).waitFor();
    expect(f.state.uploads).toBe(1);
    expect(f.copied).toEqual(new Set(f.built.files.keys()));
    expect(f.state.workers).toBe(1);
    await f.page.getByRole("button", { name: "sound: on" }).click();
    expect(
      await f.page.getByRole("button", { name: "sound: off" }).getAttribute("aria-pressed"),
    ).toBe("false");
    await f.advance(1_000);
    await f.page.getByText("14:59 left in your turn").waitFor();
    await f.page.getByRole("button", { name: "stop", exact: true }).click();
    await f.page.getByText("Thanks for hosting.", { exact: true }).waitFor();
    await f.page.getByText("7 requests handled").waitFor();
    await f.page.getByRole("button", { name: "volunteer again" }).waitFor();
    f.state.unavailable = true;
    await f.advance(HEARTBEAT_MS + 1_000);
    await f.page.getByText("No host is serving the site right now.").waitFor();
    expect(await f.page.locator(".experiment-age strong").innerText()).toBe("00h 00m 00s");
    expect(await f.page.getByRole("button", { name: "volunteer again" }).count()).toBe(0);
    expect(f.errors).toEqual([]);
  } finally {
    await f.close();
  }
});

test("stopping while the volunteer chunk loads never starts a late turn", async () => {
  const f = await fixture();
  try {
    f.state.holdTurn = true;
    await f.open();
    await f.page.getByRole("button", { name: "i'll keep it alive" }).click();
    await expect.poll(() => f.state.turnRequested).toBe(true);
    await f.page.getByRole("button", { name: "stop", exact: true }).click();
    await f.page.getByText("This tab stopped.", { exact: true }).waitFor();
    f.releaseTurn();
    await f.page.getByRole("button", { name: "i'll keep it alive" }).waitFor();
    // a second click may use the late module; only it can start a publisher.
    expect(f.state.workers).toBe(0);
    expect(f.state.released).toBe(0);
    expect(f.state.uploads).toBe(0);
    await f.page.getByRole("button", { name: "i'll keep it alive" }).click();
    await f.page.getByText("This tab is hosting.", { exact: true }).waitFor();
    expect(f.state.workers).toBe(1);
    await f.page.getByRole("button", { name: "stop", exact: true }).click();
    await f.page.getByText("Thanks for hosting.", { exact: true }).waitFor();
    expect(f.errors).toEqual([]);
  } finally {
    await f.close();
  }
});

test("a corrupt lazy chunk in a donor copy is rejected before starting the worker", async () => {
  const f = await fixture();
  try {
    f.state.corrupt = f.built.tree;
    await f.open();
    await f.page.getByRole("button", { name: "i'll keep it alive" }).click();
    await f.page.getByRole("button", { name: "try again" }).waitFor();
    expect(f.copied.has(f.built.tree)).toBe(true);
    expect(f.state.workers).toBe(0);
    expect(f.state.released).toBe(1);
    expect(f.errors).toEqual([]);
  } finally {
    await f.close();
  }
});

test("a failed tree chunk stays isolated from reading and volunteering", async () => {
  const f = await fixture();
  try {
    f.state.failTree = true;
    await f.open();
    await f.page.getByText("hosts", { exact: true }).click();
    await f.page.getByText("Couldn't load the host report.", { exact: false }).waitFor();
    await f.page.getByRole("button", { name: "i'll keep it alive" }).waitFor();
    expect(f.state.checkins).toBe(1);
    expect(f.state.uploads).toBe(0);
    expect(f.errors).toEqual([]);
    await f.page.getByText("hosts", { exact: true }).click();
    f.state.failTree = false;
    await f.page.getByText("hosts", { exact: true }).click();
    await f.page.getByText("quiet-pine", { exact: true }).waitFor();
  } finally {
    await f.close();
  }
});

test("a failed volunteer chunk can be retried without reloading the page", async () => {
  const f = await fixture();
  try {
    f.state.failTurn = true;
    await f.open();
    await f.page.getByRole("button", { name: "i'll keep it alive" }).click();
    await f.page.getByRole("button", { name: "try again" }).waitFor();
    expect(f.state.uploads).toBe(0);
    f.state.failTurn = false;
    await f.page.getByRole("button", { name: "try again" }).click();
    await f.page.getByText("This tab is hosting.", { exact: true }).waitFor();
    await f.page.getByRole("button", { name: "stop", exact: true }).click();
    await f.page.getByText("Thanks for hosting.", { exact: true }).waitFor();
    expect(f.errors).toEqual([]);
  } finally {
    await f.close();
  }
});

test("a missed check retains the clock and can recover without reloading", async () => {
  const f = await fixture();
  try {
    await f.open();
    await f.page.getByRole("button", { name: "i'll keep it alive" }).waitFor();
    f.state.presenceFailure = true;
    await f.advance(HEARTBEAT_MS + 1_000);
    await expect.poll(() => f.state.checkins).toBeGreaterThanOrEqual(2);
    await f.page.getByText("Checking for a host…", { exact: true }).waitFor();
    expect(await f.page.locator(".experiment-age strong").innerText()).not.toBe("00h 00m 00s");
    f.state.presenceFailure = false;
    await f.advance(13_000);
    await f.page.getByRole("button", { name: "i'll keep it alive" }).waitFor();
    expect(f.errors).toEqual([]);
  } finally {
    await f.close();
  }
});

test.each([false, true])(
  "the %s bootstrap variant remains readable without JavaScript",
  async (bootstrap) => {
    const f = await fixture({ bootstrap, javaScriptEnabled: false });
    try {
      await f.open();
      await f.page
        .getByRole("heading", { name: bootstrap ? "start keepalive" : "can we keep this alive?" })
        .waitFor();
      expect(await f.page.locator("#introduction").innerText()).toContain(
        bootstrap ? "up to one hour" : "served from people's browsers",
      );
      expect(f.scripts.size).toBe(0);
      expect(f.state.peers).toBe(0);
      expect(f.errors).toEqual([]);
    } finally {
      await f.close();
    }
  },
);

test("the bootstrap page starts without a donor and copies every pinned chunk", async () => {
  const f = await fixture({ bootstrap: true });
  try {
    await f.open();
    await f.page.getByRole("button", { name: "start hosting" }).click();
    await f.page.getByText("This tab is hosting.", { exact: true }).waitFor();
    expect(f.state.uploads).toBe(0);
    expect(f.copied).toEqual(new Set(f.built.files.keys()));
    expect(f.state.workers).toBe(1);
    await f.page.getByRole("button", { name: "stop", exact: true }).click();
    await f.page.getByText("No host is serving the site right now.", { exact: true }).waitFor();
    await f.page.getByText("7 requests handled", { exact: true }).waitFor();
    expect(f.errors).toEqual([]);
  } finally {
    await f.close();
  }
});
