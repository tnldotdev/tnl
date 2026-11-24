import { expect, it, vi } from "vitest";
import { HOST_PARENT, PEERS_PATH, SHARED_HOST } from "../src/peers/gossip.ts";
import { createProxy } from "../src/edge/proxy.ts";
import { WASM_PATH, WORKER_PATH, digest, parseRelease } from "../src/release.ts";

const script = "export const version = 1;";
const fontPath = "/jetbrains-mono-latin-wght-normal.woff2";
const aliases = ["a", "b", "c"].map((letter) => `https://p-${letter.repeat(26)}.${HOST_PARENT}`);
const request = (path: string, init?: RequestInit) =>
  new Request(`https://keepthisalive.com${path}`, init);

async function setup() {
  const files = {
    "/index.html": "<h1>keepalive</h1>",
    "/app.js": script,
    [fontPath]: "wOF2",
    [WORKER_PATH]: "export {};",
    [WASM_PATH]: "fixture",
  };
  const encoder = new TextEncoder();
  const assets = await Promise.all(
    Object.entries(files).map(async ([path, content]) => {
      const bytes = encoder.encode(content);
      return { path, size: bytes.length, sha256: await digest(bytes) };
    }),
  );
  const release = await parseRelease({
    id: await digest(encoder.encode(JSON.stringify(assets))),
    assets,
  });
  const fetchHost = vi.fn<typeof fetch>();
  const report = (origins = aliases, forwardedAge = 0) => {
    const now = Date.now();
    const [from, ...changes] = origins.map((origin, index) => ({
      origin,
      publisherID: `pub_${String(index).repeat(22)}`,
      runID: `srun_${String(index).repeat(22)}`,
      runNumber: String(index + 1),
      seq: 1,
      reportedAt: now - (index === 0 ? 0 : forwardedAge),
      left: false,
      startingUntil: 0,
      endsAt: now + 120_000,
    }));
    return Response.json({ releaseID: release.id, startedAt: now, from, changes });
  };
  return { fetchHost, report, proxy: createProxy(release, fetchHost) };
}

it("serves the checked font with the font MIME type", async () => {
  const { proxy, fetchHost, report } = await setup();
  fetchHost.mockResolvedValueOnce(report(aliases.slice(0, 1)));
  fetchHost.mockResolvedValueOnce(new Response("wOF2"));

  const response = await proxy.file(request(fontPath));
  expect(response.status).toBe(200);
  expect(response.headers.get("Content-Type")).toBe("font/woff2");
  expect(await response.text()).toBe("wOF2");
});

it("checks the script before serving it and does not pass through credentials", async () => {
  const { proxy, fetchHost, report } = await setup();
  fetchHost.mockResolvedValueOnce(report());
  fetchHost.mockResolvedValueOnce(new Response("export const version = 2;"));
  fetchHost.mockResolvedValueOnce(
    new Response(script, {
      status: 302,
      headers: { Location: "https://other.example/app.js" },
    }),
  );
  fetchHost.mockResolvedValueOnce(new Response(script, { headers: { "Set-Cookie": "unsafe=1" } }));

  const response = await proxy.file(request("/app.js", { headers: { Cookie: "private=1" } }));
  expect(await response.text()).toBe(script);
  expect(response.headers.get("Set-Cookie")).toBeNull();
  expect(response.headers.get("Cache-Control")).toBe("no-store, no-transform");
  const [discovery, ...files] = fetchHost.mock.calls.map(([url]) => String(url));
  expect(discovery).toBe(`${SHARED_HOST}${PEERS_PATH}`);
  expect(files.sort()).toEqual(aliases.map((origin) => `${origin}/app.js`));
  for (const [, init] of fetchHost.mock.calls) {
    expect(init?.credentials).toBe("omit");
    expect(init?.redirect).toBe("manual");
    expect(new Headers(init?.headers).has("Cookie")).toBe(false);
  }
});

it("lets a peer check seed candidates and refreshes via a known alias", async () => {
  const { proxy, fetchHost, report } = await setup();
  fetchHost.mockResolvedValueOnce(report(aliases.slice(0, 1)));
  expect((await proxy.peers(request(PEERS_PATH))).status).toBe(200);
  fetchHost.mockResolvedValueOnce(report()).mockResolvedValueOnce(new Response(script));
  const tasks: Promise<void>[] = [];
  expect(
    (await proxy.file(request("/app.js"), SHARED_HOST, (work) => tasks.push(work))).status,
  ).toBe(200);
  await Promise.all(tasks);
  expect(fetchHost.mock.calls.map(([url]) => String(url))).toEqual([
    `${SHARED_HOST}${PEERS_PATH}`,
    `${aliases[0]}${PEERS_PATH}`,
    `${aliases[0]}/app.js`,
  ]);
  fetchHost.mockImplementation(async () => new Response(script));
  const responses = await Promise.all([
    proxy.file(request("/app.js")),
    proxy.file(request("/app.js")),
    proxy.file(request("/app.js")),
  ]);
  expect(responses.every((response) => response.status === 200)).toBe(true);
  expect(
    new Set(fetchHost.mock.calls.slice(3).map(([url]) => new URL(String(url)).origin)),
  ).toEqual(new Set(aliases));
});

it("uses the shared address only for discovery when hosts stop", async () => {
  const { proxy, fetchHost } = await setup();
  fetchHost.mockRejectedValue(new Error("No connection"));
  const response = await proxy.file(request("/"));
  expect(response.status).toBe(503);
  expect(response.body).toBeNull();
  expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
  expect(response.headers.get("Cache-Control")).toBe("no-store, no-transform");
  expect(response.headers.get("Location")).toBeNull();
  expect((await proxy.file(request(WORKER_PATH))).status).toBe(404);
  expect(fetchHost).toHaveBeenCalledExactlyOnceWith(
    new URL(PEERS_PATH, SHARED_HOST),
    expect.anything(),
  );
});

it("serves one recent audience observation to many tabs and expires it if refresh stalls", async () => {
  const { proxy, fetchHost, report } = await setup();
  vi.useFakeTimers();
  try {
    const msg = await report().json();
    fetchHost.mockResolvedValueOnce(
      Response.json({
        ...msg,
        audience: { hosts: 400, tabs: 20000, sampling: true, saturated: false },
      }),
    );
    await proxy.peers(request(PEERS_PATH));
    const refresh = Promise.withResolvers<Response>();
    fetchHost.mockReturnValueOnce(refresh.promise);
    const tasks: Promise<void>[] = [];
    const read = () => proxy.audience(request("/__keepalive/audience"), (work) => tasks.push(work));
    for (let i = 0; i < 10; i++)
      expect(await read().json()).toMatchObject({
        releaseID: msg.releaseID,
        tabs: 20000,
        sampling: true,
      });
    expect(fetchHost).toHaveBeenCalledTimes(2); // discovery and one refresh
    vi.setSystemTime(Date.now() + 61_000);
    expect(read().status).toBe(204);
    refresh.resolve(new Response(null, { status: 503 }));
    await Promise.all(tasks);
  } finally {
    vi.useRealTimers();
  }
});

it("rediscovers a live publisher before spending the last asset attempt on stale aliases", async () => {
  const { proxy, fetchHost, report } = await setup();
  fetchHost.mockResolvedValueOnce(report());
  expect((await proxy.peers(request(PEERS_PATH))).status).toBe(200);
  fetchHost.mockClear();
  const live = `https://p-${"d".repeat(26)}.${HOST_PARENT}`;
  fetchHost.mockImplementation(async (input) => {
    const url = new URL(String(input));
    if (url.href === SHARED_HOST + PEERS_PATH) return report([live]);
    if (url.origin === live && url.pathname === "/app.js") return new Response(script);
    throw new Error("publisher retired");
  });
  expect(await (await proxy.file(request("/app.js"))).text()).toBe(script);
  const calls = fetchHost.mock.calls.map(([url]) => String(url));
  expect(calls.slice(2)).toEqual([SHARED_HOST + PEERS_PATH, live + "/app.js"]);
  expect(new Set(calls.slice(0, 2)).size).toBe(2);
});

it("does not give an old forwarded alias a fresh lifetime", async () => {
  const { proxy, fetchHost, report } = await setup();
  fetchHost.mockResolvedValueOnce(report(aliases, 61_000));
  fetchHost.mockImplementation(async () => new Response(script));
  expect((await proxy.file(request("/app.js"))).status).toBe(200);
  expect(fetchHost.mock.calls.map(([url]) => String(url))).toEqual([
    `${SHARED_HOST}${PEERS_PATH}`,
    `${aliases[0]}/app.js`,
  ]);
});

it("switches away from a host silent before headers and lets the next body finish", async () => {
  const { proxy, fetchHost, report } = await setup();
  vi.useFakeTimers();
  try {
    fetchHost.mockResolvedValueOnce(report());
    fetchHost.mockImplementationOnce(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("no headers")), {
            once: true,
          });
        }),
    );
    let bodySignal: AbortSignal | null | undefined;
    fetchHost.mockImplementationOnce(async (_input, init) => {
      bodySignal = init?.signal;
      return new Response(
        new ReadableStream({
          start(controller) {
            setTimeout(() => {
              controller.enqueue(new TextEncoder().encode(script));
              controller.close();
            }, 1500);
          },
        }),
      );
    });
    const result = proxy.file(request("/app.js"));
    await vi.advanceTimersByTimeAsync(999);
    expect(fetchHost).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchHost).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(1500);
    expect(await (await result).text()).toBe(script);
    expect(bodySignal?.aborted).toBe(false);
  } finally {
    vi.useRealTimers();
  }
});

it("keeps the original header budget for a sole publisher", async () => {
  const { proxy, fetchHost, report } = await setup();
  vi.useFakeTimers();
  try {
    fetchHost.mockResolvedValueOnce(report(aliases.slice(0, 1)));
    fetchHost.mockImplementationOnce(async (_input, init) => {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      init?.signal?.throwIfAborted();
      return new Response(script);
    });
    const result = proxy.file(request("/app.js"));
    await vi.advanceTimersByTimeAsync(1500);
    expect(await (await result).text()).toBe(script);
    expect(fetchHost).toHaveBeenCalledTimes(2);
  } finally {
    vi.useRealTimers();
  }
});
