import { expect, it, vi } from "vitest";
import { SHARED_HOST } from "../src/peers.ts";
import { createProxy } from "../src/proxy.ts";
import { WASM_PATH, WORKER_PATH, digest, parseRelease } from "../src/release.ts";

const script = "export const version = 1;";
const request = (path: string, init?: RequestInit) =>
  new Request(`https://keepthisalive.com${path}`, init);

async function setup() {
  const files = {
    "/index.html": "<h1>keepalive</h1>",
    "/app.js": script,
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
  return { fetchHost, proxy: createProxy(release, fetchHost) };
}

it("checks the script before serving it and does not pass through credentials", async () => {
  const { proxy, fetchHost } = await setup();
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
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  expect(fetchHost.mock.calls.map(([url]) => String(url))).toEqual([
    `${SHARED_HOST}/app.js`,
    `${SHARED_HOST}/app.js`,
    `${SHARED_HOST}/app.js`,
  ]);
  for (const [, init] of fetchHost.mock.calls) {
    expect(init?.credentials).toBe("omit");
    expect(init?.redirect).toBe("manual");
    expect(new Headers(init?.headers).has("Cookie")).toBe(false);
  }
});

it("has no fallback when hosts stop", async () => {
  const { proxy, fetchHost } = await setup();
  fetchHost.mockRejectedValue(new Error("No connection"));
  expect((await proxy.file(request("/"))).status).toBe(503);
  expect((await proxy.file(request(WORKER_PATH))).status).toBe(404);
  expect(fetchHost).toHaveBeenCalledTimes(3);
});
