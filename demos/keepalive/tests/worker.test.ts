import { afterEach, expect, test, vi } from "vitest";
import { CONFIG_PATH } from "../src/enrollment.ts";
import { RELEASE_PATH } from "../src/release.ts";

const release = { id: "a".repeat(64), assets: [] };
const env = {
  SITE_ORIGIN: "https://keepthisalive.com",
  START_HOST: "start.keepthisalive.com",
  CONTROL_URL: "https://control.tnl.dev",
  TEAM_ID: "",
  PROJECT_KEY: "",
  DEPLOYMENT_ID: "",
  ASSETS: { fetch: vi.fn<typeof fetch>() },
};

async function worker() {
  vi.stubGlobal("KEEPALIVE_RELEASE", release);
  return (await import("../src/edge/worker.ts")).default;
}

afterEach(() => vi.unstubAllGlobals());

test.each([
  ["keepthisalive.com", "GET", "/index.html?test=1&next=%2Ffoo"],
  ["start.keepthisalive.com", "POST", `${CONFIG_PATH}?test=1`],
] as const)("redirects HTTP on %s before serving the route", async (host, method, path) => {
  const app = await worker();
  const response = await app.request(`http://${host}${path}`, { method }, env);
  expect(response.status).toBe(308);
  expect(response.headers.get("location")).toBe(`https://${host}${path}`);
  expect(env.ASSETS.fetch).not.toHaveBeenCalled();
});

test.each([
  "https://keepthisalive.com",
  "https://start.keepthisalive.com",
  "http://localhost:8787",
])("keeps normal route handling at %s", async (origin) => {
  const app = await worker();
  const response = await app.request(origin + RELEASE_PATH, undefined, env);
  expect(response.status).toBe(200);
  expect(response.headers.get("location")).toBeNull();
  expect(await response.json()).toEqual(release);
});
