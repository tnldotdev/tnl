import { afterEach, expect, it, vi } from "vitest";
import { credentials } from "../src/edge/credentials.ts";
import { READY_HEADER } from "../src/enrollment.ts";
import { HOST_PARENT } from "../src/peers/gossip.ts";

const mint = vi.hoisted(() => vi.fn());
vi.mock("@tnldotdev/tnl/control", () => ({ control: () => ({}), createPublisherEnrollment: mint }));
const release = "a".repeat(64);
const env = {
  CONTROL_URL: "https://control.test",
  START_HOST: "start.test",
  PROJECT_KEY: "project",
  TEAM_ID: "team",
  MANAGEMENT_TOKEN: "fixture",
};
const requestID = crypto.randomUUID();
const donor = `https://p-${"a".repeat(26)}.${HOST_PARENT}`;
const call = (origin: string, bootstrap: boolean, peers = vi.fn(), inviter = donor) =>
  credentials(
    new Request(origin, {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({
        releaseID: release,
        requestID,
        bootstrap,
        ...(bootstrap ? {} : { inviter }),
      }),
    }),
    release,
    env,
    peers,
  );
afterEach(() => {
  vi.unstubAllGlobals();
  mint.mockReset();
});

it("checks a live invitation before minting and reuses its control idempotency key", async () => {
  const check = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(null, { status: 403 }))
    .mockImplementation(async () => new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", check);
  expect((await call("https://site.test", false, undefined, "https://other.test")).status).toBe(
    400,
  );
  expect(check).not.toHaveBeenCalled();
  expect((await call("https://site.test", false)).status).toBe(403);
  expect(mint).not.toHaveBeenCalled();
  mint.mockResolvedValue({ response: { status: 201 }, data: { enrollment_key: "fixture" } });
  for (let i = 0; i < 2; i++) expect((await call("https://site.test", false)).status).toBe(200);
  for (const [, init] of check.mock.calls)
    expect(new Headers(init?.headers).get(READY_HEADER)).toBe(requestID);
  for (const [options] of mint.mock.calls)
    expect(options).toMatchObject({
      headers: { "Idempotency-Key": requestID },
      body: { services: ["production"], max_members: 1, expires_in: 180 },
    });
});

it("only the restart site can seed, and only when no publisher answers", async () => {
  const peers = vi
    .fn()
    .mockResolvedValueOnce(new Response("alive"))
    .mockResolvedValueOnce(new Response(null, { status: 503 }));
  expect((await call("https://site.test", true, peers)).status).toBe(403);
  expect((await call("https://start.test", true, peers)).status).toBe(403);
  expect(mint).not.toHaveBeenCalled();
  mint.mockResolvedValue({ response: { status: 201 }, data: { enrollment_key: "seed" } });
  expect((await call("https://start.test", true, peers)).status).toBe(200);
});
