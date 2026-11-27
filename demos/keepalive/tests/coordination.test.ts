import { expect, it } from "vitest";
import { simulateCoordination } from "./coordination.ts";

const settings = {
  hosts: 30,
  durationMs: 240_000,
  seed: 1,
  scenario: "growth" as const,
  latencyMs: 20,
  loss: 0,
};

it("replays actual bounded gossip deterministically over virtual JSON transport", async () => {
  const first = await simulateCoordination(settings);
  expect(await simulateCoordination(settings)).toEqual(first);
  expect(first.maximumMessageBytes).toBeLessThanOrEqual(24 * 1024);
  expect(first.failedRequests).toBe(0);
  expect(first.joins).toBe(30);
  expect(first.discoveryRequests).toBeGreaterThan(0);
  expect(first.samples.at(-1)).toMatchObject({
    online: 30,
    rosterCoverage: { p50: 1, p95: 1, p99: 1 },
    freshAudienceCoverage: { p50: 1 },
  });
});

it("records failed exchanges and stale views after an abrupt loss", async () => {
  const result = await simulateCoordination({ ...settings, scenario: "loss", durationMs: 360_000 });
  expect(result.abruptlyLost).toBe(8);
  expect(result.failedRequests).toBeGreaterThan(0);
  expect(result.samples.at(-1)?.online).toBe(22);
  expect(result.samples.some((sample) => (sample.staleHosts.p95 ?? 0) > 0)).toBe(true);
});

it("heals a partition without resetting service run identities", async () => {
  const result = await simulateCoordination({
    ...settings,
    scenario: "partition",
    durationMs: 480_000,
  });
  expect(result.failedRequests).toBeGreaterThan(0);
  expect(result.joins).toBe(settings.hosts);
  expect(result.samples.at(-1)?.rosterCoverage.p50).toBe(1);
});

it("uses normal turn lengths and real invitation decisions in turnover", async () => {
  const result = await simulateCoordination({
    ...settings,
    hosts: 10,
    scenario: "turnover",
    durationMs: 1_200_000,
  });
  expect(result.invitations).toBeGreaterThan(0);
  expect(result.joins).toBeGreaterThan(10);
  expect(result.departures).toBeGreaterThan(0);
  expect(result.earlyRetirements).toBeGreaterThan(0);
  expect(result.samples.at(-1)?.online).toBeGreaterThanOrEqual(3);
});

it("rejects unbounded or invalid settings", async () => {
  await expect(simulateCoordination({ ...settings, hosts: 1_001 })).rejects.toThrow(
    "invalid coordination settings",
  );
  await expect(simulateCoordination({ ...settings, loss: Number.NaN })).rejects.toThrow(
    "invalid coordination settings",
  );
});
