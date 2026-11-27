import { expect, it } from "vitest";
import {
  MAX_TABS_PER_HOST,
  SAMPLE_WEIGHT,
  TAB_LEASE_MS,
  TabLeases,
  sampledTab,
} from "../src/peers/presence.ts";
import { seededRandom } from "./coordination.ts";
import { capacityTarget } from "./recruitment.ts";

it("places 25000 real lease records with headroom and expires silent readers", () => {
  const readers = 25_000;
  const hosts = capacityTarget({
    readerBytesPerSecond: 0,
    safeBytesPerSecondPerHost: 1,
    countedReaderLeases: readers,
  });
  expect(hosts).toBe(98);
  const random = seededRandom(1);
  const leases = Array.from({ length: hosts }, () => new TabLeases());
  for (let i = 0; i < readers; i++) {
    const host = leases[Math.floor(random() * hosts)];
    const tab = `00000000-0000-4000-8000-${i.toString(16).padStart(12, "0")}`;
    expect(host?.touch(tab, 0)).toBe(true);
    // retries refresh the same record rather than creating extra demand.
    expect(host?.touch(tab, 1)).toBe(true);
  }
  const counts = leases.map((host) => host.count(1));
  expect(counts.reduce((a, b) => a + b, 0)).toBe(readers);
  expect(Math.max(...counts)).toBeLessThan(MAX_TABS_PER_HOST);
  expect(leases.reduce((total, host) => total + host.count(TAB_LEASE_MS + 1), 0)).toBe(0);
});

it("tracks a stable one-in-four sample without treating weighted estimates as actual records", () => {
  const readers = 25_000;
  const hosts = 25;
  const random = seededRandom(3);
  const leases = Array.from({ length: hosts }, () => new TabLeases());
  let sampled = 0;
  for (let i = 0; i < readers; i++) {
    const tab = `00000000-0000-4000-8000-${i.toString(16).padStart(12, "0")}`;
    if (!sampledTab(tab)) continue;
    sampled++;
    expect(leases[Math.floor(random() * hosts)]?.touch(tab, 0)).toBe(true);
  }
  expect(sampled).toBe(readers / SAMPLE_WEIGHT);
  expect(leases.reduce((sum, host) => sum + host.count(0), 0)).toBe(sampled);
  expect(leases.reduce((sum, host) => sum + host.count(0, true), 0)).toBe(readers);
  expect(Math.max(...leases.map((host) => host.count(0)))).toBeLessThan(MAX_TABS_PER_HOST);
});
