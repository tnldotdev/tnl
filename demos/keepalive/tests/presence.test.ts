import { expect, it } from "vitest";
import { hostTarget, REPLACE_BEFORE_MS, turnLength } from "../src/policy.ts";
import { Gossip, HOST_PARENT, reportedTabs, type Host } from "../src/peers/gossip.ts";
import { MAX_TABS_PER_HOST, TAB_LEASE_MS, TabLeases } from "../src/peers/presence.ts";

const now = Date.UTC(2026, 10, 19);
const releaseID = "a".repeat(64);

function host(label: "a" | "b" | "c", run: number): Host {
  return {
    origin: `https://p-${label.repeat(26)}.${HOST_PARENT}`,
    publisherID: `pub_${label.repeat(22)}`,
    runID: `srun_${String(run).padStart(22, "0")}`,
    runNumber: String(run),
  };
}

it("refreshes a single tab lease, bounds memory and expires silent tabs", () => {
  const leases = new TabLeases();
  for (let n = 0; n < MAX_TABS_PER_HOST; n++) expect(leases.touch(`${n}`, now)).toBe(true);
  expect(leases.touch("overflow", now)).toBe(false);
  expect(leases.touch("0", now + 1000)).toBe(true);
  expect(leases.count(now + TAB_LEASE_MS)).toBe(1);
  expect(leases.count(now + TAB_LEASE_MS + 1000)).toBe(0);
});

it("sums fresh reports once and does not replace a tally with an old service run", () => {
  const a = new Gossip(releaseID, host("a", 1), now);
  const b = new Gossip(releaseID, host("b", 2), now);
  const newer = new Gossip(releaseID, host("b", 3), now + 1000);
  a.observeTabs(101, now);
  b.observeTabs(150, now);
  newer.observeTabs(49, now + 1000);
  const oldReport = b.message(now);
  const newReport = newer.message(now + 1000);
  a.receive(oldReport, now);
  expect(a.tabSnapshot(now)).toEqual({ local: 101, total: 251 });
  expect(hostTarget(a.tabs(now))).toBe(6);
  a.receive(newReport, now + 1000);
  a.receive(oldReport, now + 1000);
  expect(hostTarget(a.tabs(now + 1000))).toBe(3);
  expect(a.tabSnapshot(now + 1000)).toEqual({ local: 101, total: 150 });
  expect(reportedTabs([newReport.from, newReport.from], now + 1000)).toBe(49);
  expect(a.tabs(now + TAB_LEASE_MS)).toBe(49);
  expect(a.tabSnapshot(now + TAB_LEASE_MS)).toEqual({ local: 0, total: 49 });
  expect(a.tabs(now + TAB_LEASE_MS + 1000)).toBe(0);
  a.observeTabs(25, now + TAB_LEASE_MS + 1000);
  expect(a.tabSnapshot(now + TAB_LEASE_MS + 1000)).toEqual({ local: 25, total: 25 });
  expect(hostTarget(1651)).toBe(34);
});

it("keeps capacity for expiring turns but does not replace surplus hosts", () => {
  expect(turnLength(false)).toBe(10 * 60_000);
  expect(turnLength(true)).toBe(60 * 60_000);
  const a = new Gossip(releaseID, host("a", 1), now, { endsAt: now + REPLACE_BEFORE_MS });
  const b = new Gossip(releaseID, host("b", 2), now);
  const c = new Gossip(releaseID, host("c", 3), now);
  a.receive(b.message(now), now);
  a.receive(c.message(now), now);
  expect(a.readyBeyondWindow(now)).toBe(2);
  expect(a.maybeStart(now, 2, () => true)).toBe(false);
  expect(a.maybeStart(now, 3, () => true)).toBe(true);
});
