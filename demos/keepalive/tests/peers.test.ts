import { expect, it } from "vitest";
import { Gossip, KEEP_MS, SUSPECT_MS, parseMessage, type Change } from "../src/peers/gossip.ts";
import { HOST_PARENT } from "../src/peers/host.ts";
import { MAX_CHANGES, MAX_MESSAGE_BYTES, MAX_PEERS } from "../src/peers/report.ts";

const now = Date.UTC(2026, 10, 19);
const release = "a".repeat(64);
function report(n: number, details: Partial<Change> = {}): Change {
  const id = String(n).padStart(22, "0");
  return {
    origin: `https://p-${n.toString(2).replaceAll("0", "a").replaceAll("1", "b").padStart(26, "a")}.${HOST_PARENT}`,
    publisherID: `pub_${id}`,
    runID: `srun_${id}`,
    runNumber: String(n),
    seq: 1,
    reportedAt: now,
    left: false,
    startingUntil: 0,
    ...details,
  };
}
const message = (from: Change, ...changes: Change[]) => ({
  releaseID: release,
  startedAt: now,
  from,
  changes,
});
const fill = (view: Gossip, count: number, first = 2) => {
  for (let i = first; i < first + count; i++) view.receive(message(report(i)), now);
};
const certificate = (fingerprint: string, expiresAt = now + 60_000) => ({
  fingerprint: fingerprint.repeat(64),
  expiresAt,
});

it("bounds a full exchange and rejects unrelated or unsafe messages", () => {
  const max = Number.MAX_SAFE_INTEGER;
  const full = (n: number) =>
    report(n, {
      seq: max,
      reportedAt: max,
      runNumber: "9223372036854775807",
      name: "silver-stone",
      startingUntil: max,
      endsAt: max,
      departing: false,
      tabs: { count: 2048, observedAt: max },
      copyFrom: report(1).runID,
      certificate: certificate("f", max),
    });
  const view = new Gossip(release, report(1), max, full(1));
  for (let i = 2; i < MAX_CHANGES + 2; i++) view.receive(message(full(i)), max);
  const batch = {
    ...view.message(max),
    audience: { tabs: 16_779_264, hosts: MAX_PEERS + 1, saturated: false, sampling: true },
  };
  expect(batch.changes).toHaveLength(MAX_CHANGES);
  expect(
    new TextEncoder().encode(JSON.stringify({ target: report(2), message: batch })).length,
  ).toBeLessThanOrEqual(MAX_MESSAGE_BYTES);
  expect(parseMessage(batch, release, max)).toBeDefined();
  expect(parseMessage(batch, "b".repeat(64), max)).toBeUndefined();
  expect(
    parseMessage({ ...batch, from: { ...batch.from, origin: "https://other.test" } }, release, max),
  ).toBeUndefined();
  expect(
    parseMessage({ ...batch, changes: Array(MAX_CHANGES + 1).fill(batch.from) }, release, max),
  ).toBeUndefined();
});

it("bounds membership and reclaims expired records before admitting new hosts", () => {
  const view = new Gossip(release, report(1), now);
  fill(view, MAX_PEERS);
  view.receive(message(report(MAX_PEERS + 2)), now);
  expect(view.size).toBe(MAX_PEERS);
  expect(view.saturated(now)).toBe(true);
  const later = now + KEEP_MS;
  view.receive(
    { ...message(report(MAX_PEERS + 2, { reportedAt: later })), startedAt: later },
    later,
  );
  expect(view.hosts(later)).toHaveLength(1);
  expect(view.size).toBe(1);
});

it("keeps a thousand-host roster while sending only bounded peer samples", () => {
  const view = new Gossip(release, report(1), now);
  fill(view, 999);
  expect(view.hosts(now)).toHaveLength(999);
  for (let i = 0; i < 100; i++) {
    const batch = view.message(now + i);
    expect(batch.changes.length).toBeLessThanOrEqual(MAX_CHANGES);
    expect(new TextEncoder().encode(JSON.stringify(batch)).byteLength).toBeLessThanOrEqual(
      MAX_MESSAGE_BYTES,
    );
  }
});

it("uses an indirect probe and recovers a suspended host without losing other hosts", async () => {
  const view = new Gossip(release, report(1), now);
  const remote = new Gossip(release, report(2), now);
  view.receive(remote.message(now), now);
  view.receive(message(report(3)), now);
  const later = now + 61_000;
  expect(view.hosts(later)).toHaveLength(2);
  let indirect = false;
  await view.probe(
    () => later,
    () => 0,
    async (_, request, helper) => {
      if (helper === undefined) return undefined;
      indirect = true;
      remote.receive(request, later);
      return remote.message(later, request);
    },
  );
  expect(indirect).toBe(true);
  await view.probe(
    () => later,
    () => 0,
    async () => undefined,
  );
  expect(view.hosts(later + SUSPECT_MS).map(({ runID }) => runID)).toEqual([report(3).runID]);
  await view.probe(
    () => later + SUSPECT_MS,
    () => 0,
    async () => remote.message(later + SUSPECT_MS),
  );
  expect(view.hosts(later + SUSPECT_MS)).toHaveLength(2);
});

it("does not revive a stopped or replaced service run from a delayed report", () => {
  const view = new Gossip(release, report(1), now);
  const old = report(2);
  view.receive(message(old), now);
  view.receive(message({ ...old, seq: 2, left: true }), now);
  view.receive(message(old), now);
  expect(view.hosts(now)).toEqual([]);
  const replacement = { ...old, runID: report(3).runID, runNumber: "3" };
  view.receive(message(replacement), now);
  view.receive(message(old), now);
  expect(view.hosts(now)).toEqual([replacement]);
});

it("prioritizes a new stop and spends reply slots on information the requester lacks", () => {
  const view = new Gossip(release, report(1), now);
  fill(view, MAX_CHANGES * 3);
  view.message(now);
  const stop = report(2, { seq: 2, left: true });
  view.receive(message(stop), now);
  const filtered = view.message(now, message(stop));
  expect(filtered.changes).toHaveLength(MAX_CHANGES);
  expect(filtered.changes).not.toContainEqual(stop);
  const reply = view.message(now, message(report(2)));
  expect(reply.changes[0]).toEqual(stop);
  expect(new Set(reply.changes.map(({ publisherID }) => publisherID)).size).toBe(MAX_CHANGES);
});

it("advertises a newer certificate holder and switches donors when that host stops", () => {
  const view = new Gossip(release, report(1), now, { certificate: certificate("f") });
  fill(view, MAX_CHANGES * 2);
  const best = report(9_000, { certificate: certificate("a") });
  const fallback = report(9_001, { certificate: certificate("b") });
  view.receive(message(best, fallback), now);
  fill(view, MAX_CHANGES, 300);
  expect(view.message(now).changes).toContainEqual(best);
  view.receive(message({ ...best, seq: 2, left: true }), now);
  expect(view.message(now).changes).toContainEqual(fallback);
});
