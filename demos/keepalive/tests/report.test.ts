import { expect, it, vi } from "vitest";
import { Gossip, parseMessage } from "../src/peers/gossip.ts";
import { HOST_PARENT, type Host } from "../src/peers/host.ts";
import { readReport, MAX_CHANGES } from "../src/peers/report.ts";

const release = "a".repeat(64);
const host: Host = {
  origin: `https://p-${"a".repeat(26)}.${HOST_PARENT}`,
  publisherID: `pub_${"a".repeat(22)}`,
  runID: `srun_${"a".repeat(22)}`,
  runNumber: "1",
};
function reply(body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => Response.json(body)),
  );
}

it("readers validate selection facts without trusting or retaining hosting-only details", async () => {
  const now = Date.now();
  const report = new Gossip(release, host, now, {
    name: "quiet-pine",
    endsAt: now + 60_000,
  }).message(now);
  reply(report);
  expect(
    await readReport("https://keepthisalive.com", release, new AbortController().signal),
  ).toMatchObject({ from: host, releaseID: release });
  const unusedInvalidName = {
    ...report,
    from: { ...report.from, name: "not-an-accepted-host-name" },
  };
  expect(parseMessage(unusedInvalidName, release, now)).toBeUndefined();
  reply(unusedInvalidName);
  const selected = await readReport(
    "https://keepthisalive.com",
    release,
    new AbortController().signal,
  );
  expect(selected?.from).not.toHaveProperty("name");
  expect(selected?.from).not.toHaveProperty("certificate");
});

it.each([
  { origin: "https://other.example.test" },
  { origin: `https://p-${"a".repeat(26)}.${HOST_PARENT}:444` },
  { publisherID: "pub_bad" },
  { runID: "srun_bad" },
  { runNumber: "9223372036854775808" },
  { seq: Number.MAX_SAFE_INTEGER + 1 },
  { reportedAt: Date.now() + 31_000 },
  { startingUntil: Date.now() + 4 * 60_000 },
  { endsAt: Date.now() + 2 * 60 * 60_000 },
])("rejects unsafe selection facts: %j", async (change) => {
  const report = new Gossip(release, host, Date.now()).message(Date.now());
  reply({ ...report, from: { ...report.from, ...change } });
  expect(
    await readReport("https://keepthisalive.com", release, new AbortController().signal),
  ).toBeUndefined();
});

it("retains release, clock and list bounds for reader discovery", async () => {
  const report = new Gossip(release, host, Date.now()).message(Date.now());
  for (const invalid of [
    { ...report, releaseID: "b".repeat(64) },
    { ...report, startedAt: Date.now() + 31_000 },
    { ...report, changes: Array(MAX_CHANGES + 1).fill(report.from) },
    { ...report, unexpected: true },
  ]) {
    reply(invalid);
    expect(
      await readReport("https://keepthisalive.com", release, new AbortController().signal),
    ).toBeUndefined();
  }
});
