import { afterEach, expect, it, vi } from "vitest";
import { observeVisitors, renewPresence } from "../src/page/visitor.ts";
import { digest, RELEASE_PATH, WASM_PATH, WORKER_PATH } from "../src/release.ts";
import { REPLACE_BEFORE_MS, STARTUP_MS } from "../src/policy.ts";
import {
  FRESH_REPORT_MS,
  Gossip,
  HOST_PARENT,
  PEERS_PATH,
  reportedTabs,
  type Host,
} from "../src/peers/gossip.ts";
import {
  MAX_TABS_PER_HOST,
  AUDIENCE_PATH,
  HEARTBEAT_MS,
  PRESENCE_PATH,
  REMOTE_TAB_REPORT_MS,
  TAB_LEASE_MS,
  TabLeases,
} from "../src/peers/presence.ts";

const now = Date.UTC(2026, 10, 19);
const releaseID = "a".repeat(64);
const tab = "0336c461-0342-45ba-865e-b813ec381839";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

async function fixtureRelease() {
  const assets = ["/index.html", WORKER_PATH, WASM_PATH].map((path) => ({
    path,
    size: 1,
    sha256: "a".repeat(64),
  }));
  return { id: await digest(new TextEncoder().encode(JSON.stringify(assets))), assets };
}

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

it("recovers a lost presence reply without counting the tab twice", async () => {
  const h = host("a", 1);
  const leases = new TabLeases();
  const send = vi.fn<typeof fetch>(async (url, init) => {
    expect(String(url)).toBe(`${h.origin}/__keepalive/presence`);
    expect(init?.body).toBe(JSON.stringify({ tab, releaseID }));
    expect(leases.touch(tab, now)).toBe(true);
    if (send.mock.calls.length === 1) throw new TypeError("lost response headers");
    return Response.json({
      host: h,
      startedAt: now,
      tabs: leases.count(now),
      hosts: 1,
      saturated: false,
      fallback: [],
    });
  });
  vi.stubGlobal("fetch", send);
  const observed = await renewPresence(h, tab, releaseID, new AbortController().signal);
  expect(observed.tabs).toBe(1);
  expect(send).toHaveBeenCalledTimes(2);
  expect(send.mock.calls[1]?.[1]?.signal).toBe(send.mock.calls[0]?.[1]?.signal);
});

it("a held-out visitor reads the edge estimate and resumes reporting on the first small snapshot", async () => {
  const h = host("a", 1);
  const { id, assets } = await fixtureRelease();
  const reported = {
    host: h,
    startedAt: now,
    tabs: 20000,
    hosts: 400,
    saturated: false,
    sampling: true,
  };
  const sent: string[] = [];
  vi.useFakeTimers({ now });
  vi.spyOn(crypto, "randomUUID").mockReturnValue(tab);
  vi.stubGlobal("location", { origin: "https://keepthisalive.com" });
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(input), "https://keepthisalive.com").pathname;
    if (path === RELEASE_PATH) return Response.json({ id, assets });
    if (path === AUDIENCE_PATH) return Response.json({ ...reported, releaseID: id });
    if (path === PRESENCE_PATH) {
      sent.push(String(init?.body));
      return Response.json({ ...reported, fallback: [] });
    }
    return Response.json({
      releaseID: id,
      startedAt: now,
      from: { ...h, seq: 1, reportedAt: Date.now(), left: false, startingUntil: 0 },
      changes: [],
    });
  });
  const owner = new AbortController(),
    update = vi.fn();
  try {
    await observeVisitors(owner.signal, update);
    expect(update).toHaveBeenLastCalledWith(expect.objectContaining({ tabs: 20000 }));
    await vi.advanceTimersByTimeAsync(HEARTBEAT_MS);
    expect(sent).toEqual([]);
    Object.assign(reported, { tabs: 300, hosts: 6, sampling: false });
    await vi.advanceTimersByTimeAsync(HEARTBEAT_MS);
    expect(sent).toEqual([JSON.stringify({ tab, releaseID: id })]);
    expect(update).toHaveBeenLastCalledWith(expect.objectContaining({ tabs: 300 }));
    owner.abort();
    await vi.advanceTimersByTimeAsync(HEARTBEAT_MS);
    expect(sent).toHaveLength(1);
  } finally {
    owner.abort();
    vi.useRealTimers();
  }
});

it("does not try an old host that still appears in the peer report", async () => {
  vi.useFakeTimers({ now });
  vi.spyOn(Math, "random").mockReturnValue(0.99);
  const site = "https://keepthisalive.com";
  const release = await fixtureRelease();
  const a = new Gossip(release.id, host("a", 1), now - FRESH_REPORT_MS);
  const b = new Gossip(release.id, host("b", 2), now);
  b.receive(a.message(now - FRESH_REPORT_MS), now);
  const message = b.message(now);
  expect(message.changes).toHaveLength(1);
  vi.stubGlobal("location", { origin: site });
  const fetch = vi.fn<typeof globalThis.fetch>(async (input) => {
    const url = new URL(String(input), site);
    if (url.pathname === RELEASE_PATH) return Response.json(release);
    if (url.pathname === AUDIENCE_PATH) return new Response(null, { status: 204 });
    if (url.pathname === PEERS_PATH) return Response.json(message);
    expect(url.href).toBe(b.self.origin + PRESENCE_PATH);
    return Response.json({
      host: b.self,
      startedAt: now,
      tabs: 1,
      hosts: 1,
      saturated: false,
      fallback: [],
    });
  });
  vi.stubGlobal("fetch", fetch);
  const owner = new AbortController();
  const update = vi.fn();
  try {
    await observeVisitors(owner.signal, update);
    expect(update).toHaveBeenLastCalledWith(expect.objectContaining({ host: b.self }));
    expect(fetch.mock.calls.some(([url]) => String(url) === a.self.origin + PRESENCE_PATH)).toBe(
      false,
    );
  } finally {
    owner.abort();
  }
});

it.each([true, false])(
  "moves presence to the replacement in the same heartbeat (known fallback: %s)",
  async (hasFallback) => {
    const release = await fixtureRelease();
    const site = "https://keepthisalive.com";
    const a = new Gossip(release.id, host("a", 1), now);
    const b = new Gossip(release.id, host("b", 2), now);
    vi.useFakeTimers({ now });
    vi.stubGlobal("location", { origin: site });
    vi.spyOn(crypto, "randomUUID").mockReturnValue(tab);
    const beats: Array<[string, number]> = [];
    let replaced = false;
    let discoveries = 0;
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), site);
      if (url.pathname === RELEASE_PATH) return Response.json(release);
      if (url.pathname === AUDIENCE_PATH) return new Response(null, { status: 204 });
      if (url.pathname === PEERS_PATH) {
        discoveries++;
        return Response.json((replaced ? b : a).message(Date.now()));
      }
      expect(url.pathname).toBe(PRESENCE_PATH);
      expect(init?.body).toBe(JSON.stringify({ tab, releaseID: release.id }));
      beats.push([url.origin, Date.now()]);
      if (url.origin === a.self.origin && replaced) return new Response(null, { status: 503 });
      return Response.json({
        host: (replaced ? b : a).self,
        startedAt: now,
        tabs: 1,
        hosts: 1,
        saturated: false,
        fallback: hasFallback && !replaced ? [b.self] : [],
      });
    });
    const owner = new AbortController();
    const update = vi.fn();
    try {
      await observeVisitors(owner.signal, update);
      expect(update).toHaveBeenLastCalledWith(expect.objectContaining({ host: a.self }));
      replaced = true;
      await vi.advanceTimersByTimeAsync(HEARTBEAT_MS);
      expect(beats).toEqual([
        [a.self.origin, now],
        [a.self.origin, now + HEARTBEAT_MS],
        [b.self.origin, now + HEARTBEAT_MS],
      ]);
      expect(discoveries).toBe(hasFallback ? 1 : 2);
      expect(update).toHaveBeenCalledTimes(2);
      expect(update).toHaveBeenLastCalledWith(expect.objectContaining({ host: b.self }));
    } finally {
      owner.abort();
    }
  },
);

it("does not retry a refusal, changed run, or canceled presence request", async () => {
  for (const outcome of ["refused", "changed", "canceled"]) {
    const owner = new AbortController();
    const send = vi.fn(async () => {
      if (outcome === "refused") return new Response("unavailable", { status: 503 });
      if (outcome === "canceled") {
        owner.abort();
        throw new TypeError("connection closed");
      }
      return Response.json({
        host: host("a", 2),
        startedAt: now,
        tabs: 1,
        hosts: 1,
        saturated: false,
        fallback: [],
      });
    });
    vi.stubGlobal("fetch", send);
    await expect(renewPresence(host("a", 1), tab, releaseID, owner.signal)).rejects.toThrow();
    expect(send).toHaveBeenCalledTimes(1);
  }
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
  a.receive(newReport, now + 1000);
  a.receive(oldReport, now + 1000);
  expect(a.tabSnapshot(now + 1000)).toEqual({ local: 101, total: 150 });
  expect(reportedTabs([newReport.from, newReport.from], now + 1000)).toBe(49);
  expect(a.tabs(now + FRESH_REPORT_MS)).toBe(49);
  expect(a.tabSnapshot(now + FRESH_REPORT_MS)).toEqual({ local: 0, total: 49 });
  expect(a.tabs(now + FRESH_REPORT_MS + 1000)).toBe(49);
  expect(a.tabs(now + REMOTE_TAB_REPORT_MS + 999)).toBe(49);
  expect(a.tabs(now + REMOTE_TAB_REPORT_MS + 1000)).toBe(0);
  a.observeTabs(25, now + REMOTE_TAB_REPORT_MS + 1000);
  expect(a.tabSnapshot(now + REMOTE_TAB_REPORT_MS + 1000)).toEqual({ local: 25, total: 25 });
});

it("does not retain a remote tally after its host stops or its turn ends", () => {
  const a = new Gossip(releaseID, host("a", 1), now);
  const b = new Gossip(releaseID, host("b", 2), now);
  const c = new Gossip(releaseID, host("c", 3), now, { endsAt: now + TAB_LEASE_MS + 1_000 });
  b.observeTabs(13, now);
  c.observeTabs(27, now);
  a.receive(b.message(now), now);
  a.receive(c.message(now), now);
  expect(a.tabs(now + TAB_LEASE_MS)).toBe(40);
  a.receive(b.leave(now + TAB_LEASE_MS), now + TAB_LEASE_MS);
  expect(a.tabs(now + TAB_LEASE_MS)).toBe(27);
  expect(a.tabs(now + TAB_LEASE_MS + 1_000)).toBe(0);
});

it("keeps capacity for expiring turns but does not replace surplus hosts", () => {
  const a = new Gossip(releaseID, host("a", 1), now, { endsAt: now + REPLACE_BEFORE_MS });
  const b = new Gossip(releaseID, host("b", 2), now);
  const c = new Gossip(releaseID, host("c", 3), now);
  a.receive(b.message(now), now);
  a.receive(c.message(now), now);
  expect(a.readyBeyondWindow(now)).toBe(2);
  expect(a.canRetire(now, 2, a.hosts(now))).toBe(false);
  b.observeTabs(20, now);
  c.observeTabs(30, now);
  a.receive(b.message(now), now);
  a.receive(c.message(now), now);
  expect(a.canRetire(now, 2, a.hosts(now))).toBe(true);
  expect(a.tabs(now + TAB_LEASE_MS)).toBe(50);
  expect(a.canRetire(now + FRESH_REPORT_MS, 2, a.hosts(now + FRESH_REPORT_MS))).toBe(false);
  expect(a.canRetire(now, 3, a.hosts(now))).toBe(false);
  expect(a.maybeStart(now, 2, () => true)).toBe(false);
  expect(a.maybeStart(now, 3, () => true)).toBe(true);
  expect(a.maybeStart(now, 3, () => true)).toBe(false);
  b.receive(a.message(now), now);
  expect(b.maybeStart(now, 3, () => true)).toBe(false);
  expect(b.maybeStart(now + STARTUP_MS, 3, () => true)).toBe(true);
});

it("refreshes the presence view on a new report and at tab and host expiry", () => {
  const a = new Gossip(releaseID, host("a", 1), now);
  const b = new Gossip(releaseID, host("b", 2), now, {
    endsAt: now + REMOTE_TAB_REPORT_MS + 1000,
  });
  b.observeTabs(5, now);
  a.receive(b.message(now), now);
  expect(a.presenceView(now)).toMatchObject({ hosts: 2, remoteTabs: 5, fallback: [b.self] });
  b.update({ departing: true });
  a.receive(b.message(now + 1), now + 1);
  expect(a.presenceView(now + 1)).toMatchObject({ hosts: 2, remoteTabs: 5, fallback: [] });
  expect(a.presenceView(now + REMOTE_TAB_REPORT_MS).remoteTabs).toBe(0);
  expect(a.presenceView(now + REMOTE_TAB_REPORT_MS + 1000).hosts).toBe(1);
});

it("counts a shared origin once and reveals its next live publisher after departure", () => {
  const a = new Gossip(releaseID, host("a", 1), now);
  const b = new Gossip(releaseID, host("b", 2), now);
  const c = new Gossip(releaseID, { ...host("c", 3), origin: b.self.origin }, now);
  b.observeTabs(2, now);
  c.observeTabs(3, now);
  a.receive(b.message(now), now);
  a.receive(c.message(now), now);
  expect(a.presenceView(now)).toMatchObject({ hosts: 2, remoteTabs: 2, fallback: [b.self] });
  a.receive(b.leave(now + 1), now + 1);
  expect(a.presenceView(now + 1)).toMatchObject({ hosts: 2, remoteTabs: 3, fallback: [c.self] });
});
