import { expect, it, vi } from "vitest";
import {
  checkUpload,
  peerServer,
  readInviterCertificate,
  releaseInvitation,
  waitForWork,
} from "../src/peers/http.ts";
import { INVITATION_ACK_MS, STARTUP_MS, UPLOAD_BYTES } from "../src/policy.ts";
import { INVITATION_PATH, READY_HEADER } from "../src/enrollment.ts";
import { HOST_PARENT, type Host } from "../src/peers/gossip.ts";

it("offers one invitation without a network check and verifies the exact replacement run", async () => {
  const release = "a".repeat(64);
  const lifetime = new AbortController();
  const proxyOrigin = "https://keepthisalive.com";
  const host = (name: "a" | "b", id: string): Host => ({
    origin: `https://p-${name.repeat(26)}.${HOST_PARENT}`,
    publisherID: `pub_${id.repeat(22)}`,
    runID: `srun_${id.repeat(22)}`,
    runNumber: id,
  });
  const a = host("a", "1");
  const b = host("b", "2");
  const bundle = {
    certificate: { certificatePEM: "fixture certificate", privateKeyPEM: "fixture key" },
    expiresAt: Date.now() + STARTUP_MS + 60_000,
  };
  const serve = async () => new Response("keepalive");
  const server = () =>
    peerServer(release, [proxyOrigin], serve, lifetime.signal, async () => bundle);
  const first = server();
  const second = server();
  const hosts = new Map([
    [a.origin, first],
    [b.origin, second],
  ]);
  const directCheck = vi.fn();
  vi.stubGlobal("fetch", async (url: URL, init: RequestInit) => {
    const headers = new Headers(init.headers);
    headers.set("Origin", proxyOrigin);
    const request = new Request(url, { ...init, headers });
    const target = hosts.get(url.origin);
    if (target !== undefined) {
      if (url.origin === b.origin && request.method === "GET") directCheck();
      return target.fetch(request);
    }
    throw new Error("unexpected request outside peers");
  });
  try {
    const offeredAt = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(offeredAt);
    await first.start(
      a,
      offeredAt,
      undefined,
      undefined,
      () => {},
      () => true,
    );
    const abandoned = await waitForWork(a, lifetime.signal);
    expect(abandoned).not.toBeNull();
    clock.mockReturnValue(offeredAt + INVITATION_ACK_MS - 1);
    expect(await waitForWork(a, lifetime.signal)).toBeNull();
    clock.mockReturnValue(offeredAt + INVITATION_ACK_MS + 1);
    const offers = await Promise.all([
      waitForWork(a, lifetime.signal),
      waitForWork(a, lifetime.signal),
    ]);
    expect(offers.filter((v) => v === null)).toHaveLength(1);
    const invitation = offers.find((v) => v !== null);
    if (!invitation) throw new Error("Expected a hosting invitation.");
    expect(invitation).not.toBe(abandoned);
    const confirm = () =>
      first.fetch(
        new Request(new URL(INVITATION_PATH, a.origin), {
          headers: { [READY_HEADER]: invitation, "X-Keepalive-Release": release },
        }),
      );
    expect((await confirm()).status).toBe(403);
    await expect(readInviterCertificate(a, invitation, lifetime.signal)).rejects.toThrow();
    expect(first.replacementReady).toBe(false);
    expect(await checkUpload(a, crypto.randomUUID(), lifetime.signal)).toBe(false);
    const short = await first.fetch(
      new Request(`${a.origin}/__keepalive/upload`, {
        method: "POST",
        body: new Uint8Array(UPLOAD_BYTES - 1),
        headers: { Origin: proxyOrigin, "X-Keepalive-Ready": invitation },
      }),
    );
    expect(short.status).toBe(422);
    expect(first.replacementReady).toBe(false);
    expect(await checkUpload(a, invitation, lifetime.signal)).toBe(true);
    expect((await confirm()).status).toBe(204);
    clock.mockReturnValue(offeredAt + 2 * INVITATION_ACK_MS + 2);
    expect((await confirm()).status).toBe(204);
    expect(await waitForWork(a, lifetime.signal)).toBeNull();
    await expect(readInviterCertificate(a, crypto.randomUUID(), lifetime.signal)).rejects.toThrow();
    await expect(readInviterCertificate(a, invitation, lifetime.signal)).resolves.toEqual({
      bundle,
      knownHosts: 1,
    });
    await second.start(
      b,
      Date.now(),
      a,
      invitation,
      () => {},
      () => false,
    );
    expect(directCheck).toHaveBeenCalledOnce();
    expect(first.replacementReady).toBe(true);
    expect((await confirm()).status).toBe(403);
    expect(first.replacement?.runID).toBe(b.runID);
    await expect(readInviterCertificate(a, invitation, lifetime.signal)).rejects.toThrow();
    expect((await first.fetch(new Request(a.origin))).ok).toBe(true);
  } finally {
    lifetime.abort();
    await Promise.all([first.stop(), second.stop()]);
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
}, 8_000);

it("releases only the matching invitation and reoffers without waiting for startup", async () => {
  const release = "a".repeat(64);
  const page = "https://keepthisalive.com";
  const lifetime = new AbortController();
  const host: Host = {
    origin: `https://p-${"a".repeat(26)}.${HOST_PARENT}`,
    publisherID: `pub_${"a".repeat(22)}`,
    runID: `srun_${"a".repeat(22)}`,
    runNumber: "1",
  };
  const donor = peerServer(release, [page], async () => new Response(), lifetime.signal);
  vi.stubGlobal("fetch", (url: URL, init: RequestInit) => {
    const headers = new Headers(init.headers);
    headers.set("Origin", page);
    return donor.fetch(new Request(url, { ...init, headers }));
  });
  try {
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await donor.start(
      host,
      now,
      undefined,
      undefined,
      () => {},
      () => false,
    );
    const invitation = await waitForWork(host, lifetime.signal);
    if (!invitation) throw new Error("No invitation.");
    const preflight = await donor.fetch(
      new Request(new URL(INVITATION_PATH, host.origin), {
        method: "OPTIONS",
        headers: {
          Origin: page,
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": `${READY_HEADER}, X-Keepalive-Release`,
        },
      }),
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("Access-Control-Allow-Origin")).toBe(page);
    expect(preflight.headers.get("Access-Control-Allow-Headers")).toContain("X-Keepalive-Release");
    await releaseInvitation(host, crypto.randomUUID(), release);
    await releaseInvitation(host, invitation, "b".repeat(64));
    const crossOrigin = new Request(new URL(INVITATION_PATH, host.origin), {
      method: "POST",
      headers: {
        Origin: "https://other.test",
        [READY_HEADER]: invitation,
        "X-Keepalive-Release": release,
      },
    });
    expect((await donor.fetch(crossOrigin)).status).toBe(403);
    expect(await waitForWork(host, lifetime.signal)).toBeNull();
    expect(await checkUpload(host, invitation, lifetime.signal)).toBe(true);
    clock.mockReturnValue(now + INVITATION_ACK_MS + 1);
    expect(await checkUpload(host, invitation, lifetime.signal)).toBe(true);
    expect(await waitForWork(host, lifetime.signal)).toBeNull();
    await releaseInvitation(host, invitation, release);
    const next = await waitForWork(host, lifetime.signal);
    expect(next).not.toBeNull();
    expect(next).not.toBe(invitation);
    await releaseInvitation(host, invitation, release);
    expect(await waitForWork(host, lifetime.signal)).toBeNull();
    if (!next) throw new Error("No replacement invitation.");
    expect(await checkUpload(host, next, lifetime.signal)).toBe(true);
    clock.mockReturnValue(Date.now() + STARTUP_MS - 1);
    expect(await checkUpload(host, next, lifetime.signal)).toBe(true);
    clock.mockReturnValue(Date.now() + 1);
    expect(await checkUpload(host, next, lifetime.signal)).toBe(false);
    expect(await waitForWork(host, lifetime.signal)).not.toBeNull();
  } finally {
    lifetime.abort();
    await donor.stop();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
});
