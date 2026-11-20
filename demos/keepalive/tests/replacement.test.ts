import { expect, it, vi } from "vitest";
import { checkUpload, peerServer, readInviterCertificate, waitForWork } from "../src/peers/http.ts";
import { STARTUP_MS, UPLOAD_BYTES } from "../src/policy.ts";
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
    await first.start(
      a,
      Date.now(),
      undefined,
      undefined,
      () => {},
      () => true,
    );
    const abandoned = await waitForWork(a, lifetime.signal);
    expect(abandoned).not.toBeNull();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + STARTUP_MS + 1);
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
