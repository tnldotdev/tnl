import { expect, it, vi } from "vitest";
import { checkUpload, peerServer, readInviterCertificate, waitForWork } from "../src/peers/http.ts";
import { UPLOAD_BYTES } from "../src/policy.ts";
import { compareNetworks, proveNetwork } from "../src/network.ts";
import { HOST_PARENT, type Host } from "../src/peers/gossip.ts";

it("refuses the same IP and requires a direct reply from the invited host", async () => {
  const release = "a".repeat(64);
  const secret = "fixture-network-secret-not-used-outside-this-test";
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
  const aProof = await proveNetwork("192.0.2.1", secret);
  const bProof = await proveNetwork("192.0.2.2", secret);
  const bundle = {
    certificate: { certificatePEM: "fixture certificate", privateKeyPEM: "fixture key" },
    expiresAt: Date.now() + 60_000,
  };
  const serve = async () => new Response("keepalive");
  const server = (proof: string) =>
    peerServer(
      release,
      [proxyOrigin],
      serve,
      lifetime.signal,
      { proxyOrigin, proof },
      async () => bundle,
    );
  const first = server(aProof);
  const second = server(bProof);
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
    const accepted = await compareNetworks(request, secret).catch(() => false);
    return new Response(null, { status: accepted ? 204 : 403 });
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
    await expect(waitForWork(a, aProof, lifetime.signal)).rejects.toThrow();
    await expect(waitForWork(a, `${bProof.slice(0, -1)}x`, lifetime.signal)).rejects.toThrow();
    const invitation = await waitForWork(a, bProof, lifetime.signal);
    if (invitation === null) throw new Error("Expected a hosting invitation.");
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
    expect(first.replacement?.runID).toBe(b.runID);
    await expect(readInviterCertificate(a, invitation, lifetime.signal)).rejects.toThrow();
    expect((await first.fetch(new Request(a.origin))).ok).toBe(true);
  } finally {
    lifetime.abort();
    await Promise.all([first.stop(), second.stop()]);
    vi.unstubAllGlobals();
  }
}, 8_000);
