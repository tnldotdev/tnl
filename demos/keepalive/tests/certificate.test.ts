import { expect, it, vi } from "vitest";
import {
  CERTIFICATE_PATH,
  chooseCertificate,
  describeCertificate,
} from "../src/hosting/certificate.ts";
import { Gossip, HOST_PARENT, type Host } from "../src/peers/gossip.ts";
import { peerServer } from "../src/peers/http.ts";

const minute = 60_000;
const bundle = (expiresAt: number, leaf: string) => ({
  expiresAt,
  certificate: {
    certificatePEM: `-----BEGIN CERTIFICATE-----\n${btoa(leaf)}\n-----END CERTIFICATE-----`,
    privateKeyPEM: `fixture key for ${leaf}`,
  },
});

it("reuses a certificate only when it can finish the turn", () => {
  const now = 1_800_000_000_000;
  const soon = { bundle: bundle(now + 11 * minute, "soon"), knownHosts: 10 };
  const renew = { bundle: bundle(now + 60 * minute, "renew"), knownHosts: 10 };
  const later = { bundle: bundle(now + 2 * 24 * 60 * minute, "later"), knownHosts: 10 };
  expect(chooseCertificate(later, true, now, () => 0)).toBeUndefined();
  expect(chooseCertificate(soon, false, now, () => 1)).toBeUndefined();
  expect(chooseCertificate(renew, false, now, () => 0.09)).toBeUndefined();
  expect(chooseCertificate(renew, false, now, () => 0.11)).toBe(renew.bundle);
  expect(chooseCertificate(later, false, now, () => 0)).toBe(later.bundle);
});

it("shares a newer certificate only with a peer answering at its own service run", async () => {
  const page = "https://keepthisalive.com";
  const release = "a".repeat(64);
  const lifetime = new AbortController();
  const now = Date.now();
  const current = await describeCertificate(bundle(now + minute, "old"));
  const newer = bundle(now + 60 * minute, "new");
  const advertised = await describeCertificate(newer);
  const network = { proxyOrigin: page, proof: `${"a".repeat(64)}.${now}.${"b".repeat(64)}` };
  const host = (label: string, run: string): Host => ({
    origin: `https://p-${label.repeat(26)}.${HOST_PARENT}`,
    publisherID: `pub_${label.repeat(22)}`,
    runID: `srun_${label.repeat(22)}`,
    runNumber: run,
  });
  const a = host("a", "1");
  const b = host("b", "2");
  const server = () => Promise.resolve(new Response(null, { status: 404 }));
  const A = peerServer(release, [page], server, lifetime.signal, network);
  const B = peerServer(release, [page], server, lifetime.signal, network, async () => newer);
  const fetch = vi.fn<typeof globalThis.fetch>(async (input, init) => {
    const request = new Request(input, init);
    request.headers.set("Origin", page);
    switch (new URL(request.url).origin) {
      case a.origin:
        return A.fetch(request);
      case b.origin:
        return B.fetch(request);
      default:
        return new Response(null, { status: 503 });
    }
  });
  vi.stubGlobal("fetch", fetch);
  try {
    await A.start(
      a,
      now,
      undefined,
      undefined,
      (gossip) => {
        gossip.receive(new Gossip(release, b, now, { certificate: advertised }).message(now), now);
      },
      () => false,
    );
    await B.start(
      b,
      now,
      undefined,
      undefined,
      (gossip) => {
        gossip.receive(new Gossip(release, a, now).message(now), now);
      },
      () => false,
    );
    const endpoint = new URL(CERTIFICATE_PATH, b.origin);
    const anonymous = await B.fetch(new Request(endpoint, { headers: { Origin: page } }));
    expect(anonymous.status).toBe(403);
    const forged = await B.fetch(
      new Request(endpoint, {
        method: "POST",
        headers: { Origin: page },
        body: JSON.stringify({ requester: a, nonce: crypto.randomUUID() }),
      }),
    );
    expect(forged.status).toBe(403);
    expect(await A.newerCertificate(current, lifetime.signal)).toEqual(newer);
    expect(await A.newerCertificate(advertised, lifetime.signal)).toBeUndefined();
  } finally {
    lifetime.abort();
    await Promise.all([A.stop(), B.stop()]);
    vi.unstubAllGlobals();
  }
});
