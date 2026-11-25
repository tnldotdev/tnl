import { expect, it, vi } from "vitest";
import {
  checkUpload,
  InvitationUnavailable,
  peerServer,
  readInviterCertificate,
  releaseInvitation,
  waitForWork,
} from "../src/peers/http.ts";
import { INVITATION_ACK_MS, STARTUP_MS, UPLOAD_BYTES, UPLOAD_MS } from "../src/policy.ts";
import { INVITATION_PATH, READY_HEADER } from "../src/enrollment.ts";
import { Gossip, HOST_PARENT, PEERS_PATH, type Host } from "../src/peers/gossip.ts";

it("allows time to reach the donor without extending its upload read deadline", async () => {
  vi.useFakeTimers();
  vi.spyOn(AbortSignal, "timeout").mockImplementation((ms) => {
    const timeout = new AbortController();
    setTimeout(() => timeout.abort(new DOMException("timeout", "TimeoutError")), ms);
    return timeout.signal;
  });
  const origin = "https://keepthisalive.com";
  const release = "a".repeat(64);
  const host = {
    origin: `https://p-${"a".repeat(26)}.${HOST_PARENT}`,
    publisherID: `pub_${"A".repeat(22)}`,
    runID: `srun_${"A".repeat(22)}`,
    runNumber: "1",
  };
  const lifetime = new AbortController();
  const donor = peerServer(release, [origin], async () => new Response(), lifetime.signal);
  let bodyDelay = UPLOAD_MS + 1;
  let attempts = 0;
  vi.stubGlobal("fetch", async (url: URL, init: RequestInit) => {
    const headers = new Headers(init.headers);
    headers.set("Origin", origin);
    if (url.pathname !== "/__keepalive/upload")
      return donor.fetch(new Request(url, { ...init, headers }));
    attempts++;
    await new Promise<void>((ok) => setTimeout(ok, 900));
    init.signal?.throwIfAborted();
    let timer: ReturnType<typeof setTimeout>;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        timer = setTimeout(() => {
          controller.enqueue(new Uint8Array(UPLOAD_BYTES));
          controller.close();
        }, bodyDelay);
      },
      cancel() {
        clearTimeout(timer);
      },
    });
    const reply = await donor.fetch(
      new Request(url, { ...init, headers, body, duplex: "half" } as RequestInit),
    );
    init.signal?.throwIfAborted();
    return reply;
  });
  try {
    await donor.start(
      host,
      Date.now(),
      undefined,
      undefined,
      () => {},
      () => false,
    );
    const invitation = await waitForWork(host, lifetime.signal);
    expect(invitation).toBeTruthy();
    if (invitation === null) throw new Error("expected invitation");
    const slow = checkUpload(host, invitation, lifetime.signal);
    await vi.advanceTimersByTimeAsync(900 + UPLOAD_MS + 1);
    expect(await slow).toBe(false);
    bodyDelay = UPLOAD_MS - 200;
    const healthy = checkUpload(host, invitation, lifetime.signal);
    await vi.advanceTimersByTimeAsync(900 + bodyDelay);
    expect(await healthy).toBe(true);
    expect(attempts).toBe(2);
  } finally {
    lifetime.abort();
    await donor.stop();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
  }
});

it.each([false, true])(
  "confirms the exact replacement run (lost upload and confirmation replies: %s)",
  verifyReplacement,
  8_000,
);

async function verifyReplacement(lost: boolean) {
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
  let confirmations = 0;
  let uploads = 0;
  vi.stubGlobal("fetch", async (url: URL, init: RequestInit) => {
    const headers = new Headers(init.headers);
    headers.set("Origin", proxyOrigin);
    const request = new Request(url, { ...init, headers });
    const target = hosts.get(url.origin);
    if (target !== undefined) {
      if (url.origin === b.origin && request.method === "GET") directCheck();
      const reply = await target.fetch(request);
      if (url.origin === a.origin && request.method === "POST" && reply.ok) {
        if (url.pathname === PEERS_PATH && headers.has(READY_HEADER)) {
          confirmations++;
          if (lost && confirmations === 1) {
            expect(first.replacementReady).toBe(true);
            expect(first.confirmingHandoff).toBe(true);
            throw new TypeError("the donor accepted but the reply was lost");
          }
        }
        if (url.pathname === "/__keepalive/upload") {
          uploads++;
          if (lost && uploads === 1) throw new TypeError("upload passed but the reply was lost");
        }
      }
      return reply;
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
    await expect(checkUpload(a, crypto.randomUUID(), lifetime.signal)).rejects.toBeInstanceOf(
      InvitationUnavailable,
    );
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
    expect(confirmations).toBe(lost ? 2 : 1);
    expect(uploads).toBe(lost ? 2 : 1);
    expect(first.replacementReady).toBe(true);
    expect((await confirm()).status).toBe(403);
    expect(first.replacement?.runID).toBe(b.runID);
    const replay = (run: Host) =>
      first.fetch(
        new Request(new URL(PEERS_PATH, a.origin), {
          method: "POST",
          headers: { [READY_HEADER]: invitation },
          body: JSON.stringify(new Gossip(release, run, Date.now()).message(Date.now())),
        }),
      );
    expect((await replay({ ...b, runID: `srun_${"3".repeat(22)}`, runNumber: "3" })).status).toBe(
      403,
    );
    clock.mockReturnValue(Date.now() + 12_000);
    expect(first.confirmingHandoff).toBe(false);
    expect((await replay(b)).status).toBe(403);
    await expect(readInviterCertificate(a, invitation, lifetime.signal)).rejects.toThrow();
    expect((await first.fetch(new Request(a.origin))).ok).toBe(true);
  } finally {
    lifetime.abort();
    await Promise.all([first.stop(), second.stop()]);
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
}

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
    await expect(checkUpload(host, next, lifetime.signal)).rejects.toBeInstanceOf(
      InvitationUnavailable,
    );
    expect(await waitForWork(host, lifetime.signal)).not.toBeNull();
  } finally {
    lifetime.abort();
    await donor.stop();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  }
});
