import { expect, it, vi } from "vitest";
import { CONFIG_PATH, INVITATION_PATH, READY_HEADER } from "../src/enrollment.ts";
import {
  AlreadyHosting,
  HostingInAnotherTab,
  HostingUnavailable,
  UploadTooSlow,
  hostTab,
} from "../src/hosting/tab.ts";
import { HOST_PARENT, PEERS_PATH } from "../src/peers/gossip.ts";
import { RELEASE_PATH, WASM_PATH, WORKER_PATH, digest } from "../src/release.ts";

function browserLocks() {
  let held = false;
  const request = vi.fn(
    async (name: string, options: LockOptions, run: (lock: Lock | null) => Promise<unknown>) => {
      expect(options.ifAvailable).toBe(true);
      if (held) return run(null);
      held = true;
      try {
        return await run({ name, mode: "exclusive" });
      } finally {
        held = false;
      }
    },
  );
  vi.stubGlobal("navigator", { locks: { request } });
  return request;
}

it("rejects a second hosting attempt before it can take an invitation", async () => {
  const request = browserLocks();
  const held = Promise.withResolvers<Response>();
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockReturnValueOnce(held.promise)
    .mockImplementation(async () => new Response(null, { status: 503 }));
  vi.stubGlobal("fetch", fetch);
  const signal = new AbortController().signal;
  try {
    const first = hostTab(false, signal, vi.fn(), vi.fn());
    await expect(hostTab(false, signal, vi.fn(), vi.fn())).rejects.toBeInstanceOf(
      HostingInAnotherTab,
    );
    expect(request.mock.calls.map(([name]) => name)).toEqual(["keepalive-host", "keepalive-host"]);
    expect(fetch).toHaveBeenCalledTimes(1);
    held.resolve(new Response(null, { status: 503 }));
    await expect(first).rejects.toThrow("Response has no body");
    await expect(hostTab(false, signal, vi.fn(), vi.fn())).rejects.toThrow("Response has no body");
    expect(fetch).toHaveBeenCalledTimes(2);
  } finally {
    vi.unstubAllGlobals();
  }
});

it.each([false, true])("gives back an invitation on upload failure or Stop (%s)", async (stop) => {
  browserLocks();
  const owner = new AbortController();
  const origin = "https://keepthisalive.com";
  const host = `https://p-${"a".repeat(26)}.${HOST_PARENT}`;
  const invitation = crypto.randomUUID();
  const assets = ["/index.html", WORKER_PATH, WASM_PATH].map((path) => ({
    path,
    size: 1,
    sha256: "a".repeat(64),
  }));
  const id = await digest(new TextEncoder().encode(JSON.stringify(assets)));
  const release = vi.fn();
  vi.stubGlobal("location", { origin });
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), origin);
    if (url.pathname === RELEASE_PATH) return Response.json({ id, assets });
    if (url.pathname === PEERS_PATH) {
      const now = Date.now();
      return Response.json({
        releaseID: id,
        startedAt: now,
        from: {
          origin: host,
          publisherID: `pub_${"A".repeat(22)}`,
          runID: `srun_${"A".repeat(22)}`,
          runNumber: "1",
          seq: 1,
          reportedAt: now,
          left: false,
          startingUntil: 0,
        },
        changes: [],
      });
    }
    expect(url.origin).toBe(host);
    if (url.pathname === "/__keepalive/wait") {
      if (stop) owner.abort();
      return Response.json(invitation);
    }
    if (url.pathname === "/__keepalive/upload") return new Response(null, { status: 422 });
    expect(url.pathname).toBe(INVITATION_PATH);
    expect(init?.method).toBe("POST");
    const headers = new Headers(init?.headers);
    expect(headers.get(READY_HEADER)).toBe(invitation);
    expect(headers.get("X-Keepalive-Release")).toBe(id);
    expect(init?.signal?.aborted).toBe(false);
    release();
    return new Response(null, { status: 204 });
  });
  try {
    await expect(hostTab(false, owner.signal, vi.fn(), vi.fn())).rejects.toBeInstanceOf(
      stop ? DOMException : UploadTooSlow,
    );
    expect(release).toHaveBeenCalledOnce();
  } finally {
    vi.unstubAllGlobals();
  }
});

it.each([true, false])(
  "only starts bootstrap if no host answers (answers: %s)",
  async (reachable) => {
    const encoder = new TextEncoder();
    const hash = await digest(encoder.encode("a"));
    const assets = ["/index.html", WORKER_PATH, WASM_PATH].map((path) => ({
      path,
      size: 1,
      sha256: hash,
    }));
    const release = { id: await digest(encoder.encode(JSON.stringify(assets))), assets };
    const now = Date.now();
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(Response.json(release))
      .mockResolvedValueOnce(
        reachable
          ? Response.json({
              releaseID: release.id,
              startedAt: now,
              from: {
                origin: `https://p-${"a".repeat(26)}.${HOST_PARENT}`,
                publisherID: `pub_${"A".repeat(22)}`,
                runID: `srun_${"A".repeat(22)}`,
                runNumber: "1",
                seq: 1,
                reportedAt: now,
                left: false,
                startingUntil: 0,
              },
              changes: [],
            })
          : new Response(null, { status: 503 }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 503 }));
    vi.stubGlobal("fetch", fetch);
    vi.stubGlobal("location", { origin: "https://start.keepthisalive.com" });
    browserLocks();
    try {
      const update = vi.fn();
      await expect(
        hostTab(true, new AbortController().signal, update, vi.fn()),
      ).rejects.toBeInstanceOf(reachable ? AlreadyHosting : HostingUnavailable);
      expect(fetch.mock.calls.map(([url]) => String(url))).toEqual([
        RELEASE_PATH,
        `https://start.keepthisalive.com${PEERS_PATH}`,
        ...(reachable ? [] : [CONFIG_PATH]),
      ]);
    } finally {
      vi.unstubAllGlobals();
    }
  },
);
