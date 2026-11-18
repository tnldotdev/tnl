import * as z from "zod";
import { parseMessage } from "../peers.ts";
import { WASM_PATH, parseRelease, readJSON } from "../release.ts";
import { serveRelease } from "../serving.ts";
import { openRelease, rememberStart } from "../storage.ts";
import { CREDENTIALS_PATH, enrollmentKey } from "./config.ts";
import { hostCommand, type HostUpdate } from "./messages.ts";
import { peerServer, readPeers } from "./peer-http.ts";
import { startPublisher } from "./publish.ts";

const lifetime = new AbortController();
const { signal } = lifetime;
const emit = (update: HostUpdate) => globalThis.postMessage(update);
let started = false;
let replacing = false;

globalThis.addEventListener("message", ({ data }: MessageEvent<unknown>) => {
  const message = hostCommand.safeParse(data);
  if (!message.success) {
    emit({ type: "failed" });
    return;
  }
  if (message.data.type === "stop") lifetime.abort();
  else if (message.data.type === "replace") replacing = true;
  else if (!started) {
    started = true;
    void host(message.data);
  }
});

async function host(command: Extract<z.infer<typeof hostCommand>, { type: "start" }>) {
  let running: Awaited<ReturnType<typeof startPublisher>> | undefined;
  let peers: ReturnType<typeof peerServer> | undefined;
  let failed = false;
  try {
    const release = await parseRelease(command.release);
    const first = parseMessage(command.first, release.id, Date.now());
    const read = await openRelease(release);
    const module = release.assets.find((asset) => asset.path === WASM_PATH);
    const wasm = module === undefined ? undefined : read(module);
    if (wasm === undefined) throw new Error("The copy is missing the hosting code.");
    useLocalWasm(wasm, command.pageOrigin);

    let filesServed = 0;
    const serve = serveRelease(release, read);
    const allowedOrigins = [
      command.pageOrigin,
      command.config.siteOrigin,
      `https://${command.config.startHost}`,
    ];
    peers = peerServer(
      release.id,
      allowedOrigins,
      async (request) => {
        const response = await serve(request);
        if (response.ok) filesServed++;
        return response;
      },
      signal,
    );
    const requestID = crypto.randomUUID();
    running = await startPublisher(
      command.config,
      async (signal) => {
        const response = await fetch(new URL(CREDENTIALS_PATH, command.pageOrigin), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ releaseID: release.id, requestID }),
          redirect: "error",
          signal,
        });
        if (!response.ok) throw new Error("Could not get permission to host.");
        return enrollmentKey.parse(await readJSON(response, 1024, signal));
      },
      peers.fetch,
      signal,
    );
    const { host } = running;
    const since = Date.now();
    let savedStart = await rememberStart(release.id, first?.startedAt ?? since);
    let nextDiscovery = since + 30_000;
    peers.start(
      host,
      savedStart,
      first,
      (gossip) => {
        const now = Date.now();
        const hosts = gossip.hosts(now);
        if (now >= nextDiscovery) {
          nextDiscovery = now + 30_000;
          void readPeers(command.pageOrigin, release.id, signal)
            .then((report) => {
              if (report !== undefined) gossip.receive(report, Date.now());
            })
            .catch(() => {});
        }
        if (gossip.startedAt < savedStart) {
          savedStart = gossip.startedAt;
          void rememberStart(release.id, savedStart).catch(() => {});
        }
        if (replacing && hosts.length >= 3) lifetime.abort();
        emit({
          type: "hosting",
          since,
          filesServed,
          hosts: hosts.length + 1,
          startedAt: savedStart,
          origin: host.origin,
        });
      },
      () => replacing,
    );
    await running.wait();
    failed = !signal.aborted;
  } catch {
    failed = !signal.aborted;
  } finally {
    try {
      // closing the publisher ends HTTP streams even after abrupt tab closure.
      await peers?.stop();
      await running?.close();
    } catch {
      failed = true;
    }
    emit({ type: failed ? "failed" : "stopped" });
  }
}

function useLocalWasm(wasm: Uint8Array<ArrayBuffer>, pageOrigin: string) {
  const originalFetch = globalThis.fetch.bind(globalThis);
  const wasmURL = new URL(WASM_PATH, pageOrigin).href;
  // serve the SDK's lazy WASM fetch from the verified copy, not the network.
  globalThis.fetch = (input, init) => {
    if ((input instanceof URL ? input.href : input) === wasmURL) {
      init?.signal?.throwIfAborted();
      return Promise.resolve(
        new Response(wasm, { headers: { "Content-Type": "application/wasm" } }),
      );
    }
    return originalFetch(input, init);
  };
}
