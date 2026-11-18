import { WASM_PATH, parseRelease, readJSON } from "../release.ts";
import { serveRelease } from "../serving.ts";
import { CREDENTIALS_PATH, HOST_TURN_MS, REPLACE_BEFORE_MS, enrollmentKey } from "./config.ts";
import { hostCommand, type HostStart, type HostUpdate } from "./messages.ts";
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

async function host(command: HostStart) {
  let running: Awaited<ReturnType<typeof startPublisher>> | undefined;
  let peers: ReturnType<typeof peerServer> | undefined;
  let failed = false;
  let expired = false;
  let endsAt = Infinity;
  let stopTimer: ReturnType<typeof setTimeout> | undefined;
  function endTurn() {
    expired = true;
    lifetime.abort();
  }
  try {
    const release = await parseRelease(command.release);
    const wasm = command.files.get(WASM_PATH);
    if (wasm === undefined) throw new Error("The copy is missing the hosting code.");
    useLocalWasm(wasm, command.pageOrigin);

    let filesServed = 0;
    const serve = serveRelease(release, command.files);
    const allowedOrigins = [
      command.pageOrigin,
      command.config.siteOrigin,
      `https://${command.config.startHost}`,
    ];
    peers = peerServer(
      release.id,
      allowedOrigins,
      async (request) => {
        if (Date.now() >= endsAt) {
          endTurn();
          return new Response(null, { status: 503 });
        }
        const response = await serve(request);
        if (response.ok) filesServed++;
        return response;
      },
      signal,
      { proxyOrigin: command.pageOrigin, proof: command.config.networkProof },
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
    endsAt = since + HOST_TURN_MS;
    stopTimer = setTimeout(endTurn, HOST_TURN_MS);
    let nextDiscovery = since + 30_000;
    await peers.start(
      host,
      since,
      command.firstHostToContact,
      command.invitation,
      (gossip) => {
        const now = Date.now();
        if (now >= endsAt) return endTurn();
        if (now >= endsAt - REPLACE_BEFORE_MS) replacing = true;
        const hosts = gossip.hosts(now);
        if (now >= nextDiscovery) {
          nextDiscovery = now + 30_000;
          void readPeers(command.pageOrigin, release.id, signal)
            .then((report) => {
              if (report !== undefined) gossip.receive(report, Date.now());
            })
            .catch(() => {});
        }
        if (replacing && peers?.replacementReady) lifetime.abort();
        emit({
          type: "hosting",
          since,
          endsAt,
          replacing,
          filesServed,
          hosts: hosts.length + 1,
          startedAt: gossip.startedAt,
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
    clearTimeout(stopTimer);
    try {
      // closing the publisher ends HTTP streams even after abrupt tab closure.
      await peers?.stop();
      await running?.close();
    } catch {
      failed = true;
    }
    emit(failed ? { type: "failed" } : { type: "stopped", expired });
  }
}

function useLocalWasm(wasm: ArrayBuffer, pageOrigin: string) {
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
