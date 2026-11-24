import "../validation.ts";
import { WASM_PATH, parseRelease, readJSON } from "../release.ts";
import { serveRelease } from "./serving.ts";
import { RequestActivity } from "./activity.ts";
import { CREDENTIALS_PATH, enrollmentKey } from "../enrollment.ts";
import { REPLACE_BEFORE_MS, hostTarget, turnLength } from "../policy.ts";
import { hostCommand, type HostStart, type HostUpdate } from "./messages.ts";
import { peerServer, readPeers } from "../peers/http.ts";
import { startPublisher } from "./publish.ts";
import { chooseCertificate, describeCertificate } from "./certificate.ts";
import { request, requireStatus } from "../network.ts";

const lifetime = new AbortController();
const { signal } = lifetime;
const emit = (update: HostUpdate) => globalThis.postMessage(update);
let started = false;
const replacementJitter = Math.floor(Math.random() * 5_000);

globalThis.addEventListener("message", ({ data }: MessageEvent<unknown>) => {
  const message = hostCommand.safeParse(data);
  if (!message.success) {
    emit({ type: "failed" });
    return;
  }
  if (message.data.type === "stop") lifetime.abort();
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
  let activityTimer: ReturnType<typeof setInterval> | undefined;
  let checkingCertificate = false;
  const requestID = command.requestID;
  const activity = new RequestActivity();
  function endTurn() {
    expired = true;
    lifetime.abort();
  }
  try {
    const release = await parseRelease(command.release);
    const wasm = command.files.get(WASM_PATH);
    if (wasm === undefined) throw new Error("The copy is missing the hosting code.");
    useLocalWasm(wasm, command.pageOrigin);

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
        if (signal.aborted) return new Response(null, { status: 503 });
        if (Date.now() >= endsAt) {
          endTurn();
          return new Response(null, { status: 503 });
        }
        const response = await serve(request);
        if (running !== undefined && response.ok)
          response.headers.set("X-Keepalive-Run", running.host.runID);
        if (endsAt !== Infinity) activity.record(response, Date.now());
        return response;
      },
      signal,
      async (request) => {
        request.throwIfAborted();
        return running?.exportCertificate();
      },
    );
    const supplied = chooseCertificate(command.inherited, command.bootstrap, Date.now());
    running = await startPublisher(
      command.config,
      async (signal) => {
        const response = await request(new URL(CREDENTIALS_PATH, command.pageOrigin), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            releaseID: release.id,
            requestID,
            bootstrap: command.bootstrap,
            inviter: command.firstHostToContact?.origin,
          }),
          signal,
        });
        return enrollmentKey.parse(await readJSON(await requireStatus(response), 1024, signal));
      },
      peers.fetch,
      signal,
      supplied === undefined
        ? undefined
        : async (operation) => {
            const installed = running === undefined ? supplied : await running.exportCertificate();
            const report = await describeCertificate(installed);
            return ((await peers?.newerCertificate(report, operation)) ?? installed).certificate;
          },
    );
    const { host } = running;
    emit({ type: "published", host });
    const certificate = await describeCertificate(await running.exportCertificate());
    const since = Date.now();
    if (since >= command.startupEndsAt) throw new Error("The hosting invitation expired.");
    const duration = turnLength(command.bootstrap);
    endsAt = since + duration;
    stopTimer = setTimeout(endTurn, duration);
    const departing = () => Date.now() >= endsAt - REPLACE_BEFORE_MS + replacementJitter;
    const reportActivity = () => {
      if (!signal.aborted) emit({ type: "activity", ...activity.snapshot(Date.now()) });
    };
    const discoveryDelay = () => 27_000 + Math.random() * 6_000;
    let nextDiscovery = since + discoveryDelay();
    await peers.start(
      host,
      since,
      command.firstHostToContact,
      command.invitation,
      (gossip) => {
        const now = Date.now();
        if (now >= endsAt) return endTurn();
        const hosts = gossip.hosts(now);
        if (now >= nextDiscovery) {
          nextDiscovery = now + discoveryDelay();
          void readPeers(command.pageOrigin, release.id, signal)
            .then((report) => {
              if (report !== undefined) gossip.receive(report, Date.now());
            })
            .catch(() => {});
          if (!checkingCertificate && running !== undefined) {
            checkingCertificate = true;
            void running
              .exportCertificate()
              .then(describeCertificate)
              .then((installed) => {
                if (!signal.aborted) peers?.advertiseCertificate(installed);
              })
              .catch(() => {})
              .finally(() => {
                checkingCertificate = false;
              });
          }
        }
        const tabs = gossip.tabSnapshot(now, hosts);
        if (
          departing() &&
          !peers?.confirmingHandoff &&
          (peers?.replacementReady || gossip.canRetire(now, hostTarget(tabs.total), hosts))
        ) {
          endTurn();
          return;
        }
        emit({
          type: "hosting",
          since,
          endsAt,
          hosts: hosts.length + 1,
          saturated: gossip.saturated(now),
          startedAt: gossip.startedAt,
          origin: host.origin,
          runID: host.runID,
          tabs: tabs.total,
          localTabs: tabs.local,
        });
      },
      departing,
      {
        name: command.name,
        certificate,
        endsAt,
        ...(command.invitation && command.firstHostToContact
          ? { copyFrom: command.firstHostToContact.runID }
          : {}),
      },
    );
    reportActivity();
    activityTimer = setInterval(reportActivity, 1_000);
    await running.wait();
    failed = !signal.aborted;
  } catch {
    failed = !signal.aborted;
  } finally {
    clearTimeout(stopTimer);
    clearInterval(activityTimer);
    try {
      // closing the publisher ends HTTP streams even after abrupt tab closure.
      await peers?.stop();
    } catch {
      failed = true;
    }
    try {
      await running?.close();
    } catch {
      failed = true;
    }
    emit(failed ? { type: "failed" } : { type: "stopped", expired, requests: activity.count });
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
