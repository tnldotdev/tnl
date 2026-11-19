import { NETWORK_PROOF_PATH, networkProof } from "../network.ts";
import type { Host } from "../peers.ts";
import {
  ARTIFACT_PREFIX,
  MAX_MANIFEST_BYTES,
  RELEASE_PATH,
  WORKER_PATH,
  parseRelease,
  readBytes,
  readJSON,
  verifyAsset,
  type Release,
} from "../release.ts";
import { CONFIG_PATH, hostingConfig } from "./config.ts";
import { hostUpdate, type HostStart, type HostUpdate } from "./messages.ts";
import { readPeers, waitForWork } from "./peer-http.ts";

export type HostState =
  | { type: "waiting" | "starting" | "stopping" }
  | { type: "copying"; received: number; total: number }
  | Extract<HostUpdate, { type: "hosting" }>;

export class HostingUnavailable extends Error {}

async function waitForInvitation(releaseID: string, signal: AbortSignal) {
  for (;;) {
    signal.throwIfAborted();
    const peers = await readPeers(location.origin, releaseID, signal).catch(() => undefined);
    if (peers !== undefined) {
      const proof = networkProof.parse(await getJSON(NETWORK_PROOF_PATH, 192, signal, "POST"));
      // try the host reached through the shared service first.
      const candidates = [peers.from, ...peers.changes].filter((host) => !host.left).slice(0, 3);
      for (const host of candidates) {
        signal.throwIfAborted();
        try {
          const invitation = await waitForWork(host, proof, signal);
          if (invitation === null) break;
          return { host, invitation };
        } catch {
          // this tab can wait with a different host.
        }
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

async function copySite(
  release: Release,
  source: string,
  signal: AbortSignal,
  update: (state: HostState) => void,
) {
  const files = new Map<string, ArrayBuffer>();
  const total = release.assets.reduce((sum, asset) => sum + asset.size, 0);
  let received = 0;
  let lastUpdate = 0;
  const started = performance.now();
  let verification = 0;
  update({ type: "copying", received, total });
  for (const asset of release.assets) {
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(30_000)]);
    const response = await fetch(source + asset.path, {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      signal: deadline,
    });
    const bytes = await readBytes(response, asset.size, deadline, asset.size, (bytes) => {
      if (performance.now() - lastUpdate < 100 && received + bytes !== total) return;
      lastUpdate = performance.now();
      update({ type: "copying", received: received + bytes, total });
    });
    const verifying = performance.now();
    await verifyAsset(asset, bytes);
    verification += performance.now() - verifying;
    received += bytes.byteLength;
    files.set(asset.path, bytes.buffer);
  }
  const finished = performance.now();
  performance.measure("keepalive copy", { start: started, end: finished });
  performance.measure("keepalive verify", { start: started, duration: verification });
  return files;
}

async function getHostingConfig(signal: AbortSignal) {
  return hostingConfig.parse(await getJSON(CONFIG_PATH, 160 * 1024, signal, "POST"));
}

async function getJSON(path: string, limit: number, signal: AbortSignal, method = "GET") {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(10_000)]);
  const response = await fetch(path, {
    method,
    cache: "no-store",
    redirect: "error",
    signal: deadline,
  });
  if (path === CONFIG_PATH && response.status === 503) throw new HostingUnavailable();
  return readJSON(response, limit, deadline);
}

export async function hostTab(
  bootstrap: boolean,
  signal: AbortSignal,
  replace: AbortSignal,
  update: (state: HostState) => void,
) {
  // check bootstrap availability before probing peers or downloading the release.
  const bootstrapConfig = bootstrap ? await getHostingConfig(signal) : undefined;
  const release = await parseRelease(await getJSON(RELEASE_PATH, MAX_MANIFEST_BYTES, signal));
  let source = ARTIFACT_PREFIX;
  let firstHostToContact: Host | undefined;
  let invitation: string | undefined;
  if (bootstrap) {
    const report = await readPeers(location.origin, release.id, signal).catch(() => undefined);
    if (report !== undefined && !report.from.left) firstHostToContact = report.from;
  } else {
    update({ type: "waiting" });
    const selected = await waitForInvitation(release.id, signal);
    firstHostToContact = selected.host;
    invitation = selected.invitation;
    source = selected.host.origin;
  }
  const config = bootstrapConfig ?? (await getHostingConfig(signal));
  const files = await copySite(release, source, signal, update);
  const code = files.get(WORKER_PATH);
  if (code === undefined) throw new Error("The copy is missing the hosting code.");
  signal.throwIfAborted();
  update({ type: "starting" });
  const url = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
  const worker = new Worker(url, { type: "module", name: "keepalive" });
  try {
    return await runWorker(
      worker,
      {
        type: "start",
        release,
        files,
        config,
        firstHostToContact,
        invitation,
        pageOrigin: location.origin,
      },
      signal,
      replace,
      update,
    );
  } finally {
    worker.terminate();
    URL.revokeObjectURL(url);
  }
}

function runWorker(
  worker: Worker,
  start: HostStart,
  signal: AbortSignal,
  replace: AbortSignal,
  update: (state: HostState) => void,
) {
  return new Promise<{ expired: boolean }>((resolve, reject) => {
    const started = performance.now();
    let startupMeasured = false;
    let stopTimer: ReturnType<typeof setTimeout> | undefined;
    const startup = setTimeout(
      () => finish(new Error("This tab took too long to start.")),
      120_000,
    );
    function finish(error?: Error, expired = false) {
      clearTimeout(startup);
      clearTimeout(stopTimer);
      signal.removeEventListener("abort", stop);
      replace.removeEventListener("abort", replaceHost);
      if (error === undefined) resolve({ expired });
      else reject(error);
    }
    function stop() {
      update({ type: "stopping" });
      worker.postMessage({ type: "stop" });
      stopTimer = setTimeout(() => finish(new Error("This tab did not stop in time.")), 15_000);
    }
    function replaceHost() {
      worker.postMessage({ type: "replace" });
    }
    signal.addEventListener("abort", stop, { once: true });
    replace.addEventListener("abort", replaceHost, { once: true });
    worker.onerror = () => finish(new Error("The hosting code could not run."));
    worker.onmessage = ({ data }: MessageEvent<unknown>) => {
      const message = hostUpdate.safeParse(data);
      if (!message.success) return;
      if (message.data.type === "failed") finish(new Error("This tab could not host the site."));
      if (message.data.type === "stopped") finish(undefined, message.data.expired);
      if (message.data.type === "hosting" && !signal.aborted) {
        if (!startupMeasured) {
          startupMeasured = true;
          performance.measure("keepalive startup", { start: started });
        }
        clearTimeout(startup);
        update(message.data);
      }
    };
    worker.postMessage(start, [...start.files.values()]);
    if (signal.aborted) stop();
  });
}
