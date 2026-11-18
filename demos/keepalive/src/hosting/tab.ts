import type { Host } from "../peers.ts";
import {
  ARTIFACT_PREFIX,
  MAX_MANIFEST_BYTES,
  RELEASE_PATH,
  WORKER_PATH,
  parseRelease,
  readAssetResponse,
  readJSON,
  type Release,
} from "../release.ts";
import { CONFIG_PATH, hostingConfig } from "./config.ts";
import { hostUpdate, type HostStart, type HostUpdate } from "./messages.ts";
import { readPeers, waitForWork } from "./peer-http.ts";

export type HostState =
  | { type: "copying" | "waiting" | "starting" | "stopping" }
  | Extract<HostUpdate, { type: "hosting" }>;

async function waitForHost(releaseID: string, signal: AbortSignal) {
  for (;;) {
    signal.throwIfAborted();
    const peers = await readPeers(location.origin, releaseID, signal).catch(() => undefined);
    if (peers !== undefined) {
      // try the host reached through the shared service first.
      const candidates = [peers.from, ...peers.changes].filter((host) => !host.left).slice(0, 3);
      for (const host of candidates) {
        signal.throwIfAborted();
        try {
          if (!(await waitForWork(host, signal))) break;
          return host;
        } catch {
          // this tab can wait with a different host.
        }
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

async function copySite(release: Release, source: string, signal: AbortSignal) {
  const files = new Map<string, ArrayBuffer>();
  for (const asset of release.assets) {
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(30_000)]);
    const response = await fetch(source + asset.path, {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      signal: deadline,
    });
    files.set(asset.path, (await readAssetResponse(asset, response, deadline)).buffer);
  }
  return files;
}

async function getJSON(path: string, limit: number, signal: AbortSignal, method = "GET") {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(10_000)]);
  const response = await fetch(path, {
    method,
    cache: "no-store",
    redirect: "error",
    signal: deadline,
  });
  return readJSON(response, limit, deadline);
}

export async function hostTab(
  bootstrap: boolean,
  signal: AbortSignal,
  replace: AbortSignal,
  update: (state: HostState) => void,
) {
  const release = await parseRelease(await getJSON(RELEASE_PATH, MAX_MANIFEST_BYTES, signal));
  let source = ARTIFACT_PREFIX;
  let initialPeer: Host | undefined;
  if (bootstrap) {
    const report = await readPeers(location.origin, release.id, signal).catch(() => undefined);
    if (report !== undefined && !report.from.left) initialPeer = report.from;
  } else {
    update({ type: "waiting" });
    initialPeer = await waitForHost(release.id, signal);
    source = initialPeer.origin;
  }
  update({ type: "copying" });
  const files = await copySite(release, source, signal);
  const code = files.get(WORKER_PATH);
  if (code === undefined) throw new Error("The copy is missing the hosting code.");
  const config = hostingConfig.parse(await getJSON(CONFIG_PATH, 160 * 1024, signal, "POST"));
  signal.throwIfAborted();
  update({ type: "starting" });
  const url = URL.createObjectURL(new Blob([code], { type: "text/javascript" }));
  const worker = new Worker(url, { type: "module", name: "keepalive" });
  try {
    await runWorker(
      worker,
      { type: "start", release, files, config, initialPeer, pageOrigin: location.origin },
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
  return new Promise<void>((resolve, reject) => {
    let stopTimer: ReturnType<typeof setTimeout> | undefined;
    const startup = setTimeout(
      () => finish(new Error("This tab took too long to start.")),
      120_000,
    );
    function finish(error?: Error) {
      clearTimeout(startup);
      clearTimeout(stopTimer);
      signal.removeEventListener("abort", stop);
      replace.removeEventListener("abort", replaceHost);
      if (error === undefined) resolve();
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
      if (message.data.type === "stopped") finish();
      if (message.data.type === "hosting" && !signal.aborted) {
        clearTimeout(startup);
        update(message.data);
      }
    };
    worker.postMessage(start, [...start.files.values()]);
    if (signal.aborted) stop();
  });
}
