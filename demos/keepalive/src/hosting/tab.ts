import { browserHostName } from "../peers/host-names.ts";
import type { Host } from "../peers/gossip.ts";
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
import { CONFIG_PATH, hostingConfig } from "../enrollment.ts";
import { hostUpdate, type HostStart, type HostUpdate } from "./messages.ts";
import { checkUpload, readInviterCertificate, readPeers, waitForWork } from "../peers/http.ts";
import { STARTUP_MS } from "../policy.ts";

export type HostState =
  | { type: "waiting" | "checking" | "starting" | "stopping" }
  | { type: "copying"; received: number; total: number; bootstrap: boolean }
  | Extract<HostUpdate, { type: "hosting" }>;

export class HostingUnavailable extends Error {}
export class AlreadyHosting extends Error {}
export class UploadTooSlow extends Error {}

async function waitForInvitation(releaseID: string, signal: AbortSignal) {
  for (;;) {
    signal.throwIfAborted();
    const peers = await readPeers(location.origin, releaseID, signal).catch(() => undefined);
    if (peers !== undefined) {
      // try the host reached through the shared service first.
      const candidates = [peers.from, ...peers.changes].filter((host) => !host.left).slice(0, 3);
      for (const host of candidates) {
        signal.throwIfAborted();
        try {
          const invitation = await waitForWork(host, signal);
          if (invitation === null) break;
          return { host, invitation };
        } catch {
          // this tab can wait with a different host.
        }
      }
    }
    await new Promise<void>((resolve, reject) => {
      const abort = () => {
        clearTimeout(timer);
        reject(signal.reason);
      };
      const timer = setTimeout(
        () => {
          signal.removeEventListener("abort", abort);
          resolve();
        },
        5_000 + Math.random() * 10_000,
      );
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    });
  }
}

async function copySite(
  release: Release,
  source: string,
  bootstrap: boolean,
  signal: AbortSignal,
  update: (state: HostState) => void,
) {
  const files = new Map<string, ArrayBuffer>();
  const total = release.assets.reduce((sum, asset) => sum + asset.size, 0);
  let received = 0;
  let lastUpdate = 0;
  const started = performance.now();
  performance.mark("keepalive copying");
  let verification = 0;
  update({ type: "copying", received, total, bootstrap });
  for (const asset of release.assets) {
    const response = await fetch(source + asset.path, {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      signal,
    });
    const bytes = await readBytes(response, asset.size, signal, asset.size, (bytes) => {
      if (performance.now() - lastUpdate < 100 && received + bytes !== total) return;
      lastUpdate = performance.now();
      update({ type: "copying", received: received + bytes, total, bootstrap });
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
  performance.mark("keepalive copied");
  return files;
}

async function getHostingConfig(signal: AbortSignal) {
  return hostingConfig.parse(await getJSON(CONFIG_PATH, 4_096, signal, "POST"));
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
  startupPage: boolean,
  signal: AbortSignal,
  update: (state: HostState) => void,
  activity: (state: Extract<HostUpdate, { type: "activity" }>) => void,
) {
  // keep only the current turn on this page's local performance timeline.
  for (const name of ["volunteered", "invited", "copying", "copied", "published", "ended"])
    performance.clearMarks(`keepalive ${name}`);
  for (const name of ["copy", "verify", "startup"]) performance.clearMeasures(`keepalive ${name}`);
  performance.mark("keepalive volunteered");
  const release = await parseRelease(await getJSON(RELEASE_PATH, MAX_MANIFEST_BYTES, signal));
  // the startup page provides the seed copy only if no host answers the proxy.
  const report = startupPage
    ? await readPeers(location.origin, release.id, signal).catch(() => undefined)
    : undefined;
  signal.throwIfAborted();
  if (report !== undefined && !report.from.left && (report.from.endsAt ?? Infinity) > Date.now())
    throw new AlreadyHosting();
  const bootstrap = startupPage;
  let source = ARTIFACT_PREFIX;
  let firstHostToContact: Host | undefined;
  let invitation: string | undefined;
  if (!bootstrap) {
    update({ type: "waiting" });
    const selected = await waitForInvitation(release.id, signal);
    signal.throwIfAborted();
    firstHostToContact = selected.host;
    invitation = selected.invitation;
    source = selected.host.origin;
  }
  const startupEndsAt = Date.now() + STARTUP_MS - 2_000;
  if (!bootstrap) performance.mark("keepalive invited");
  const preparing = AbortSignal.any([signal, AbortSignal.timeout(startupEndsAt - Date.now())]);
  if (invitation !== undefined && firstHostToContact !== undefined) {
    update({ type: "checking" });
    if (!(await checkUpload(firstHostToContact, invitation, preparing))) throw new UploadTooSlow();
  }
  const config = await getHostingConfig(preparing);
  const [files, inherited] = await Promise.all([
    copySite(release, source, bootstrap, preparing, update),
    invitation === undefined || firstHostToContact === undefined
      ? undefined
      : readInviterCertificate(firstHostToContact, invitation, preparing).catch(() => undefined),
  ]);
  const code = files.get(WORKER_PATH);
  if (code === undefined) throw new Error("The copy is missing the hosting code.");
  preparing.throwIfAborted();
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
        requestID: invitation ?? crypto.randomUUID(),
        inherited,
        bootstrap,
        startupEndsAt,
        name: browserHostName(),
        firstHostToContact,
        invitation,
        pageOrigin: location.origin,
      },
      signal,
      update,
      activity,
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
  update: (state: HostState) => void,
  activity: (state: Extract<HostUpdate, { type: "activity" }>) => void,
) {
  return new Promise<{ expired: boolean; requests: number }>((resolve, reject) => {
    const started = performance.now();
    let startupMeasured = false;
    let stopTimer: ReturnType<typeof setTimeout> | undefined;
    let startupExpired = false;
    const startupError = new DOMException("This tab took too long to start.", "TimeoutError");
    const startup = setTimeout(
      () => {
        startupExpired = true;
        if (stopTimer === undefined) stop();
      },
      Math.max(0, start.startupEndsAt - Date.now()),
    );
    function finish(error?: Error, expired = false, requests = 0) {
      clearTimeout(startup);
      clearTimeout(stopTimer);
      signal.removeEventListener("abort", stop);
      if (error === undefined) resolve({ expired, requests });
      else reject(error);
    }
    function stop() {
      if (stopTimer !== undefined) return;
      update({ type: "stopping" });
      worker.postMessage({ type: "stop" });
      stopTimer = setTimeout(() => finish(new Error("This tab did not stop in time.")), 15_000);
    }
    signal.addEventListener("abort", stop, { once: true });
    worker.onerror = () => finish(new Error("The hosting code could not run."));
    worker.onmessage = ({ data }: MessageEvent<unknown>) => {
      const message = hostUpdate.safeParse(data);
      if (!message.success) return;
      if (message.data.type === "published")
        performance.mark("keepalive published", { detail: message.data.host });
      if (message.data.type === "failed") finish(new Error("This tab could not host the site."));
      if (message.data.type === "stopped")
        finish(
          startupExpired ? startupError : undefined,
          message.data.expired,
          message.data.requests,
        );
      if (message.data.type === "activity" && !signal.aborted && !startupExpired)
        activity(message.data);
      if (message.data.type === "hosting" && !signal.aborted && !startupExpired) {
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
