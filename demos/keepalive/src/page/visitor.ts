import { FRESH_REPORT_MS, sameRun, type Change, type Host } from "../peers/gossip.ts";
import { readPeers } from "../peers/http.ts";
import {
  AUDIENCE_PATH,
  heartbeatSchema,
  HEARTBEAT_MS,
  PRESENCE_PATH,
  sampledTab,
} from "../peers/presence.ts";
import { audienceSnapshot, presenceSummary } from "../peers/view.ts";
import type * as z from "zod";
import { MAX_MANIFEST_BYTES, parseRelease, readJSON, RELEASE_PATH } from "../release.ts";

export type Observation = Omit<z.infer<typeof presenceSummary>, "fallback">;

async function findCountingHost(releaseID: string, signal: AbortSignal, failed?: Host) {
  const report = await readPeers(location.origin, releaseID, signal);
  if (report === undefined) return;
  const now = Date.now();
  const eligible = (peer: Change) =>
    !peer.left &&
    (peer.endsAt ?? Infinity) > now &&
    now - peer.reportedAt < FRESH_REPORT_MS &&
    (failed === undefined || !sameRun(failed, peer));
  const candidates = [report.from, ...report.changes].filter(
    (peer) => eligible(peer) && !peer.departing,
  );
  // on recovery, prefer the host that just answered the proxy's probe.
  const index = failed === undefined ? Math.floor(Math.random() * candidates.length) : 0;
  return candidates[index] ?? (eligible(report.from) ? report.from : undefined);
}

export async function renewPresence(
  host: Host,
  tab: string,
  releaseID: string,
  signal: AbortSignal,
) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(5_000)]);
  const url = new URL(PRESENCE_PATH, host.origin);
  const body = JSON.stringify(heartbeatSchema.parse({ tab, releaseID }));
  const send = () =>
    fetch(url, {
      method: "POST",
      body,
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      signal: deadline,
    });
  const response = await send().catch((err: unknown) => {
    deadline.throwIfAborted();
    if (!(err instanceof TypeError)) throw err;
    // the relay can close before fetch gets headers. the same tab refreshes
    // one lease even if the counting host already received the first POST.
    return send();
  });
  const report = presenceSummary.safeParse(await readJSON(response, 4_096, deadline));
  if (!report.success || !sameRun(host, report.data.host))
    throw new Error("The counting host changed.");
  return report.data;
}

export async function observeVisitors(
  signal: AbortSignal,
  update: (observation: Observation | undefined) => void,
) {
  const tab = crypto.randomUUID();
  let checkAudience = !sampledTab(tab);
  let releaseID: string | undefined;
  let host: Host | undefined;
  let alternates: Host[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;
  function stop() {
    clearTimeout(timer);
  }
  async function beat() {
    try {
      if (releaseID === undefined) {
        const deadline = AbortSignal.any([signal, AbortSignal.timeout(5_000)]);
        const response = await fetch(RELEASE_PATH, { cache: "no-store", signal: deadline });
        releaseID = (await parseRelease(await readJSON(response, MAX_MANIFEST_BYTES, deadline))).id;
      }
      if (checkAudience) {
        const deadline = AbortSignal.any([signal, AbortSignal.timeout(5_000)]);
        const summary = await fetch(AUDIENCE_PATH, { cache: "no-store", signal: deadline })
          .then(async (r) =>
            r.status === 204
              ? undefined
              : audienceSnapshot.parse(await readJSON(r, 4096, deadline)),
          )
          .catch(() => undefined);
        signal.throwIfAborted();
        if (summary?.releaseID === releaseID && summary.sampling) {
          update(summary);
          return;
        }
        // a missing, stale or small estimate resumes counting on this tick.
      }
      const deadline = AbortSignal.any([signal, AbortSignal.timeout(15_000)]);
      const currentRelease = releaseID;
      const selected = (host ??= await findCountingHost(currentRelease, deadline));
      if (selected === undefined) throw new Error("No counting host.");
      const { fallback, ...observation } = await renewPresence(
        selected,
        tab,
        currentRelease,
        deadline,
      ).catch(async (error: unknown) => {
        deadline.throwIfAborted();
        // try only one different run in this heartbeat, with the same tab ID.
        host = alternates.pop() ?? (await findCountingHost(currentRelease, deadline, selected));
        if (host === undefined) throw error;
        return renewPresence(host, tab, currentRelease, deadline);
      });
      checkAudience = !sampledTab(tab) && observation.sampling === true;
      alternates = fallback.filter((candidate) => !sameRun(candidate, observation.host));
      if (!signal.aborted) update(observation);
    } catch {
      // a newer release may be active after a deployment.
      host = undefined;
      alternates = [];
      releaseID = undefined;
      if (!signal.aborted) update(undefined);
    } finally {
      if (!signal.aborted) timer = setTimeout(() => void beat(), HEARTBEAT_MS);
    }
  }
  signal.addEventListener("abort", stop, { once: true });
  await beat();
}
