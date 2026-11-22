import { sameRun, type Host } from "../peers/gossip.ts";
import { readPeers } from "../peers/http.ts";
import { heartbeatSchema, HEARTBEAT_MS, PRESENCE_PATH } from "../peers/presence.ts";
import { presenceSummary } from "../peers/view.ts";
import type * as z from "zod";
import { MAX_MANIFEST_BYTES, parseRelease, readJSON, RELEASE_PATH } from "../release.ts";

export type Observation = Omit<z.infer<typeof presenceSummary>, "fallback">;

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
      if (host === undefined) {
        const report = await readPeers(location.origin, releaseID, signal);
        const now = Date.now();
        alternates =
          report === undefined
            ? []
            : [report.from, ...report.changes].filter(
                (peer) =>
                  !peer.left && (peer.endsAt === undefined || peer.endsAt > now) && !peer.departing,
              );
        if (alternates.length === 0 && report?.from.left === false) alternates.push(report.from);
        const index = Math.floor(Math.random() * alternates.length);
        host = alternates.splice(index, 1)[0];
      }
      if (host === undefined) throw new Error("No counting host.");
      const { fallback, ...observation } = await renewPresence(host, tab, releaseID, signal);
      alternates = fallback.filter((candidate) => !sameRun(candidate, observation.host));
      if (!signal.aborted) update(observation);
    } catch {
      // retry discovery; a newer release may be active after a deployment.
      host = alternates.pop();
      if (host === undefined) releaseID = undefined;
      if (!signal.aborted) update(undefined);
    } finally {
      if (!signal.aborted) timer = setTimeout(() => void beat(), HEARTBEAT_MS);
    }
  }
  signal.addEventListener("abort", stop, { once: true });
  await beat();
}
