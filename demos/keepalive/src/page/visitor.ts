import { sameRun, type Host } from "../peers/host.ts";
import { FRESH_REPORT_MS, readReport, type ReportedHost } from "../peers/report.ts";
import { AUDIENCE_PATH, heartbeatSchema, PRESENCE_PATH, sampledTab } from "../peers/presence.ts";
import { audienceSnapshot, presenceSummary } from "../peers/audience.ts";
import type * as z from "zod/mini";
import { loadRelease, readJSON } from "../release.ts";
import {
  HTTPFailure,
  NoReachableHost,
  PEER_REQUEST_MS,
  TransportFailure,
  request,
  requireStatus,
} from "../network.ts";

export type Observation = Omit<z.infer<typeof presenceSummary>, "fallback">;

class MissingPeerReport extends Error {}

async function findCountingHost(releaseID: string, signal: AbortSignal, failed?: Host) {
  const report = await readReport(location.origin, releaseID, signal);
  if (report === undefined) throw new MissingPeerReport("No matching host report.");
  const now = Date.now();
  const eligible = (peer: ReportedHost) =>
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
  async function send() {
    const response = await request(url, {
      method: "POST",
      body,
      credentials: "omit",
      signal: deadline,
    });
    const report = presenceSummary.safeParse(
      await readJSON(await requireStatus(response), 4_096, deadline),
    );
    if (!report.success || !sameRun(host, report.data.host))
      throw new Error("The counting host changed.");
    return report.data;
  }
  return send().catch((err: unknown) => {
    deadline.throwIfAborted();
    if (!(err instanceof TransportFailure)) throw err;
    // the relay can close before fetch gets headers. the same tab refreshes
    // one lease even if the counting host already received the first POST.
    return send();
  });
}

export function createVisitorCheck() {
  const tab = crypto.randomUUID();
  let checkAudience = !sampledTab(tab);
  let releaseID: string | undefined;
  let host: Host | undefined;
  let alternates: Host[] = [];
  return async function check(signal: AbortSignal): Promise<Observation | null> {
    signal.throwIfAborted();
    try {
      releaseID ??= (await loadRelease(signal)).id;
      if (checkAudience) {
        const deadline = AbortSignal.any([signal, AbortSignal.timeout(5_000)]);
        const summary = await request(AUDIENCE_PATH, { signal: deadline })
          .then(async (r) =>
            r.status === 204
              ? undefined
              : audienceSnapshot.parse(await readJSON(await requireStatus(r), 4096, deadline)),
          )
          .catch(() => undefined);
        signal.throwIfAborted();
        if (summary?.releaseID === releaseID && summary.sampling) return summary;
        // a missing, stale or small estimate resumes counting on this tick.
      }
      // allow two presence attempts and one complete proxy discovery.
      const deadline = AbortSignal.any([signal, AbortSignal.timeout(PEER_REQUEST_MS + 11_000)]);
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
        const alternate = alternates.pop();
        host = alternate ?? (await findCountingHost(currentRelease, deadline, selected));
        if (host === undefined) throw error;
        try {
          return await renewPresence(host, tab, currentRelease, deadline);
        } catch (error) {
          // dead cached hosts do not prove the site is down. ask the proxy.
          if (alternate !== undefined) await readReport(location.origin, currentRelease, deadline);
          throw error;
        }
      });
      checkAudience = !sampledTab(tab) && observation.sampling === true;
      alternates = fallback.filter((candidate) => !sameRun(candidate, observation.host));
      signal.throwIfAborted();
      return observation;
    } catch (error) {
      signal.throwIfAborted();
      host = undefined;
      alternates = [];
      checkAudience = false;
      // only discard the manifest when the active release might have changed.
      if (
        error instanceof MissingPeerReport ||
        (error instanceof HTTPFailure && error.status === 400)
      )
        releaseID = undefined;
      if (error instanceof NoReachableHost) return null;
      throw error;
    }
  };
}
