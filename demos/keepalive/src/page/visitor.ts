import { MAX_MESSAGE_BYTES, parseMessage, sameRun, type Change } from "../peers/gossip.ts";
import { readPeers } from "../peers/http.ts";
import { heartbeatSchema, HEARTBEAT_MS, PRESENCE_PATH } from "../peers/presence.ts";
import { MAX_MANIFEST_BYTES, parseRelease, readJSON, RELEASE_PATH } from "../release.ts";

export type Observation = {
  roster: Change[];
  hostRunID: string;
  startedAt: number;
};

export async function observeVisitors(
  signal: AbortSignal,
  update: (observation: Observation | undefined) => void,
) {
  const tab = crypto.randomUUID();
  let releaseID: string | undefined;
  let host: Change | undefined;
  let alternates: Change[] = [];
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
      const deadline = AbortSignal.any([signal, AbortSignal.timeout(5_000)]);
      const response = await fetch(new URL(PRESENCE_PATH, host.origin), {
        method: "POST",
        body: JSON.stringify(heartbeatSchema.parse({ tab, releaseID })),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
        signal: deadline,
      });
      const report = parseMessage(
        await readJSON(response, MAX_MESSAGE_BYTES, deadline),
        releaseID,
        Date.now(),
      );
      if (report === undefined || report.from.left || !sameRun(host, report.from))
        throw new Error("The counting host changed.");
      if (!signal.aborted)
        update({
          roster: [report.from, ...report.changes],
          hostRunID: report.from.runID,
          startedAt: report.startedAt,
        });
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
