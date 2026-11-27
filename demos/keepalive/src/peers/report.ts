import * as z from "zod/mini";
import { BOOTSTRAP_TURN_MS, STARTUP_MS } from "../policy.ts";
import { readJSON } from "../release.ts";
import {
  request,
  requireStatus,
  noReachableHost,
  NoReachableHost,
  PEER_REQUEST_MS,
} from "../network.ts";
import { hostSchema, hostOrigin, HOST_PARENT, PEERS_PATH, releaseIDSchema } from "./host.ts";
import { MAX_TABS_PER_HOST, SAMPLE_WEIGHT } from "./presence.ts";

export const MAX_MESSAGE_BYTES = 24 * 1024;
export const MAX_PEERS = 8_192;
export const MAX_CHANGES = 40;
export const FRESH_REPORT_MS = 60_000;
export const audienceSchema = z.strictObject({
  tabs: z.int().check(z.minimum(0), z.maximum((MAX_PEERS + 1) * MAX_TABS_PER_HOST * SAMPLE_WEIGHT)),
  hosts: z.int().check(z.minimum(1), z.maximum(MAX_PEERS + 1)),
  saturated: z.boolean(),
  sampling: z.boolean(),
});
// readers select runs from these facts, not names, certificates or ancestry.
// gossip extends this same shape and validates its additional fields.
export const reportedHost = z.extend(hostSchema, {
  seq: z.int().check(z.positive()),
  reportedAt: z.int().check(z.positive()),
  left: z.boolean(),
  startingUntil: z.int().check(z.nonnegative()),
  endsAt: z.optional(z.int().check(z.positive())),
  departing: z.optional(z.boolean()),
  tabs: z.optional(
    z.strictObject({
      count: z.int().check(z.minimum(0), z.maximum(MAX_TABS_PER_HOST * SAMPLE_WEIGHT)),
      observedAt: z.int().check(z.positive()),
    }),
  ),
});
export function peerReport<T extends z.core.SomeType>(change: T) {
  return z.strictObject({
    releaseID: releaseIDSchema,
    startedAt: z.int().check(z.minimum(Date.UTC(2026, 0, 1))),
    from: change,
    changes: z.array(change).check(z.maxLength(MAX_CHANGES)),
    audience: z.optional(audienceSchema),
  });
}
const selectionReport = peerReport(reportedHost);
export type ReportedHost = z.infer<typeof reportedHost>;

export function validReport(
  report: z.infer<typeof selectionReport>,
  releaseID: string,
  now: number,
  parent = HOST_PARENT,
) {
  const valid = (change: ReportedHost) =>
    hostOrigin(change.origin, parent) &&
    change.reportedAt <= now + 30_000 &&
    change.startingUntil <= now + STARTUP_MS + 30_000 &&
    (change.endsAt === undefined || change.endsAt <= now + BOOTSTRAP_TURN_MS + 30_000) &&
    (change.tabs === undefined || change.tabs.observedAt <= now + 30_000);
  return (
    report.releaseID === releaseID &&
    report.startedAt <= now + 30_000 &&
    valid(report.from) &&
    report.changes.every(valid)
  );
}

export async function readReport(origin: string, releaseID: string, signal: AbortSignal) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(PEER_REQUEST_MS)]);
  const response = await request(new URL(PEERS_PATH, origin), {
    signal: deadline,
    credentials: "omit",
  });
  if (noReachableHost(response)) {
    await response.body?.cancel().catch(() => {});
    throw new NoReachableHost();
  }
  const parsed = selectionReport.safeParse(
    await readJSON(await requireStatus(response), MAX_MESSAGE_BYTES, deadline),
  );
  if (parsed.success && validReport(parsed.data, releaseID, Date.now())) return parsed.data;
  return undefined;
}
