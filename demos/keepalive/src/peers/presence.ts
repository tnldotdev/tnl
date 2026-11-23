import * as z from "zod";

export const PRESENCE_PATH = "/__keepalive/presence";
export const AUDIENCE_PATH = "/__keepalive/audience";
export const HEARTBEAT_MS = 40_000;
export const TAB_LEASE_MS = 3 * HEARTBEAT_MS;
export const SAMPLE_WEIGHT = 4;
// other hosts' snapshots take longer to reach us than local heartbeats do.
export const REMOTE_TAB_REPORT_MS = 3 * 60_000;
export const MAX_TABS_PER_HOST = 512;

// use a wide gap so small changes in a peer's estimate don't flip the policy.
export function sampleAudience(tabs: number, sampling: boolean) {
  return sampling ? tabs > 10_000 : tabs >= 20_000;
}

export function sampledTab(tab: string) {
  // the low two bits of a random tab UUID stay fixed for its whole lifetime.
  return Number.parseInt(tab.slice(-1), 16) % SAMPLE_WEIGHT === 0;
}

export const heartbeatSchema = z.strictObject({
  tab: z.uuid(),
  releaseID: z.string().regex(/^[a-f0-9]{64}$/),
});

export class TabLeases {
  readonly #expires = new Map<string, number>();
  #sample = 0;

  touch(tab: string, now: number) {
    this.count(now);
    if (!this.#expires.has(tab)) {
      if (this.#expires.size >= MAX_TABS_PER_HOST) return false;
      if (sampledTab(tab)) this.#sample++;
    }
    // insertion order is expiry order; refresh moves the tab to the end.
    this.#expires.delete(tab);
    this.#expires.set(tab, now + TAB_LEASE_MS);
    return true;
  }

  count(now: number, sampling = false) {
    for (const [tab, expiresAt] of this.#expires) {
      if (expiresAt > now) break;
      this.#expires.delete(tab);
      if (sampledTab(tab)) this.#sample--;
    }
    return sampling ? this.#sample * SAMPLE_WEIGHT : this.#expires.size;
  }
}
