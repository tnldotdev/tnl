import * as z from "zod";

export const PRESENCE_PATH = "/__keepalive/presence";
export const HEARTBEAT_MS = 20_000;
export const TAB_LEASE_MS = 60_000;
// other hosts' snapshots take longer to reach us than local heartbeats do.
export const REMOTE_TAB_REPORT_MS = 3 * 60_000;
export const MAX_TABS_PER_HOST = 512;
export const heartbeatSchema = z.strictObject({
  tab: z.uuid(),
  releaseID: z.string().regex(/^[a-f0-9]{64}$/),
});

export class TabLeases {
  readonly #expires = new Map<string, number>();

  touch(tab: string, now: number) {
    this.count(now);
    if (this.#expires.size >= MAX_TABS_PER_HOST && !this.#expires.has(tab)) return false;
    // insertion order is expiry order; refresh moves the tab to the end.
    this.#expires.delete(tab);
    this.#expires.set(tab, now + TAB_LEASE_MS);
    return true;
  }

  count(now: number) {
    for (const [tab, expiresAt] of this.#expires) {
      if (expiresAt > now) break;
      this.#expires.delete(tab);
    }
    return this.#expires.size;
  }
}
