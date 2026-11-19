import * as z from "zod";
import { hostNameSchema } from "./host-names.ts";
import { BOOTSTRAP_TURN_MS, REPLACE_BEFORE_MS, STARTUP_MS } from "./hosting/policy.ts";
import { MAX_TABS_PER_HOST, TAB_LEASE_MS } from "./presence.ts";

export const HOST_PARENT = "hosts.keepthisalive.com";
export const SHARED_HOST = `https://prod.${HOST_PARENT}`;
export const PEERS_PATH = "/__keepalive/peers";
export const MAX_MESSAGE_BYTES = 24 * 1024;
export const MAX_PEERS = 256;
export const MAX_CHANGES = 24;
export const PROBE_MS = 2_000;
export const SUSPECT_MS = 15_000;
export const QUIET_MS = 60_000;
export const KEEP_MS = 5 * 60_000;
const COOLDOWN_MS = 30_000;
const EARLIEST_START = Date.UTC(2026, 0, 1);
export const releaseIDSchema = z.string().regex(/^[a-f0-9]{64}$/);
export const runIDSchema = z.string().regex(/^srun_[A-Za-z0-9]{22}$/);
export const httpsOriginSchema = z
  .string()
  .max(261)
  .refine((value) => {
    const url = URL.parse(value);
    return url?.protocol === "https:" && url.origin === value;
  });
export const hostSchema = z.object({
  origin: httpsOriginSchema,
  publisherID: z.string().regex(/^pub_[A-Za-z0-9]{22}$/),
  runID: runIDSchema,
  runNumber: z
    .string()
    .regex(/^[1-9]\d{0,18}$/)
    .refine((value) => value.length < 19 || value <= "9223372036854775807"),
});
const changeSchema = hostSchema.extend({
  seq: z.int().positive(),
  left: z.boolean(),
  startingUntil: z.int().nonnegative(),
  name: hostNameSchema.optional(),
  endsAt: z.int().positive().optional(),
  departing: z.boolean().optional(),
  tabs: z
    .strictObject({
      count: z.int().min(0).max(MAX_TABS_PER_HOST),
      observedAt: z.int().positive(),
    })
    .optional(),
  copyFrom: runIDSchema.optional(),
  invitedBy: runIDSchema.optional(),
  replacedBy: runIDSchema.optional(),
});
const startTimeSchema = z.int().min(EARLIEST_START);
const messageSchema = z.strictObject({
  releaseID: releaseIDSchema,
  startedAt: startTimeSchema,
  from: changeSchema,
  changes: z.array(changeSchema).max(MAX_CHANGES),
});
export type Host = Readonly<z.infer<typeof hostSchema>>;
export type Change = Readonly<z.infer<typeof changeSchema>>;
export const hostDetailsSchema = changeSchema.pick({
  name: true,
  endsAt: true,
  departing: true,
  copyFrom: true,
  invitedBy: true,
  replacedBy: true,
});
type HostDetails = z.infer<typeof hostDetailsSchema>;
export type GossipMessage = Readonly<z.infer<typeof messageSchema>>;

export type PeerTransport = (
  target: Host,
  message: GossipMessage,
  helper?: Host,
) => Promise<GossipMessage | undefined>;

export function hostOrigin(value: unknown, parent = HOST_PARENT): value is string {
  if (typeof value !== "string" || value.length > 261) return false;
  const url = URL.parse(value);
  if (url?.protocol !== "https:" || url.origin !== value || url.port !== "") return false;
  if (!url.hostname.endsWith(`.${parent}`)) return false;
  return /^p-[a-z2-7]{26}$/.test(url.hostname.slice(0, -(parent.length + 1)));
}

export function parseHost(value: unknown, parent = HOST_PARENT): Host | undefined {
  const parsed = hostSchema.safeParse(value);
  if (parsed.success && hostOrigin(parsed.data.origin, parent)) return parsed.data;
  return undefined;
}

export function parseMessage(
  value: unknown,
  releaseID: string,
  now: number,
  parent = HOST_PARENT,
): GossipMessage | undefined {
  const parsed = messageSchema.safeParse(value);
  if (
    !parsed.success ||
    parsed.data.releaseID !== releaseID ||
    parsed.data.startedAt > now + 30_000
  )
    return;
  const valid = (change: Change) =>
    hostOrigin(change.origin, parent) &&
    change.startingUntil <= now + STARTUP_MS + 30_000 &&
    (change.endsAt === undefined || change.endsAt <= now + BOOTSTRAP_TURN_MS + 30_000) &&
    (change.tabs === undefined || change.tabs.observedAt <= now + 30_000);
  if (valid(parsed.data.from) && parsed.data.changes.every(valid)) return parsed.data;
  return undefined;
}

export function sameRun(a: Host, b: Host): boolean {
  return (
    a.publisherID === b.publisherID &&
    a.origin === b.origin &&
    a.runID === b.runID &&
    a.runNumber === b.runNumber
  );
}

type Seen = { change: Change; heardAt: number; suspectAt?: number };

function isNewerChange(next: Change, current: Change): boolean {
  if (next.runNumber !== current.runNumber) {
    return BigInt(next.runNumber) > BigInt(current.runNumber);
  }
  // a publisher can restart at the same url, but a departed run can't come back.
  return sameRun(next, current) && !current.left && next.seq > current.seq;
}

export class Gossip {
  readonly releaseID: string;
  readonly #peers = new Map<string, Seen>();
  #self: Change;
  #startedAt: number;
  #nextStart = 0;
  #round = 0;
  #probing = false;

  constructor(releaseID: string, host: Host, startedAt: number, details?: HostDetails) {
    this.releaseID = releaseID;
    this.#self = { ...host, ...details, seq: 1, left: false, startingUntil: 0 };
    this.#startedAt = startedAt;
  }

  get startedAt() {
    return this.#startedAt;
  }

  get size() {
    return this.#peers.size;
  }

  update(details: HostDetails) {
    this.#self = { ...this.#self, ...details };
  }

  observeTabs(count: number, now: number) {
    this.#self = { ...this.#self, tabs: { count, observedAt: now } };
  }

  roster(now: number) {
    const live = [this.#self, ...this.hosts(now)];
    const former = [...this.#peers.values()]
      .filter(({ change }) => change.left)
      .map(({ change }) => change)
      .slice(-8);
    return [...live, ...former];
  }

  tabs(now: number) {
    return reportedTabs([this.#self, ...this.hosts(now)], now);
  }

  receive(message: GossipMessage, now: number) {
    if (message.releaseID !== this.releaseID) return;
    this.#startedAt = Math.min(this.#startedAt, message.startedAt);
    this.#forgetOldPeers(now);
    // consider the sender first in case the peer list is almost full.
    for (const change of [message.from, ...message.changes]) {
      this.#rememberChange(change, change === message.from, now);
    }
  }

  #rememberChange(change: Change, fromSender: boolean, now: number) {
    if (change.publisherID === this.#self.publisherID || change.origin === this.#self.origin) {
      return;
    }
    const previous = this.#peers.get(change.publisherID);
    if (previous !== undefined && !isNewerChange(change, previous.change)) return;
    if (previous === undefined && this.#peers.size >= MAX_PEERS) return;

    // hearing about a known run can update its report, but not when it last replied.
    if (!fromSender && previous !== undefined && sameRun(previous.change, change)) {
      this.#peers.set(change.publisherID, { ...previous, change });
    } else {
      this.#peers.set(change.publisherID, { change, heardAt: now });
    }
  }

  message(now: number): GossipMessage {
    this.#forgetOldPeers(now);
    if (!this.#self.left) this.#self = { ...this.#self, seq: this.#self.seq + 1 };
    const records = [...this.#peers.values()];
    // rotate through small groups so a peer can repair a missed change over time.
    const changes: Change[] = [];
    for (let index = 0; index < Math.min(MAX_CHANGES, records.length); index++) {
      const peer = records[(this.#round + index) % records.length];
      if (peer !== undefined) changes.push(peer.change);
    }
    this.#round += changes.length;
    return { releaseID: this.releaseID, startedAt: this.#startedAt, from: this.#self, changes };
  }

  leave(now: number): GossipMessage {
    this.#self = { ...this.#self, seq: this.#self.seq + 1, left: true, startingUntil: 0 };
    return this.message(now);
  }

  hosts(now: number): readonly Change[] {
    return this.#countedPeers(now).map(({ change }) => change);
  }

  #forgetOldPeers(now: number) {
    for (const [id, peer] of this.#peers) {
      if (now - peer.heardAt >= KEEP_MS) this.#peers.delete(id);
    }
  }

  #countedPeers(now: number) {
    this.#forgetOldPeers(now);
    const origins = new Set<string>();
    return [...this.#peers.values()].filter(({ change, heardAt, suspectAt }) => {
      if (
        change.left ||
        (change.endsAt !== undefined && change.endsAt <= now) ||
        now - heardAt >= QUIET_MS ||
        (suspectAt !== undefined && now - suspectAt >= SUSPECT_MS) ||
        origins.has(change.origin)
      )
        return false;
      origins.add(change.origin);
      return true;
    });
  }

  async probe(clock: () => number, random: () => number, send: PeerTransport): Promise<void> {
    if (this.#probing || this.#self.left) return;
    this.#forgetOldPeers(clock());
    // try suspect and quiet hosts too: a suspended tab can return at the same URL.
    const candidates = [...this.#peers.values()].filter(({ change }) => !change.left);
    const selected = candidates[Math.floor(random() * candidates.length)];
    if (selected === undefined) return;
    const target = selected.change;
    const helpers = this.hosts(clock()).filter((host) => host.publisherID !== target.publisherID);
    const helper = helpers[Math.floor(random() * helpers.length)];
    this.#probing = true;
    try {
      const message = this.message(clock());
      let reply = await this.#probeReply(() => send(target, message), target);
      if (reply === undefined && helper !== undefined) {
        // ask one other host to check the same run.
        reply = await this.#probeReply(() => send(target, message, helper), target);
      }
      const now = clock();
      if (reply !== undefined) {
        this.receive(reply, now);
        const current = this.#peers.get(target.publisherID);
        if (
          current !== undefined &&
          sameRun(current.change, target) &&
          !current.change.left &&
          reply.from.seq >= current.change.seq
        ) {
          this.#peers.set(target.publisherID, { change: current.change, heardAt: now });
        }
      } else if (this.#peers.get(target.publisherID) === selected) {
        // don't mark an updated peer record based on an earlier failed check.
        selected.suspectAt ??= now;
      }
    } finally {
      this.#probing = false;
    }
  }

  async #probeReply(send: () => ReturnType<PeerTransport>, target: Host) {
    try {
      const reply = await send();
      if (reply?.releaseID === this.releaseID && sameRun(target, reply.from)) return reply;
      return undefined;
    } catch {
      return undefined;
    }
  }

  readyBeyondWindow(now: number) {
    const cutoff = now + REPLACE_BEFORE_MS;
    return [this.#self, ...this.hosts(now)].filter(
      ({ endsAt, departing, left }) =>
        !left && !departing && (endsAt === undefined || endsAt > cutoff),
    ).length;
  }

  maybeStart(now: number, target: number, offer: () => boolean, random = Math.random): boolean {
    if (this.#self.left || now < this.#nextStart || now < this.#self.startingUntil) return false;
    const peers = this.#countedPeers(now);
    const starting = peers.filter(({ change }) => change.startingUntil > now).length;
    if (this.readyBeyondWindow(now) + starting >= target || !offer()) return false;
    this.#self = { ...this.#self, startingUntil: now + STARTUP_MS };
    this.#nextStart = now + COOLDOWN_MS + Math.floor(random() * 5_000);
    return true;
  }

  finishStart() {
    this.#self = { ...this.#self, startingUntil: 0 };
  }
}

export function reportedTabs(changes: readonly Change[], now: number) {
  const seen = new Set<string>();
  let tabs = 0;
  for (const { publisherID, origin, left, endsAt, tabs: tally } of changes) {
    if (
      left ||
      (endsAt !== undefined && endsAt <= now) ||
      seen.has(publisherID) ||
      seen.has(origin) ||
      tally === undefined ||
      now - tally.observedAt >= TAB_LEASE_MS
    )
      continue;
    seen.add(publisherID);
    seen.add(origin);
    tabs += tally.count;
  }
  return tabs;
}
