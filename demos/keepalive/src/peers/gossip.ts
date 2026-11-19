import * as z from "zod";
import { hostNameSchema } from "./host-names.ts";
import { BOOTSTRAP_TURN_MS, REPLACE_BEFORE_MS, STARTUP_MS } from "../policy.ts";
import { MAX_TABS_PER_HOST, TAB_LEASE_MS } from "./presence.ts";
import { certificateReport } from "../hosting/certificate.ts";

export const HOST_PARENT = "hosts.keepthisalive.com";
export const SHARED_HOST = `https://prod.${HOST_PARENT}`;
export const PEERS_PATH = "/__keepalive/peers";
export const MAX_MESSAGE_BYTES = 24 * 1024;
export const MAX_PEERS = 8_192;
export const MAX_CHANGES = 24;
export const PROBE_MS = 2_000;
export const SUSPECT_MS = 15_000;
export const KEEP_MS = 5 * 60_000;
const PRIORITY_CHANGES = 8;
const PRIORITY_SENDS = 3;
const FRESH_CHANGES = 8;
const FRESH_QUEUE_LIMIT = 128;
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
  reportedAt: z.int().positive(),
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
  certificate: certificateReport.optional(),
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
  certificate: true,
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
    change.reportedAt <= now + 30_000 &&
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

export function hostIdentity({ origin, publisherID, runID, runNumber }: Host): Host {
  return { origin, publisherID, runID, runNumber };
}

type Seen = { change: Change; slot: number; suspectAt?: number };

function recordDeadline(change: Change) {
  return (
    (change.left ? change.reportedAt : Math.max(change.reportedAt, change.endsAt ?? 0)) + KEEP_MS
  );
}

function importantChange(next: Change, previous: Change) {
  return (
    !sameRun(next, previous) ||
    next.left !== previous.left ||
    next.startingUntil !== previous.startingUntil ||
    next.departing !== previous.departing ||
    next.certificate?.fingerprint !== previous.certificate?.fingerprint
  );
}

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
  readonly #slots: Seen[] = [];
  readonly #priority = new Map<string, number>();
  readonly #fresh = new Set<string>();
  #rotation = 0;
  #self: Change;
  #startedAt: number;
  #nextStart = 0;
  #nextPrune = Infinity;
  #saturatedUntil = 0;
  #probing = false;

  constructor(releaseID: string, host: Host, startedAt: number, details?: HostDetails) {
    this.releaseID = releaseID;
    this.#self = {
      ...host,
      ...details,
      seq: 1,
      reportedAt: startedAt,
      left: false,
      startingUntil: 0,
    };
    this.#startedAt = startedAt;
  }

  get startedAt() {
    return this.#startedAt;
  }

  get self(): Host {
    return hostIdentity(this.#self);
  }

  get size() {
    return this.#peers.size;
  }

  saturated(now: number) {
    return this.#saturatedUntil > now;
  }

  update(details: HostDetails) {
    this.#self = { ...this.#self, ...details };
  }

  observeTabs(count: number, now: number) {
    this.#self = { ...this.#self, tabs: { count, observedAt: now } };
  }

  roster(now: number) {
    this.#forgetOldPeers(now);
    return [this.#self, ...[...this.#peers.values()].map(({ change }) => change)];
  }

  tabs(now: number) {
    return this.tabSnapshot(now).total;
  }

  tabSnapshot(now: number, hosts = this.hosts(now)) {
    return {
      local: reportedTabs([this.#self], now),
      total: reportedTabs([this.#self, ...hosts], now),
    };
  }

  canRetire(now: number, target: number, hosts: readonly Change[]) {
    if (this.saturated(now) || this.readyBeyondWindow(now, hosts) < target) return false;
    // don't call a host surplus when most peers' tab counts are too old to use.
    return (
      hosts.filter(({ tabs }) => tabs !== undefined && now - tabs.observedAt < TAB_LEASE_MS)
        .length >=
      hosts.length * 0.9
    );
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
    if (recordDeadline(change) <= now) return;
    const previous = this.#peers.get(change.publisherID);
    if (previous !== undefined && !isNewerChange(change, previous.change)) {
      if (
        fromSender &&
        previous.suspectAt !== undefined &&
        !previous.change.left &&
        !change.left &&
        change.seq >= previous.change.seq &&
        sameRun(change, previous.change)
      ) {
        delete previous.suspectAt;
        this.#prioritize(change.publisherID);
      }
      return;
    }
    if (previous === undefined && this.#peers.size >= MAX_PEERS) {
      this.#saturatedUntil = now + KEEP_MS;
      return;
    }
    const suspectAt =
      previous === undefined || !sameRun(change, previous.change) ? undefined : previous.suspectAt;
    // an older forwarded report can't undo a failed probe; a fresh report
    // after the grace period can show the host is serving another browser.
    const recovered =
      suspectAt !== undefined && (fromSender || change.reportedAt >= suspectAt + SUSPECT_MS);
    const slot = previous?.slot ?? this.#slots.length;
    const entry =
      suspectAt !== undefined && !recovered ? { change, slot, suspectAt } : { change, slot };
    this.#peers.set(change.publisherID, entry);
    this.#slots[slot] = entry;
    this.#nextPrune = Math.min(this.#nextPrune, recordDeadline(change));
    if (previous === undefined || recovered || importantChange(change, previous.change))
      this.#prioritize(change.publisherID);
    else if (now - change.reportedAt < TAB_LEASE_MS) {
      // send recent updates as well as cycling through the older reports.
      this.#fresh.delete(change.publisherID);
      this.#fresh.add(change.publisherID);
      const oldest = this.#fresh.values().next();
      if (this.#fresh.size > FRESH_QUEUE_LIMIT && !oldest.done) this.#fresh.delete(oldest.value);
    }
  }

  message(now: number): GossipMessage {
    this.#forgetOldPeers(now);
    if (!this.#self.left) this.#self = { ...this.#self, seq: this.#self.seq + 1, reportedAt: now };
    const selected = new Set<string>();
    const changes: Change[] = [];
    const count = Math.min(PRIORITY_CHANGES, this.#priority.size);
    for (let i = 0; i < count; i++) {
      const next = this.#priority.entries().next();
      if (next.done) break;
      const [id, remaining] = next.value;
      const peer = this.#peers.get(id);
      this.#priority.delete(id);
      if (peer === undefined) continue;
      selected.add(id);
      changes.push(peer.change);
      if (remaining > 1) this.#priority.set(id, remaining - 1);
    }
    let fresh = 0;
    for (const id of this.#fresh) {
      if (fresh >= FRESH_CHANGES) break;
      this.#fresh.delete(id);
      const peer = this.#peers.get(id);
      if (peer === undefined || selected.has(id) || now - peer.change.reportedAt >= TAB_LEASE_MS)
        continue;
      selected.add(id);
      changes.push(peer.change);
      fresh++;
    }
    // even during churn, reserve space for ordinary reports.
    const limit = Math.min(MAX_CHANGES, this.#peers.size);
    while (changes.length < limit) {
      this.#rotation %= this.#slots.length;
      const peer = this.#slots[this.#rotation++];
      if (peer === undefined || selected.has(peer.change.publisherID)) continue;
      selected.add(peer.change.publisherID);
      changes.push(peer.change);
    }
    return { releaseID: this.releaseID, startedAt: this.#startedAt, from: this.#self, changes };
  }

  leave(now: number): GossipMessage {
    this.#self = {
      ...this.#self,
      seq: this.#self.seq + 1,
      reportedAt: now,
      left: true,
      startingUntil: 0,
    };
    return this.message(now);
  }

  hosts(now: number): readonly Change[] {
    return this.#countedPeers(now).map(({ change }) => change);
  }

  #forgetOldPeers(now: number) {
    if (now < this.#nextPrune) return;
    this.#nextPrune = Infinity;
    for (const [id, peer] of this.#peers) {
      const deadline = recordDeadline(peer.change);
      if (deadline <= now) {
        this.#peers.delete(id);
        this.#priority.delete(id);
        this.#fresh.delete(id);
        const last = this.#slots.pop();
        if (last !== undefined && last !== peer) {
          this.#slots[peer.slot] = last;
          last.slot = peer.slot;
        }
      } else {
        this.#nextPrune = Math.min(this.#nextPrune, deadline);
      }
    }
  }

  #prioritize(id: string) {
    this.#priority.set(id, PRIORITY_SENDS);
  }

  #countedPeers(now: number) {
    this.#forgetOldPeers(now);
    const origins = new Set<string>();
    return [...this.#peers.values()].filter(({ change, suspectAt }) => {
      if (
        change.left ||
        (change.endsAt !== undefined && change.endsAt <= now) ||
        (change.endsAt === undefined && now - change.reportedAt >= KEEP_MS) ||
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
    const now = clock();
    const eligible = ({ change }: Seen) => !change.left && (change.endsAt ?? Infinity) > now;
    let selected: Seen | undefined;
    for (let i = 0; i < 8; i++) {
      const candidate = this.#slots[Math.floor(random() * this.#slots.length)];
      if (candidate !== undefined && eligible(candidate)) {
        selected = candidate;
        break;
      }
    }
    if (selected === undefined) {
      const candidates = this.#slots.filter(eligible);
      selected = candidates[Math.floor(random() * candidates.length)];
    }
    if (selected === undefined) return;
    const target = selected.change;
    this.#probing = true;
    try {
      const message = this.message(clock());
      let reply = await this.#probeReply(() => send(target, message), target);
      if (reply === undefined) {
        // ask one other host to check the same run.
        const helpers = this.hosts(clock()).filter(
          (host) => host.publisherID !== target.publisherID,
        );
        const helper = helpers[Math.floor(random() * helpers.length)];
        if (helper !== undefined)
          reply = await this.#probeReply(() => send(target, message, helper), target);
      }
      if (reply !== undefined) {
        this.receive(reply, clock());
      } else if (
        this.#peers.get(target.publisherID) === selected &&
        selected.suspectAt === undefined
      ) {
        // don't mark an updated peer record based on an earlier failed check.
        selected.suspectAt = clock();
        this.#prioritize(target.publisherID);
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

  readyBeyondWindow(now: number, hosts = this.hosts(now)) {
    const cutoff = now + REPLACE_BEFORE_MS;
    return [this.#self, ...hosts].filter(
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
