import * as z from "zod";
import { hostNameSchema } from "./host-names.ts";
import { BOOTSTRAP_TURN_MS, INVITATION_ACK_MS, REPLACE_BEFORE_MS, STARTUP_MS } from "../policy.ts";
import { MAX_TABS_PER_HOST, REMOTE_TAB_REPORT_MS, SAMPLE_WEIGHT } from "./presence.ts";
import { certificateReport, newerCertificate } from "../hosting/certificate.ts";

export const HOST_PARENT = "live.hosts.keepthisalive.com";
export const SHARED_HOST = `https://prod.${HOST_PARENT}`;
export const PEERS_PATH = "/__keepalive/peers";
export const MAX_MESSAGE_BYTES = 24 * 1024;
export const MAX_PEERS = 8_192;
export const MAX_CHANGES = 40;
const MAX_HOST_HISTORY = 128;
export const PROBE_MS = 2_000;
export const FRESH_REPORT_MS = 60_000;
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
      count: z
        .int()
        .min(0)
        .max(MAX_TABS_PER_HOST * SAMPLE_WEIGHT),
      observedAt: z.int().positive(),
    })
    .optional(),
  copyFrom: runIDSchema.optional(),
  certificate: certificateReport.optional(),
});
const startTimeSchema = z.int().min(EARLIEST_START);
export const audienceSchema = z.strictObject({
  tabs: z
    .int()
    .min(0)
    .max((MAX_PEERS + 1) * MAX_TABS_PER_HOST * SAMPLE_WEIGHT),
  hosts: z
    .int()
    .min(1)
    .max(MAX_PEERS + 1),
  saturated: z.boolean(),
  sampling: z.boolean(),
});
const messageSchema = z.strictObject({
  releaseID: releaseIDSchema,
  startedAt: startTimeSchema,
  from: changeSchema,
  changes: z.array(changeSchema).max(MAX_CHANGES),
  audience: audienceSchema.optional(),
});
export type Host = Readonly<z.infer<typeof hostSchema>>;
export type Change = Readonly<z.infer<typeof changeSchema>>;
export type HostHistory = Pick<Change, "runID" | "name" | "endsAt" | "copyFrom" | "left"> & {
  unreachable?: boolean | undefined;
};
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

type PriorityReport = { id: string; sent: number; queued: number };

function preferredReport(a: PriorityReport, b: PriorityReport) {
  return a.sent < b.sent || (a.sent === b.sent && a.queued > b.queued);
}

// an indexed heap keeps one entry per publisher across the send tiers.
class PriorityReports {
  readonly #entries: PriorityReport[] = [];
  readonly #positions = new Map<string, number>();
  #queued = 0;

  enqueue(id: string) {
    this.delete(id);
    this.restore({ id, sent: 0, queued: ++this.#queued });
  }

  delete(id: string) {
    const index = this.#positions.get(id);
    if (index !== undefined) this.#remove(index);
  }

  take() {
    return this.#remove(0);
  }

  restore(report: PriorityReport) {
    if (report.sent < PRIORITY_SENDS) this.#place(this.#entries.length, report);
  }

  #remove(index: number) {
    const report = this.#entries[index];
    if (report === undefined) return;
    this.#positions.delete(report.id);
    const last = this.#entries.pop();
    if (last !== undefined && last !== report) this.#place(index, last);
    return report;
  }

  #place(index: number, report: PriorityReport) {
    while (index > 0) {
      const parentIndex = Math.floor((index - 1) / 2);
      const parent = this.#entries[parentIndex];
      if (parent === undefined || !preferredReport(report, parent)) break;
      this.#set(index, parent);
      index = parentIndex;
    }
    while (true) {
      let childIndex = 2 * index + 1;
      let child = this.#entries[childIndex];
      if (child === undefined) break;
      const right = this.#entries[childIndex + 1];
      if (right !== undefined && preferredReport(right, child)) {
        child = right;
        childIndex++;
      }
      if (!preferredReport(child, report)) break;
      this.#set(index, child);
      index = childIndex;
    }
    this.#set(index, report);
  }

  #set(index: number, report: PriorityReport) {
    this.#entries[index] = report;
    this.#positions.set(report.id, index);
  }
}

function recordDeadline(change: Change) {
  return (
    (change.left ? change.reportedAt : Math.max(change.reportedAt, change.endsAt ?? 0)) + KEEP_MS
  );
}

function liveCertificate({ change, suspectAt }: Seen, now: number) {
  if (
    change.left ||
    (change.endsAt ?? change.reportedAt + KEEP_MS) <= now ||
    (suspectAt !== undefined && suspectAt + SUSPECT_MS <= now) ||
    change.certificate === undefined ||
    change.certificate.expiresAt <= now
  )
    return undefined;
  return change.certificate;
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
  readonly #history = new Map<string, HostHistory>();
  readonly #slots: Seen[] = [];
  readonly #priority = new PriorityReports();
  readonly #fresh = new Set<string>();
  #certificateHolder: Seen | undefined;
  #rotation = 0;
  #self: Change;
  #startedAt: number;
  #nextStart = 0;
  #nextPrune = Infinity;
  #saturatedUntil = 0;
  #probing = false;
  #presence:
    | {
        at: number;
        until: number;
        hosts: number;
        remoteTabs: number;
        fallback: readonly Host[];
      }
    | undefined;

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

  hostHistory(now: number): HostHistory[] {
    this.#forgetOldPeers(now);
    return [
      historyEntry(this.#self),
      ...[...this.#peers.values()].map(({ change, suspectAt }) =>
        historyEntry(
          change,
          !change.left && suspectAt !== undefined && now >= suspectAt + SUSPECT_MS,
        ),
      ),
      ...[...this.#history.values()].reverse(),
    ];
  }

  #archive(change: Change) {
    // never feed the display history back into gossip, routing or admission.
    this.#history.set(change.runID, { ...historyEntry(change), left: true });
    if (this.#history.size <= MAX_HOST_HISTORY) return;
    const oldest = this.#history.keys().next();
    if (!oldest.done) this.#history.delete(oldest.value);
  }

  tabs(now: number) {
    return this.tabSnapshot(now).total;
  }

  tabSnapshot(now: number, hosts = this.hosts(now)) {
    const local = reportedTabs([this.#self], now);
    return { local, total: local + reportedTabs(hosts, now, REMOTE_TAB_REPORT_MS, this.#self) };
  }

  // local leases change on every heartbeat; the remote view changes only on
  // a peer update, a suspect deadline, or the expiry of a host or tab report.
  presenceView(now: number) {
    const cached = this.#presence;
    if (cached !== undefined && cached.at <= now && now < cached.until) return cached;
    const peers = this.#countedPeers(now);
    const fallback: Host[] = [];
    let remoteTabs = 0;
    let until = Infinity;
    for (const { change, suspectAt } of peers) {
      until = Math.min(until, change.endsAt ?? change.reportedAt + KEEP_MS);
      if (suspectAt !== undefined) until = Math.min(until, suspectAt + SUSPECT_MS);
      if (change.tabs !== undefined && now < change.tabs.observedAt + REMOTE_TAB_REPORT_MS) {
        until = Math.min(until, change.tabs.observedAt + REMOTE_TAB_REPORT_MS);
        remoteTabs += change.tabs.count;
      }
      if (!change.departing) fallback.push(change);
    }
    return (this.#presence = { at: now, until, hosts: peers.length + 1, remoteTabs, fallback });
  }

  canRetire(now: number, target: number, hosts: readonly Change[]) {
    if (this.saturated(now) || this.readyBeyondWindow(now, hosts) < target) return false;
    // don't call a host surplus when most peers' tab counts are too old to use.
    return (
      hosts.filter(({ tabs }) => tabs !== undefined && now - tabs.observedAt < FRESH_REPORT_MS)
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
        // the same report can clear local suspicion without resetting its sends.
        delete previous.suspectAt;
        this.#presence = undefined;
        this.#considerCertificate(previous, now);
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
    if (previous !== undefined && !sameRun(change, previous.change)) this.#archive(previous.change);
    const entry =
      suspectAt !== undefined && !recovered ? { change, slot, suspectAt } : { change, slot };
    this.#peers.set(change.publisherID, entry);
    this.#presence = undefined;
    this.#slots[slot] = entry;
    this.#considerCertificate(entry, now);
    this.#nextPrune = Math.min(this.#nextPrune, recordDeadline(change));
    if (previous === undefined || importantChange(change, previous.change))
      this.#priority.enqueue(change.publisherID);
    else if (now - change.reportedAt < FRESH_REPORT_MS) {
      // send recent updates as well as cycling through the older reports.
      this.#fresh.delete(change.publisherID);
      this.#fresh.add(change.publisherID);
      const oldest = this.#fresh.values().next();
      if (this.#fresh.size > FRESH_QUEUE_LIMIT && !oldest.done) this.#fresh.delete(oldest.value);
    }
  }

  #considerCertificate(peer: Seen, now: number) {
    const candidate = liveCertificate(peer, now);
    if (candidate === undefined) return;
    const holder = this.#certificateHolder;
    const best = holder?.change.certificate;
    if (
      best === undefined ||
      newerCertificate(candidate, best) ||
      (holder?.change.publisherID === peer.change.publisherID &&
        candidate.expiresAt === best.expiresAt &&
        candidate.fingerprint === best.fingerprint)
    )
      this.#certificateHolder = peer;
  }

  #bestCertificateHolder(now: number) {
    const holder = this.#certificateHolder;
    if (
      holder !== undefined &&
      (this.#peers.get(holder.change.publisherID) !== holder ||
        liveCertificate(holder, now) === undefined)
    ) {
      // a better report or a refresh of the same holder updates the cache on receipt.
      // only search the roster again if the cached holder is gone, worse, or no longer live.
      this.#certificateHolder = undefined;
      for (const peer of this.#slots) this.#considerCertificate(peer, now);
    }
    return this.#certificateHolder?.change;
  }

  message(now: number, requesterMessage?: GossipMessage): GossipMessage {
    this.#forgetOldPeers(now);
    if (!this.#self.left) this.#self = { ...this.#self, seq: this.#self.seq + 1, reportedAt: now };
    let excluded: Set<string> | undefined;
    if (requesterMessage?.releaseID === this.releaseID) {
      for (const report of [requesterMessage.from, ...requesterMessage.changes]) {
        const peer = this.#peers.get(report.publisherID);
        if (peer !== undefined && report.seq >= peer.change.seq && sameRun(report, peer.change)) {
          (excluded ??= new Set()).add(report.publisherID);
        }
      }
    }
    const selected = new Set<string>();
    const changes: Change[] = [];
    const pending: PriorityReport[] = [];
    while (changes.length < PRIORITY_CHANGES) {
      const report = this.#priority.take();
      if (report === undefined) break;
      const { id } = report;
      if (excluded?.has(id)) {
        pending.push(report);
        continue;
      }
      const peer = this.#peers.get(id);
      if (peer === undefined) continue;
      selected.add(id);
      changes.push(peer.change);
      report.sent++;
      pending.push(report);
    }
    // don't revisit promoted retries or spend a send on a requester's echo.
    for (const report of pending) this.#priority.restore(report);
    let fresh = 0;
    for (const id of this.#fresh) {
      if (fresh >= FRESH_CHANGES) break;
      if (excluded?.has(id)) continue;
      this.#fresh.delete(id);
      const peer = this.#peers.get(id);
      if (peer === undefined || selected.has(id) || now - peer.change.reportedAt >= FRESH_REPORT_MS)
        continue;
      selected.add(id);
      changes.push(peer.change);
      fresh++;
    }
    // even during churn, reserve space for ordinary reports.
    const limit = Math.min(MAX_CHANGES, this.#peers.size - (excluded?.size ?? 0));
    if (changes.length < limit) {
      const holder = this.#bestCertificateHolder(now);
      const installed = this.#self.certificate;
      if (
        holder?.certificate !== undefined &&
        (installed === undefined || newerCertificate(holder.certificate, installed)) &&
        !selected.has(holder.publisherID) &&
        !excluded?.has(holder.publisherID)
      ) {
        selected.add(holder.publisherID);
        changes.push(holder);
      }
    }
    for (let scanned = 0; scanned < this.#slots.length && changes.length < limit; scanned++) {
      this.#rotation %= this.#slots.length;
      const peer = this.#slots[this.#rotation++];
      if (
        peer === undefined ||
        selected.has(peer.change.publisherID) ||
        excluded?.has(peer.change.publisherID)
      )
        continue;
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
        this.#archive(peer.change);
        this.#presence = undefined;
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
        this.#presence = undefined;
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
    this.#self = { ...this.#self, startingUntil: now + INVITATION_ACK_MS };
    this.#nextStart = now + COOLDOWN_MS + Math.floor(random() * 5_000);
    return true;
  }

  finishStart() {
    this.#self = { ...this.#self, startingUntil: 0 };
  }

  confirmStart(startingUntil: number) {
    this.#self = { ...this.#self, startingUntil };
  }

  cancelStart() {
    this.finishStart();
    this.#nextStart = 0;
  }
}

function historyEntry(
  { runID, name, endsAt, copyFrom, left }: Change,
  unreachable = false,
): HostHistory {
  return { runID, name, endsAt, copyFrom, left, ...(unreachable ? { unreachable } : {}) };
}

export function reportedTabs(
  changes: readonly Change[],
  now: number,
  maxAge = FRESH_REPORT_MS,
  exclude?: Host,
) {
  const seen = new Set(exclude === undefined ? [] : [exclude.publisherID, exclude.origin]);
  let tabs = 0;
  for (const { publisherID, origin, left, endsAt, tabs: tally } of changes) {
    if (
      left ||
      (endsAt !== undefined && endsAt <= now) ||
      seen.has(publisherID) ||
      seen.has(origin) ||
      tally === undefined ||
      now - tally.observedAt >= maxAge
    )
      continue;
    seen.add(publisherID);
    seen.add(origin);
    tabs += tally.count;
  }
  return tabs;
}
