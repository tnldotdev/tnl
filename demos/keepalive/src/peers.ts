import * as z from "zod";

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
const START_MS = 90_000;
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
});
const startTimeSchema = z.int().min(EARLIEST_START);
const messageSchema = z.strictObject({
  releaseID: releaseIDSchema,
  startedAt: startTimeSchema,
  from: changeSchema,
  changes: z.array(changeSchema).max(MAX_CHANGES),
});
export type Host = Readonly<z.infer<typeof hostSchema>>;
type Change = Readonly<z.infer<typeof changeSchema>>;
export type GossipMessage = Readonly<z.infer<typeof messageSchema>>;

export type PeerTransport = (
  target: Host,
  message: GossipMessage,
  via?: Host,
) => Promise<GossipMessage | undefined>;

export function hostOrigin(value: unknown, parent = HOST_PARENT): value is string {
  if (typeof value !== "string" || value.length > 261) return false;
  const url = URL.parse(value);
  if (url?.protocol !== "https:" || url.origin !== value || url.port !== "") return false;
  if (!url.hostname.endsWith(`.${parent}`)) return false;
  return /^(r|p)-[a-z2-7]{26}$/.test(url.hostname.slice(0, -(parent.length + 1)));
}

export function parseHost(value: unknown, parent = HOST_PARENT): Host | undefined {
  const parsed = hostSchema.safeParse(value);
  if (parsed.success && hostOrigin(parsed.data.origin, parent)) return parsed.data;
  return undefined;
}

export function startTime(value: unknown, now: number): number | undefined {
  const parsed = startTimeSchema.safeParse(value);
  if (parsed.success && parsed.data <= now + 30_000) return parsed.data;
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
    startTime(parsed.data.startedAt, now) === undefined
  )
    return;
  const valid = (change: Change) =>
    hostOrigin(change.origin, parent) && change.startingUntil <= now + START_MS + 30_000;
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

function newer(next: Change, current: Change): boolean {
  if (next.runNumber !== current.runNumber) {
    return BigInt(next.runNumber) > BigInt(current.runNumber);
  }
  // one service run number has only one run and address.
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

  constructor(releaseID: string, host: Host, startedAt: number) {
    this.releaseID = releaseID;
    this.#self = { ...host, seq: 1, left: false, startingUntil: 0 };
    this.#startedAt = startedAt;
  }

  get startedAt() {
    return this.#startedAt;
  }

  get size() {
    return this.#peers.size;
  }

  #prune(now: number) {
    for (const [id, peer] of this.#peers) {
      if (now - peer.heardAt >= KEEP_MS) this.#peers.delete(id);
    }
  }

  receive(message: GossipMessage, now: number) {
    if (message.releaseID !== this.releaseID) return;
    this.#startedAt = Math.min(this.#startedAt, message.startedAt);
    this.#prune(now);
    if (
      !message.from.left &&
      !this.#peers.has(message.from.publisherID) &&
      message.from.publisherID !== this.#self.publisherID
    ) {
      this.finishStart();
    }
    // give the sender the first slot; forwarded observations cannot evict live hosts.
    for (const change of [message.from, ...message.changes]) {
      if (change.publisherID === this.#self.publisherID || change.origin === this.#self.origin) {
        continue;
      }
      const previous = this.#peers.get(change.publisherID);
      if (previous !== undefined && !newer(change, previous.change)) continue;
      if (previous === undefined && this.#peers.size >= MAX_PEERS) continue;
      this.#peers.set(
        change.publisherID,
        previous !== undefined && sameRun(previous.change, change) && change !== message.from
          ? { ...previous, change }
          : { change, heardAt: now },
      );
    }
  }

  message(now: number): GossipMessage {
    this.#prune(now);
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

  hosts(now: number): readonly Host[] {
    return this.#live(now).map(({ change }) => change);
  }

  #live(now: number) {
    this.#prune(now);
    const origins = new Set<string>();
    return [...this.#peers.values()].filter(({ change, heardAt, suspectAt }) => {
      if (
        change.left ||
        now - heardAt >= QUIET_MS ||
        (suspectAt !== undefined && now - suspectAt >= SUSPECT_MS) ||
        origins.has(change.origin)
      )
        return false;
      origins.add(change.origin);
      return true;
    });
  }

  maybeStart(now: number, target: number, offer: () => boolean): boolean {
    if (this.#self.left || now < this.#nextStart || now < this.#self.startingUntil) return false;
    const live = this.#live(now);
    const starting = live.filter(({ change }) => change.startingUntil > now).length;
    if (1 + live.length + starting >= target || !offer()) return false;
    this.#self = { ...this.#self, startingUntil: now + START_MS };
    this.#nextStart = now + COOLDOWN_MS;
    return true;
  }

  finishStart() {
    this.#self = { ...this.#self, startingUntil: 0 };
  }

  leave(now: number): GossipMessage {
    this.#self = { ...this.#self, seq: this.#self.seq + 1, left: true, startingUntil: 0 };
    return this.message(now);
  }

  async probe(clock: () => number, random: () => number, send: PeerTransport): Promise<void> {
    if (this.#probing || this.#self.left) return;
    this.#prune(clock());
    // try suspect and quiet hosts too: a suspended tab can return at the same URL.
    const candidates = [...this.#peers.values()].filter(({ change }) => !change.left);
    const selected = candidates[Math.floor(random() * candidates.length)];
    if (selected === undefined) return;
    const target = selected.change;
    const helper = this.hosts(clock()).filter((host) => host.publisherID !== target.publisherID);
    const via = helper[Math.floor(random() * helper.length)];
    this.#probing = true;
    try {
      const message = this.message(clock());
      const ask = async (via?: Host) => {
        try {
          const reply = await send(target, message, via);
          return reply?.releaseID === this.releaseID && sameRun(target, reply.from)
            ? reply
            : undefined;
        } catch {
          return undefined;
        }
      };
      const reply = (await ask()) ?? (via === undefined ? undefined : await ask(via));
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
        selected.suspectAt ??= now;
      }
    } finally {
      this.#probing = false;
    }
  }
}
