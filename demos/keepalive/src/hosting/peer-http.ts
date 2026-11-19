import { Hono } from "hono";
import { cors } from "hono/cors";
import { streamText } from "hono/streaming";
import * as z from "zod";
import { NETWORK_CHECK_PATH, networkProof } from "../network.ts";
import {
  Gossip,
  HOST_PARENT,
  MAX_MESSAGE_BYTES,
  PEERS_PATH,
  PROBE_MS,
  hostOrigin,
  hostSchema,
  parseMessage,
  hostDetailsSchema,
  sameRun,
  type Change,
  type GossipMessage,
  type Host,
} from "../peers.ts";
import { heartbeatSchema, PRESENCE_PATH, TabLeases } from "../presence.ts";
import { readBytes, readJSON } from "../release.ts";
import { invitationSchema } from "./config.ts";
import { hostTarget, STARTUP_MS, UPLOAD_BYTES, UPLOAD_MS } from "./policy.ts";

const CHECK_PATH = "/__keepalive/check";
const WAIT_PATH = "/__keepalive/wait";
const UPLOAD_PATH = "/__keepalive/upload";
const MAX_WAITING = 16;
const WAIT_MS = 20_000;
const READY_HEADER = "X-Keepalive-Ready";
const checkSchema = z.strictObject({ target: hostSchema, message: z.unknown() });

export async function readPeers(
  origin: string,
  releaseID: string,
  signal?: AbortSignal,
  invitation?: string,
) {
  const response = await fetch(new URL(PEERS_PATH, origin), {
    ...options(signal, 5_000),
    ...(invitation === undefined ? {} : { headers: { [READY_HEADER]: invitation } }),
  });
  return parseMessage(await readJSON(response, MAX_MESSAGE_BYTES), releaseID, Date.now());
}

/** waits for the host to pick this tab and returns its private invitation. */
export async function waitForWork(host: Host, proof: string, signal: AbortSignal) {
  const response = await fetch(new URL(WAIT_PATH, host.origin), {
    ...options(signal, WAIT_MS + 5_000),
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(proof),
  });
  if (!response.ok) throw new Error("Could not wait on this host.");
  return invitationSchema.nullable().parse(await readJSON(response, 64));
}

export async function checkUpload(host: Host, invitation: string, signal: AbortSignal) {
  const bytes = new Uint8Array(UPLOAD_BYTES);
  for (let offset = 0; offset < bytes.length; offset += 65_536) {
    crypto.getRandomValues(bytes.subarray(offset, offset + 65_536));
  }
  for (let attempt = 0; attempt < 2; attempt++) {
    signal.throwIfAborted();
    const response = await fetch(new URL(UPLOAD_PATH, host.origin), {
      ...options(signal, UPLOAD_MS),
      method: "POST",
      headers: { [READY_HEADER]: invitation },
      body: bytes,
    }).catch(() => undefined);
    if (response?.status === 204) return true;
    await response?.body?.cancel().catch(() => {});
  }
  signal.throwIfAborted();
  return false;
}

function options(signal: AbortSignal | undefined, timeout: number): RequestInit {
  const deadline = AbortSignal.timeout(timeout);
  return {
    signal: signal === undefined ? deadline : AbortSignal.any([signal, deadline]),
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  };
}

export function peerServer(
  releaseID: string,
  allowedOrigins: readonly string[],
  serve: (request: Request) => Promise<Response>,
  signal: AbortSignal,
  network: { proxyOrigin: string; proof: string },
) {
  const app = new Hono();
  const allowed = (origin: string) => (allowedOrigins.includes(origin) ? origin : undefined);
  const waiting = new Set<(invitation: string) => void>();
  const leases = new TabLeases();
  let gossip: Gossip | undefined;
  let promotion:
    | {
        invitation: string;
        endsAt: number;
        replacing: boolean;
        uploadPassed: boolean;
        uploads: number;
        reading: boolean;
      }
    | undefined;
  let acceptedInvitation: string | undefined;
  let replacement: Change | undefined;
  let checking = false;
  let timer: ReturnType<typeof setInterval> | undefined;
  let networkChecks = 0;

  function reportMessage(now: number) {
    if (gossip === undefined) throw new Error("No peer view yet.");
    gossip.observeTabs(leases.count(now), now);
    return gossip.message(now);
  }

  async function send(
    target: Host,
    message: GossipMessage,
    via?: Host,
    lifetime = signal,
    invitation?: string,
  ) {
    const path = via === undefined ? PEERS_PATH : CHECK_PATH;
    const response = await fetch(new URL(path, (via ?? target).origin), {
      ...options(lifetime, invitation !== undefined ? 8_000 : via === undefined ? 1800 : 2400),
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(invitation === undefined ? {} : { [READY_HEADER]: invitation }),
      },
      body: JSON.stringify(via === undefined ? message : { target, message }),
    });
    const reply = parseMessage(await readJSON(response, MAX_MESSAGE_BYTES), releaseID, Date.now());
    if (reply !== undefined && sameRun(reply.from, target)) return reply;
    return undefined;
  }

  app.use(
    "*",
    cors({
      origin: allowed,
      allowMethods: ["GET", "POST", "OPTIONS"],
      allowHeaders: ["Content-Type", READY_HEADER],
    }),
  );
  app.use("*", async (c, next) => {
    await next();
    c.header("Cache-Control", "no-store");
  });

  app.get(PEERS_PATH, (c) => {
    if (gossip === undefined || signal.aborted) return c.body(null, 503);
    const invitation = c.req.header(READY_HEADER);
    if (invitation !== undefined && invitation !== acceptedInvitation) return c.body(null, 403);
    return c.json(reportMessage(Date.now()));
  });
  app.post(PRESENCE_PATH, async (c) => {
    if (!allowed(c.req.header("Origin") ?? "")) return c.body(null, 403);
    if (gossip === undefined || signal.aborted) return c.body(null, 503);
    const deadline = AbortSignal.any([signal, c.req.raw.signal, AbortSignal.timeout(3_000)]);
    const heartbeat = heartbeatSchema.safeParse(
      await readJSON(new Response(c.req.raw.body), 192, deadline).catch(() => undefined),
    );
    if (!heartbeat.success || heartbeat.data.releaseID !== releaseID) return c.body(null, 400);
    const now = Date.now();
    if (!leases.touch(heartbeat.data.tab, now)) return c.body(null, 503);
    return c.json(reportMessage(now));
  });
  app.post(UPLOAD_PATH, async (c) => {
    const pending = promotion;
    if (
      pending === undefined ||
      pending.endsAt <= Date.now() ||
      signal.aborted ||
      pending.invitation !== c.req.header(READY_HEADER) ||
      !allowed(c.req.header("Origin") ?? "")
    )
      return c.body(null, 403);
    if (pending.uploadPassed) return c.body(null, 204);
    if (pending.reading || pending.uploads >= 2 || c.req.raw.body === null)
      return c.body(null, 409);
    pending.reading = true;
    pending.uploads++;
    try {
      const deadline = AbortSignal.any([signal, c.req.raw.signal, AbortSignal.timeout(UPLOAD_MS)]);
      await readBytes(new Response(c.req.raw.body), UPLOAD_BYTES, deadline, UPLOAD_BYTES);
      if (promotion !== pending || pending.endsAt <= Date.now()) return c.body(null, 409);
      pending.uploadPassed = true;
      return c.body(null, 204);
    } catch {
      return c.body(null, 422);
    } finally {
      pending.reading = false;
    }
  });
  app.post(PEERS_PATH, async (c) => {
    if (gossip === undefined || signal.aborted) return c.body(null, 503);
    const body = await readJSON(
      new Response(c.req.raw.body),
      MAX_MESSAGE_BYTES,
      c.req.raw.signal,
    ).catch(() => undefined);
    const message = parseMessage(body, releaseID, Date.now());
    if (message === undefined) return c.body(null, 400);
    const pending = promotion;
    const invitation = c.req.header(READY_HEADER);
    if (invitation !== undefined) {
      if (
        !pending?.uploadPassed ||
        pending.endsAt <= Date.now() ||
        pending.invitation !== invitation ||
        message.from.left ||
        pending.reading
      )
        return c.body(null, 403);
      pending.reading = true;
      const reply = await readPeers(message.from.origin, releaseID, signal, invitation).catch(
        () => undefined,
      );
      pending.reading = false;
      if (
        promotion !== pending ||
        pending.endsAt <= Date.now() ||
        reply === undefined ||
        reply.from.left ||
        !sameRun(reply.from, message.from) ||
        signal.aborted
      )
        return c.body(null, 409);
      promotion = undefined;
      gossip.finishStart();
      gossip.receive(reply, Date.now());
      if (pending.replacing) {
        replacement = reply.from;
        gossip.update({ replacedBy: replacement.runID });
      }
    } else {
      gossip.receive(message, Date.now());
    }
    return c.json(reportMessage(Date.now()));
  });
  app.post(CHECK_PATH, async (c) => {
    if (gossip === undefined || checking) return c.body(null, 503);
    const raw = await readJSON(
      new Response(c.req.raw.body),
      MAX_MESSAGE_BYTES,
      c.req.raw.signal,
    ).catch(() => undefined);
    const check = checkSchema.safeParse(raw);
    if (!check.success || !hostOrigin(check.data.target.origin, HOST_PARENT))
      return c.body(null, 400);
    const message = parseMessage(check.data.message, releaseID, Date.now());
    if (message === undefined || checking) return c.body(null, 400);
    checking = true;
    try {
      const reply = await send(check.data.target, message);
      return reply === undefined ? c.body(null, 503) : c.json(reply);
    } catch {
      return c.body(null, 503);
    } finally {
      checking = false;
    }
  });
  app.post(WAIT_PATH, async (c) => {
    if (gossip === undefined || waiting.size + networkChecks >= MAX_WAITING) {
      return c.body(null, 503);
    }
    networkChecks++;
    const parsed = networkProof.safeParse(
      await readJSON(new Response(c.req.raw.body), 192, c.req.raw.signal).catch(() => undefined),
    );
    if (!parsed.success) {
      networkChecks--;
      return c.body(null, 400);
    }
    const allowed = await fetch(new URL(NETWORK_CHECK_PATH, network.proxyOrigin), {
      ...options(AbortSignal.any([signal, c.req.raw.signal]), 5_000),
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host: network.proof, volunteer: parsed.data }),
    })
      .then((reply) => reply.status === 204)
      .catch(() => false);
    networkChecks--;
    if (!allowed) return c.body(null, 403);
    if (waiting.size >= MAX_WAITING) return c.body(null, 503);
    return streamText(c, async (stream) => {
      const selected = await new Promise<string | null>((resolve) => {
        const start = (invitation: string) => finish(invitation);
        const stop = () => finish(null);
        const timeout = setTimeout(stop, WAIT_MS);
        function finish(value: string | null) {
          clearTimeout(timeout);
          waiting.delete(start);
          signal.removeEventListener("abort", stop);
          resolve(value);
        }
        stream.onAbort(stop);
        signal.addEventListener("abort", stop, { once: true });
        waiting.add(start);
        if (signal.aborted || stream.aborted) stop();
      });
      await stream.write(JSON.stringify(selected));
    });
  });
  app.get("*", (c) => serve(c.req.raw));

  return {
    fetch: async (request: Request) => app.fetch(request),
    get replacementReady() {
      return replacement !== undefined;
    },
    get replacement() {
      return replacement;
    },
    async start(
      host: Host,
      startedAt: number,
      firstHostToContact: Host | undefined,
      invitation: string | undefined,
      report: (gossip: Gossip) => void,
      replacing: () => boolean,
      details?: z.infer<typeof hostDetailsSchema>,
    ) {
      const peers = new Gossip(releaseID, host, startedAt, details);
      gossip = peers;
      acceptedInvitation = invitation;
      if (firstHostToContact !== undefined) {
        // a report from before startup doesn't tell us whether a host stayed up.
        const reply = await send(
          firstHostToContact,
          reportMessage(Date.now()),
          undefined,
          signal,
          invitation,
        ).catch(() => undefined);
        if (reply !== undefined && !reply.from.left) peers.receive(reply, Date.now());
        else if (invitation !== undefined)
          throw new Error("The inviting host did not confirm this turn.");
      }
      signal.throwIfAborted();
      const tick = () => {
        const now = Date.now();
        const departing = replacing();
        peers.update({ departing });
        peers.observeTabs(leases.count(now), now);
        if (promotion !== undefined && promotion.endsAt <= now) promotion = undefined;
        if (promotion === undefined)
          peers.maybeStart(now, hostTarget(peers.tabs(now)), () => {
            const next = waiting.values().next().value;
            if (next === undefined) return false;
            const invitation = crypto.randomUUID();
            promotion = {
              invitation,
              endsAt: now + STARTUP_MS,
              replacing: departing,
              uploadPassed: false,
              uploads: 0,
              reading: false,
            };
            next(invitation);
            return true;
          });
        void peers.probe(Date.now, Math.random, send);
        report(peers);
      };
      tick();
      timer = setInterval(tick, PROBE_MS + Math.random() * 1000);
    },
    async stop() {
      clearInterval(timer);
      if (gossip === undefined) return;
      const peers = gossip.hosts(Date.now()).slice(0, 3);
      const message = gossip.leave(Date.now());
      const deadline = AbortSignal.timeout(1_000);
      await Promise.allSettled(peers.map((peer) => send(peer, message, undefined, deadline)));
    },
  };
}
