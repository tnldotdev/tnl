import { Hono } from "hono";
import { cors } from "hono/cors";
import { streamText } from "hono/streaming";
import * as z from "zod";
import {
  Gossip,
  HOST_PARENT,
  MAX_MESSAGE_BYTES,
  PEERS_PATH,
  PROBE_MS,
  hostOrigin,
  hostSchema,
  parseMessage,
  sameRun,
  type GossipMessage,
  type Host,
} from "../peers.ts";
import { readJSON } from "../release.ts";

const CHECK_PATH = "/__keepalive/check";
const WAIT_PATH = "/__keepalive/wait";
const TARGET = 3;
const MAX_WAITING = 16;
const WAIT_MS = 20_000;
const checkSchema = z.strictObject({ target: hostSchema, message: z.unknown() });

export async function readPeers(origin: string, releaseID: string, signal?: AbortSignal) {
  const response = await fetch(new URL(PEERS_PATH, origin), options(signal, 5_000));
  return parseMessage(await readJSON(response, MAX_MESSAGE_BYTES), releaseID, Date.now());
}

/** waits for the host to pick this tab, returning false if the wait ends first. */
export async function waitForWork(host: Host, signal: AbortSignal) {
  const response = await fetch(new URL(WAIT_PATH, host.origin), options(signal, WAIT_MS + 5_000));
  if (!response.ok) throw new Error("Could not wait on this host.");
  return z.literal("start").safeParse(await readJSON(response, 64)).success;
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
) {
  const app = new Hono();
  const allowed = (origin: string) => (allowedOrigins.includes(origin) ? origin : undefined);
  const waiting = new Set<() => void>();
  let gossip: Gossip | undefined;
  let checking = false;
  let timer: ReturnType<typeof setInterval> | undefined;

  async function send(target: Host, message: GossipMessage, via?: Host, lifetime = signal) {
    const path = via === undefined ? PEERS_PATH : CHECK_PATH;
    const response = await fetch(new URL(path, (via ?? target).origin), {
      ...options(lifetime, via === undefined ? 1800 : 2400),
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(via === undefined ? message : { target, message }),
    });
    const reply = parseMessage(await readJSON(response, MAX_MESSAGE_BYTES), releaseID, Date.now());
    if (reply !== undefined && sameRun(reply.from, target)) return reply;
    return undefined;
  }

  app.use("*", cors({ origin: allowed, allowMethods: ["GET", "POST", "OPTIONS"] }));
  app.use("*", async (c, next) => {
    await next();
    c.header("Cache-Control", "no-store");
  });

  app.get(PEERS_PATH, (c) => {
    if (gossip === undefined) return c.body(null, 503);
    return c.json(gossip.message(Date.now()));
  });
  app.post(PEERS_PATH, async (c) => {
    if (gossip === undefined) return c.body(null, 503);
    const body = await readJSON(
      new Response(c.req.raw.body),
      MAX_MESSAGE_BYTES,
      c.req.raw.signal,
    ).catch(() => undefined);
    const message = parseMessage(body, releaseID, Date.now());
    if (message === undefined) return c.body(null, 400);
    gossip.receive(message, Date.now());
    return c.json(gossip.message(Date.now()));
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
  app.get(WAIT_PATH, (c) => {
    if (gossip === undefined || waiting.size >= MAX_WAITING) return c.body(null, 503);
    return streamText(c, async (stream) => {
      const selected = await new Promise<boolean>((resolve) => {
        const start = () => finish(true);
        const stop = () => finish(false);
        const timeout = setTimeout(stop, WAIT_MS);
        function finish(value: boolean) {
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
      await stream.write(JSON.stringify(selected ? "start" : "wait"));
    });
  });
  app.get("*", (c) => serve(c.req.raw));

  return {
    fetch: async (request: Request) => app.fetch(request),
    async start(
      host: Host,
      startedAt: number,
      initialPeer: Host | undefined,
      report: (gossip: Gossip) => void,
      replacing: () => boolean,
    ) {
      const peers = new Gossip(releaseID, host, startedAt);
      gossip = peers;
      if (initialPeer !== undefined) {
        // a report from before startup doesn't tell us whether a host stayed up.
        const reply = await send(initialPeer, peers.message(Date.now())).catch(() => undefined);
        if (reply !== undefined && !reply.from.left) peers.receive(reply, Date.now());
      }
      signal.throwIfAborted();
      const tick = () => {
        peers.maybeStart(Date.now(), replacing() ? TARGET + 1 : TARGET, () => {
          const next = waiting.values().next().value;
          next?.();
          return next !== undefined;
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
