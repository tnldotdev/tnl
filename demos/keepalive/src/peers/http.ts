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
  hostIdentity,
  hostOrigin,
  hostSchema,
  runIDSchema,
  parseMessage,
  hostDetailsSchema,
  sameRun,
  type Change,
  type GossipMessage,
  type Host,
} from "./gossip.ts";
import { heartbeatSchema, PRESENCE_PATH, TabLeases } from "./presence.ts";
import { MAX_FALLBACK_HOSTS, TREE_PATH, treeSample } from "./view.ts";
import { readBytes, readJSON } from "../release.ts";
import { invitationSchema } from "../enrollment.ts";
import { hostTarget, STARTUP_MS, UPLOAD_BYTES, UPLOAD_MS } from "../policy.ts";
import type { ExportedCertificate } from "@tnldotdev/tnl";
import {
  CERTIFICATE_PATH,
  CERTIFICATE_PROOF_PATH,
  certificateBundle,
  CERTIFICATE_BYTES,
  describeCertificate,
  newerCertificate,
  readInheritedCertificate,
  type CertificateReport,
} from "../hosting/certificate.ts";

const CHECK_PATH = "/__keepalive/check";
const WAIT_PATH = "/__keepalive/wait";
const UPLOAD_PATH = "/__keepalive/upload";
const MAX_WAITING = 16;
const WAIT_MS = 20_000;
const READY_HEADER = "X-Keepalive-Ready";
const checkSchema = z.strictObject({ target: hostSchema, message: z.unknown() });
const certificateRequest = z.strictObject({ requester: hostSchema, nonce: z.uuid() });
const certificateProof = z.strictObject({ donor: hostSchema, run: runIDSchema, nonce: z.uuid() });

export async function readPeers(
  origin: string,
  releaseID: string,
  signal?: AbortSignal,
  invitation?: string,
) {
  const request = options(signal, 5_000);
  const response = await fetch(new URL(PEERS_PATH, origin), {
    ...request,
    ...(invitation === undefined ? {} : { headers: { [READY_HEADER]: invitation } }),
  });
  return parseMessage(
    await readJSON(response, MAX_MESSAGE_BYTES, request.signal ?? undefined),
    releaseID,
    Date.now(),
  );
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

export async function readInviterCertificate(host: Host, invitation: string, signal: AbortSignal) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(4_000)]);
  const response = await fetch(new URL(CERTIFICATE_PATH, host.origin), {
    ...options(deadline, 4_000),
    headers: { [READY_HEADER]: invitation },
  });
  return readInheritedCertificate(response, deadline);
}

export function peerServer(
  releaseID: string,
  allowedOrigins: readonly string[],
  serve: (request: Request) => Promise<Response>,
  signal: AbortSignal,
  network: { proxyOrigin: string; proof: string },
  exportCertificate?: (signal: AbortSignal) => Promise<ExportedCertificate | undefined>,
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
  let timer: ReturnType<typeof setTimeout> | undefined;
  const probing = new AbortController();
  let probe: Promise<void> | undefined;
  let networkChecks = 0;
  let pendingCertificateProof: { donor: Host; nonce: string; answered: boolean } | undefined;
  let checkingCertificate = false;

  function reportMessage(now: number, requesterMessage?: GossipMessage) {
    if (gossip === undefined) throw new Error("No peer view yet.");
    gossip.observeTabs(leases.count(now), now);
    return gossip.message(now, requesterMessage);
  }

  async function send(
    target: Host,
    message: GossipMessage,
    via?: Host,
    lifetime = signal,
    invitation?: string,
  ) {
    const path = via === undefined ? PEERS_PATH : CHECK_PATH;
    const request = options(
      lifetime,
      invitation !== undefined ? 8_000 : via === undefined ? 1800 : 2400,
    );
    const response = await fetch(new URL(path, (via ?? target).origin), {
      ...request,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(invitation === undefined ? {} : { [READY_HEADER]: invitation }),
      },
      body: JSON.stringify(via === undefined ? message : { target, message }),
    });
    const reply = parseMessage(
      await readJSON(response, MAX_MESSAGE_BYTES, request.signal ?? undefined),
      releaseID,
      Date.now(),
    );
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
    gossip.observeTabs(leases.count(now), now);
    const live = gossip.hosts(now);
    const fallback = live.filter((host) => !host.departing);
    const offset = Math.floor(Math.random() * fallback.length);
    const hints: Host[] = [];
    for (let i = 0; i < Math.min(fallback.length, MAX_FALLBACK_HOSTS); i++) {
      const candidate = fallback[(offset + i) % fallback.length];
      if (candidate !== undefined) hints.push(hostIdentity(candidate));
    }
    return c.json({
      host: gossip.self,
      startedAt: gossip.startedAt,
      tabs: gossip.tabSnapshot(now, live).total,
      hosts: live.length + 1,
      saturated: gossip.saturated(now),
      fallback: hints,
    });
  });
  app.get(TREE_PATH, (c) => {
    if (gossip === undefined || signal.aborted) return c.body(null, 503);
    const hostRunID = gossip.self.runID;
    return c.json({ hostRunID, hosts: treeSample(gossip.roster(Date.now()), hostRunID) });
  });
  app.get(CERTIFICATE_PATH, async (c) => {
    const pending = promotion;
    if (
      gossip === undefined ||
      signal.aborted ||
      exportCertificate === undefined ||
      !pending?.uploadPassed ||
      pending.reading ||
      pending.endsAt <= Date.now() ||
      pending.invitation !== c.req.header(READY_HEADER) ||
      !allowed(c.req.header("Origin") ?? "")
    )
      return c.body(null, 403);
    const deadline = AbortSignal.any([signal, c.req.raw.signal, AbortSignal.timeout(3_000)]);
    pending.reading = true;
    try {
      const bundle = await exportCertificate(deadline).catch(() => undefined);
      if (
        deadline.aborted ||
        promotion !== pending ||
        pending.endsAt <= Date.now() ||
        bundle === undefined ||
        bundle.expiresAt <= Date.now()
      )
        return c.body(null, 503);
      return c.json({ bundle, knownHosts: gossip.hosts(Date.now()).length + 1 });
    } finally {
      pending.reading = false;
    }
  });
  app.post(CERTIFICATE_PROOF_PATH, async (c) => {
    const pending = pendingCertificateProof;
    if (
      pending === undefined ||
      pending.answered ||
      signal.aborted ||
      !allowed(c.req.header("Origin") ?? "")
    )
      return c.body(null, 404);
    const deadline = AbortSignal.any([signal, c.req.raw.signal, AbortSignal.timeout(2_000)]);
    const proof = certificateProof.safeParse(
      await readJSON(new Response(c.req.raw.body), 1_024, deadline).catch(() => undefined),
    );
    if (
      !proof.success ||
      deadline.aborted ||
      pendingCertificateProof !== pending ||
      pending.answered ||
      proof.data.nonce !== pending.nonce ||
      proof.data.run !== gossip?.self.runID ||
      !sameRun(proof.data.donor, pending.donor)
    )
      return c.body(null, 404);
    pending.answered = true;
    return c.body(null, 204);
  });
  app.post(CERTIFICATE_PATH, async (c) => {
    const view = gossip;
    if (
      view === undefined ||
      signal.aborted ||
      exportCertificate === undefined ||
      !allowed(c.req.header("Origin") ?? "") ||
      checkingCertificate
    )
      return c.body(null, 403);
    const deadline = AbortSignal.any([signal, c.req.raw.signal, AbortSignal.timeout(3_000)]);
    const request = certificateRequest.safeParse(
      await readJSON(new Response(c.req.raw.body), 1_024, deadline).catch(() => undefined),
    );
    if (!request.success || checkingCertificate) return c.body(null, 403);
    const { requester, nonce } = request.data;
    if (
      !hostOrigin(requester.origin) ||
      !view.hosts(Date.now()).some((host) => sameRun(host, requester))
    )
      return c.body(null, 403);
    checkingCertificate = true;
    try {
      // require the caller to make its nonce answer from its own exact address.
      // naming a host seen in public gossip alone does not give access to the key.
      const answered = await fetch(new URL(CERTIFICATE_PROOF_PATH, requester.origin), {
        ...options(deadline, 2_000),
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ donor: view.self, run: requester.runID, nonce }),
      }).catch(() => undefined);
      if (answered?.status !== 204) return c.body(null, 403);
      const bundle = await exportCertificate(deadline).catch(() => undefined);
      if (deadline.aborted || bundle === undefined || bundle.expiresAt <= Date.now())
        return c.body(null, 503);
      return c.json(bundle);
    } finally {
      checkingCertificate = false;
    }
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
      if (pending.replacing) replacement = reply.from;
    } else {
      gossip.receive(message, Date.now());
    }
    return c.json(reportMessage(Date.now(), message));
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
    advertiseCertificate(certificate: CertificateReport) {
      gossip?.update({ certificate });
    },
    async newerCertificate(current: CertificateReport, operation: AbortSignal) {
      const view = gossip;
      if (view === undefined || pendingCertificateProof !== undefined) return undefined;
      const now = Date.now();
      let best: Change | undefined;
      for (const host of view.hosts(now)) {
        const candidate = host.certificate;
        if (
          candidate !== undefined &&
          candidate.expiresAt > now &&
          newerCertificate(candidate, best?.certificate ?? current)
        )
          best = host;
      }
      const expected = best?.certificate;
      if (best === undefined || expected === undefined) return undefined;
      const nonce = crypto.randomUUID();
      pendingCertificateProof = { donor: best, nonce, answered: false };
      try {
        const deadline = AbortSignal.any([operation, signal, AbortSignal.timeout(4_000)]);
        const response = await fetch(new URL(CERTIFICATE_PATH, best.origin), {
          ...options(deadline, 4_000),
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ requester: view.self, nonce }),
        });
        const bundle = certificateBundle.parse(
          await readJSON(response, CERTIFICATE_BYTES, deadline),
        );
        const actual = await describeCertificate(bundle);
        if (actual.fingerprint !== expected.fingerprint || actual.expiresAt !== expected.expiresAt)
          return undefined;
        return bundle;
      } catch {
        return undefined;
      } finally {
        pendingCertificateProof = undefined;
      }
    },
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
        if (signal.aborted || probing.signal.aborted) return;
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
        if (probe === undefined) {
          const operation = AbortSignal.any([signal, probing.signal]);
          probe = peers
            .probe(Date.now, Math.random, (target, message, via) =>
              send(target, message, via, operation),
            )
            .finally(() => {
              probe = undefined;
            });
        }
        report(peers);
        if (!signal.aborted) timer = setTimeout(tick, PROBE_MS + Math.random() * 1_000);
      };
      tick();
    },
    async stop() {
      clearTimeout(timer);
      probing.abort();
      await probe;
      if (gossip === undefined) return;
      const peers = gossip.hosts(Date.now()).slice(0, 3);
      const message = gossip.leave(Date.now());
      const deadline = AbortSignal.timeout(1_000);
      await Promise.allSettled(peers.map((peer) => send(peer, message, undefined, deadline)));
    },
  };
}
