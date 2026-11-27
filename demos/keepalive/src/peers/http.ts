import { Hono } from "hono";
import { cors } from "hono/cors";
import * as z from "zod/mini";
import {
  Gossip,
  PROBE_MS,
  parseMessage,
  hostDetailsSchema,
  type Change,
  type GossipMessage,
} from "./gossip.ts";
import {
  HOST_PARENT,
  PEERS_PATH,
  hostIdentity,
  hostOrigin,
  hostSchema,
  runIDSchema,
  sameRun,
  type Host,
} from "./host.ts";
import { MAX_MESSAGE_BYTES } from "./report.ts";
import { InvitationUnavailable } from "./invitation.ts";
import {
  heartbeatSchema,
  PRESENCE_PATH,
  sampleAudience,
  sampledTab,
  TabLeases,
} from "./presence.ts";
import { TREE_PATH, treeSample } from "./view.ts";
import { MAX_FALLBACK_HOSTS } from "./audience.ts";
import { readBytes, readJSON } from "../release.ts";
import { INVITATION_PATH, READY_HEADER, invitationSchema } from "../enrollment.ts";
import { hostTarget, INVITATION_ACK_MS, STARTUP_MS, UPLOAD_BYTES, UPLOAD_MS } from "../policy.ts";
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
import {
  NoReachableHost,
  PEER_REQUEST_MS,
  TransportFailure,
  noReachableHost,
  request as sendRequest,
  requireStatus,
  retryOnce,
} from "../network.ts";

declare const KEEPALIVE_RAMP_UPLOAD_TRACE: boolean;

const CHECK_PATH = "/__keepalive/check";
const WAIT_PATH = "/__keepalive/wait";
const UPLOAD_PATH = "/__keepalive/upload";
const WAIT_MS = 5_000;
const CONFIRMATION_MS = 12_000;
const MAX_CONFIRMATIONS = 16;
const checkSchema = z.strictObject({ target: hostSchema, message: z.unknown() });
const certificateRequest = z.strictObject({ requester: hostSchema, nonce: z.uuid() });
const certificateProof = z.strictObject({ donor: hostSchema, run: runIDSchema, nonce: z.uuid() });

export async function readPeers(
  origin: string,
  releaseID: string,
  signal?: AbortSignal,
  invitation?: string,
  parent = HOST_PARENT,
) {
  const request = options(signal, invitation === undefined ? PEER_REQUEST_MS : 5_000);
  const response = await sendRequest(new URL(PEERS_PATH, origin), {
    ...request,
    ...(invitation === undefined ? {} : { headers: { [READY_HEADER]: invitation } }),
  });
  if (invitation === undefined && noReachableHost(response)) {
    await response.body?.cancel().catch(() => {});
    throw new NoReachableHost();
  }
  return parseMessage(
    await readJSON(await requireStatus(response), MAX_MESSAGE_BYTES, request.signal ?? undefined),
    releaseID,
    Date.now(),
    parent,
  );
}

/** waits for the host to pick this tab and returns its private invitation. */
export async function waitForWork(host: Host, signal: AbortSignal) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(WAIT_MS + 5_000)]);
  const response = await sendRequest(new URL(WAIT_PATH, host.origin), {
    signal: deadline,
    credentials: "omit",
    method: "POST",
  });
  return z
    .nullable(invitationSchema)
    .parse(await readJSON(await requireStatus(response), 64, deadline));
}

export async function checkUpload(host: Host, invitation: string, signal: AbortSignal) {
  signal.throwIfAborted();
  const bytes = new Uint8Array(UPLOAD_BYTES);
  for (let offset = 0; offset < bytes.length; offset += 65_536) {
    crypto.getRandomValues(bytes.subarray(offset, offset + 65_536));
  }
  return retryOnce(signal, async () => {
    const response = await sendRequest(new URL(UPLOAD_PATH, host.origin), {
      // allow for preflight, connection setup and the return trip. the donor
      // still has only UPLOAD_MS to read the complete body.
      ...options(signal, UPLOAD_MS + 2_000),
      method: "POST",
      headers: { [READY_HEADER]: invitation },
      body: bytes,
    });
    if (response.status === 403 || response.status === 409 || response.status === 422) {
      await response.body?.cancel().catch(() => {});
      if (response.status === 422) return false;
      throw new InvitationUnavailable(response.status === 409);
    }
    await requireStatus(response, 204);
    return true;
  });
}

export async function releaseInvitation(host: Host, invitation: string, releaseID: string) {
  const deadline = AbortSignal.timeout(2_000);
  await retryOnce(deadline, async () => {
    const response = await sendRequest(new URL(INVITATION_PATH, host.origin), {
      ...options(deadline, 1_000),
      method: "POST",
      headers: { [READY_HEADER]: invitation, "X-Keepalive-Release": releaseID },
    });
    await requireStatus(response, 204);
  }).catch(() => {});
}

function options(signal: AbortSignal | undefined, timeout: number): RequestInit {
  const deadline = AbortSignal.timeout(timeout);
  return {
    signal: signal === undefined ? deadline : AbortSignal.any([signal, deadline]),
    cache: "no-store",
    credentials: "omit",
    redirect: "manual",
  };
}

export async function readInviterCertificate(host: Host, invitation: string, signal: AbortSignal) {
  const deadline = AbortSignal.any([signal, AbortSignal.timeout(8_000)]);
  return retryOnce(deadline, async () => {
    const attempt = AbortSignal.any([deadline, AbortSignal.timeout(4_000)]);
    const response = await sendRequest(new URL(CERTIFICATE_PATH, host.origin), {
      signal: attempt,
      credentials: "omit",
      headers: { [READY_HEADER]: invitation },
    });
    return readInheritedCertificate(await requireStatus(response), attempt);
  });
}

export function peerServer(
  releaseID: string,
  allowedOrigins: readonly string[],
  serve: (request: Request) => Promise<Response>,
  signal: AbortSignal,
  exportCertificate?: (signal: AbortSignal) => Promise<ExportedCertificate | undefined>,
) {
  const app = new Hono();
  const allowed = (origin: string) => (allowedOrigins.includes(origin) ? origin : undefined);
  const leases = new TabLeases();
  let sampling = false;
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
  const confirmations = new Map<string, { host: Host; until: number }>();
  let replacement: Change | undefined;
  let checking = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const probing = new AbortController();
  let probe: Promise<void> | undefined;
  let pendingCertificateProof: { donor: Host; nonce: string; answered: boolean } | undefined;
  let checkingCertificate = false;
  let isReplacing = () => false;

  function cancelPromotion() {
    promotion = undefined;
    gossip?.cancelStart();
  }

  function expirePromotion(now: number) {
    if (promotion !== undefined && promotion.endsAt <= now) cancelPromotion();
  }

  function expireConfirmations(now: number) {
    for (const [invitation, receipt] of confirmations)
      if (receipt.until <= now) confirmations.delete(invitation);
  }

  function reportMessage(now: number, requesterMessage?: GossipMessage) {
    if (gossip === undefined) throw new Error("No peer view yet.");
    gossip.observeTabs(leases.count(now, sampling), now);
    return gossip.message(now, requesterMessage);
  }

  function updateSampling(view: Gossip, now: number) {
    sampling = sampleAudience(
      view.presenceView(now).remoteTabs + leases.count(now, sampling),
      sampling,
    );
  }

  function audience(view: Gossip, now: number) {
    const { remoteTabs, hosts } = view.presenceView(now);
    const local = leases.count(now, sampling);
    view.observeTabs(local, now);
    return { tabs: local + remoteTabs, hosts, saturated: view.saturated(now), sampling };
  }

  async function send(
    target: Host,
    message: GossipMessage,
    via?: Host,
    lifetime = signal,
    invitation?: string,
  ) {
    const path = via === undefined ? PEERS_PATH : CHECK_PATH;
    const body = JSON.stringify(via === undefined ? message : { target, message });
    const operation =
      invitation === undefined
        ? lifetime
        : AbortSignal.any([lifetime, AbortSignal.timeout(CONFIRMATION_MS)]);
    async function attempt() {
      const request = options(
        operation,
        invitation !== undefined ? 6_000 : via === undefined ? 1800 : 2400,
      );
      const response = await sendRequest(new URL(path, (via ?? target).origin), {
        ...request,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(invitation === undefined ? {} : { [READY_HEADER]: invitation }),
        },
        body,
      });
      const reply = parseMessage(
        await readJSON(
          await requireStatus(response),
          MAX_MESSAGE_BYTES,
          request.signal ?? undefined,
        ),
        releaseID,
        Date.now(),
      );
      if (reply !== undefined && sameRun(reply.from, target)) return reply;
      return undefined;
    }
    // only invitation confirmation has a replay receipt. routine gossip already
    // retries via another peer on its own schedule.
    return invitation === undefined ? attempt() : retryOnce(operation, attempt);
  }

  app.use(
    "*",
    cors({
      origin: allowed,
      allowMethods: ["GET", "POST", "OPTIONS"],
      allowHeaders: ["Content-Type", READY_HEADER, "X-Keepalive-Release"],
    }),
  );
  app.use("*", async (c, next) => {
    await next();
    c.header("Cache-Control", "no-store");
    // Go closes HTTP/1 or sends HTTP/2 GOAWAY after these finite responses.
    // random probes and visitor presence must not retain one stream per peer.
    c.header("Connection", "close");
  });

  app.get(PEERS_PATH, (c) => {
    if (gossip === undefined || signal.aborted) return c.body(null, 503);
    const invitation = c.req.header(READY_HEADER);
    if (invitation !== undefined && invitation !== acceptedInvitation) return c.body(null, 403);
    const now = Date.now();
    updateSampling(gossip, now);
    const summary = audience(gossip, now);
    return c.json({ ...gossip.message(now), audience: summary });
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
    updateSampling(gossip, now);
    if ((!sampling || sampledTab(heartbeat.data.tab)) && !leases.touch(heartbeat.data.tab, now))
      return c.body(null, 503);
    const summary = audience(gossip, now);
    const { fallback } = gossip.presenceView(now);
    const offset = Math.floor(Math.random() * fallback.length);
    const hints: Host[] = [];
    for (let i = 0; i < Math.min(fallback.length, MAX_FALLBACK_HOSTS); i++) {
      const candidate = fallback[(offset + i) % fallback.length];
      if (candidate !== undefined) hints.push(hostIdentity(candidate));
    }
    return c.json({
      host: gossip.self,
      startedAt: gossip.startedAt,
      ...summary,
      fallback: hints,
    });
  });
  app.get(TREE_PATH, (c) => {
    if (gossip === undefined || signal.aborted) return c.body(null, 503);
    const hostRunID = gossip.self.runID;
    return c.json({ hostRunID, hosts: treeSample(gossip.hostHistory(Date.now()), hostRunID) });
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
    const readTimeout = AbortSignal.timeout(UPLOAD_MS);
    const requestSignal = c.req.raw.signal;
    const deadline = AbortSignal.any([signal, requestSignal, readTimeout]);
    let bytes = 0;
    let outcome = "ok";
    const tracing =
      typeof KEEPALIVE_RAMP_UPLOAD_TRACE !== "undefined" && KEEPALIVE_RAMP_UPLOAD_TRACE;
    const started = tracing ? performance.now() : 0;
    try {
      await readBytes(
        new Response(c.req.raw.body),
        UPLOAD_BYTES,
        deadline,
        UPLOAD_BYTES,
        tracing
          ? (received) => {
              bytes = received;
            }
          : undefined,
      );
      const now = Date.now();
      if (promotion !== pending || pending.endsAt <= now || deadline.aborted) {
        outcome = "invitation_no_longer_current";
        return c.body(null, 409);
      }
      pending.uploadPassed = true;
      pending.endsAt = now + STARTUP_MS;
      gossip?.confirmStart(pending.endsAt);
      return c.body(null, 204);
    } catch (error) {
      if (tracing) {
        if (readTimeout.aborted && deadline.reason === readTimeout.reason) outcome = "read_timeout";
        else if (requestSignal.aborted && deadline.reason === requestSignal.reason)
          outcome = "request_canceled";
        else if (signal.aborted) outcome = "donor_stopped";
        else if (error instanceof TransportFailure) outcome = "transport_error";
        else outcome = "body_read_failed";
      }
      return c.body(null, 422);
    } finally {
      pending.reading = false;
      if (typeof KEEPALIVE_RAMP_UPLOAD_TRACE !== "undefined" && KEEPALIVE_RAMP_UPLOAD_TRACE) {
        console.info(
          "keepalive_donor_upload " +
            JSON.stringify({
              host: gossip?.self.origin,
              runID: gossip?.self.runID,
              outcome,
              bytes,
              elapsedMs: Math.round(performance.now() - started),
            }),
        );
      }
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
      const now = Date.now();
      expireConfirmations(now);
      const receipt = confirmations.get(invitation);
      if (receipt !== undefined) {
        if (message.from.left || !sameRun(receipt.host, message.from)) return c.body(null, 403);
        return c.json(reportMessage(now, message));
      }
      if (
        !pending?.uploadPassed ||
        pending.endsAt <= now ||
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
      const acceptedAt = Date.now();
      confirmations.set(invitation, { host: reply.from, until: acceptedAt + CONFIRMATION_MS });
      gossip.receive(reply, acceptedAt);
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
  app.get(INVITATION_PATH, (c) => {
    const valid =
      !signal.aborted &&
      promotion?.uploadPassed &&
      promotion.endsAt > Date.now() &&
      promotion.invitation === c.req.header(READY_HEADER) &&
      c.req.header("X-Keepalive-Release") === releaseID;
    return c.body(null, valid ? 204 : 403);
  });
  app.post(INVITATION_PATH, (c) => {
    expirePromotion(Date.now());
    if (
      signal.aborted ||
      !allowed(c.req.header("Origin") ?? "") ||
      c.req.header("X-Keepalive-Release") !== releaseID ||
      promotion === undefined ||
      promotion.invitation !== c.req.header(READY_HEADER)
    )
      return c.body(null, 403);
    cancelPromotion();
    return c.body(null, 204);
  });
  app.post(WAIT_PATH, (c) => {
    if (!allowed(c.req.header("Origin") ?? "")) return c.body(null, 403);
    if (gossip === undefined || signal.aborted) return c.body(null, 503);
    const now = Date.now();
    let selected: string | null = null;
    expirePromotion(now);
    expireConfirmations(now);
    if (promotion === undefined && confirmations.size < MAX_CONFIRMATIONS)
      gossip.maybeStart(now, hostTarget(gossip.tabs(now)), () => {
        selected = crypto.randomUUID();
        promotion = {
          invitation: selected,
          endsAt: now + INVITATION_ACK_MS,
          replacing: isReplacing(),
          uploadPassed: false,
          uploads: 0,
          reading: false,
        };
        return true;
      });
    return c.json(selected);
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
    get confirmingHandoff() {
      expireConfirmations(Date.now());
      return confirmations.size > 0;
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
      isReplacing = replacing;
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
        updateSampling(peers, now);
        peers.observeTabs(leases.count(now, sampling), now);
        expirePromotion(now);
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
