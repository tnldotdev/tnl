import {
  MAX_MESSAGE_BYTES,
  PEERS_PATH,
  SHARED_HOST,
  hostIdentity,
  parseMessage,
  type GossipMessage,
} from "../peers/gossip.ts";
import { contentType, readAssetResponse, readJSON, type Release } from "../release.ts";
import { NO_HOST_HEADER, PEER_DISCOVERY_MS } from "../network.ts";

export function siteHeaders(type = "application/octet-stream") {
  return {
    // do not let the edge inject scripts or change the checked response bytes.
    "Cache-Control": "no-store, no-transform",
    "Content-Type": type,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy":
      "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src blob:; " +
      "style-src 'self'; font-src 'self'; img-src 'self'; connect-src https: wss: 'self'; " +
      "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  };
}

function unavailable(discoveredNoHost = false) {
  // keep empty navigations from becoming downloads in Safari.
  return new Response(null, {
    status: 503,
    headers: {
      ...siteHeaders("text/html; charset=utf-8"),
      ...(discoveredNoHost ? { [NO_HOST_HEADER]: "1" } : {}),
    },
  });
}

const ATTEMPTS = 3;
const REFRESH_MS = 10_000;
const STALE_MS = 60_000;
const COOLDOWN_MS = 5_000;
const MAX_KNOWN_HOSTS = 5_000;

type Retain = (work: Promise<void>) => void;
type Candidate = {
  run: bigint;
  sequence: number;
  seenAt: number;
  endsAt: number;
  retryAt: number;
  stopped: boolean;
};

export function createProxy(release: Release, fetchHost = fetch) {
  const assets = new Map(release.assets.map((asset) => [asset.path, asset]));
  const known = new Map<string, Candidate>();
  let cursor = Math.floor(Math.random() * MAX_KNOWN_HOSTS);
  let refreshCursor = cursor;
  let refreshAt = 0;
  let refreshing = false;
  let audience: { until: number; message: GossipMessage } | undefined;
  let liveRevision = 0;
  let outageRevision = 0;

  function remember(message: GossipMessage, now: number) {
    for (const host of [message.from, ...message.changes]) {
      const current = known.get(host.origin);
      const run = BigInt(host.runNumber);
      if (
        current !== undefined &&
        (run < current.run ||
          (run === current.run && (current.stopped || host.seq <= current.sequence)))
      ) {
        continue;
      }
      if (known.size < MAX_KNOWN_HOSTS || current !== undefined)
        known.set(host.origin, {
          run,
          sequence: host.seq,
          seenAt: Math.max(
            current?.run === run ? current.seenAt : 0,
            Math.min(now, host.reportedAt),
          ),
          endsAt: host.endsAt ?? Infinity,
          retryAt: current?.run === run ? current.retryAt : 0,
          stopped: host.left,
        });
    }
  }

  function candidates(now: number) {
    const origins: string[] = [];
    for (const [origin, host] of known) {
      if (host.endsAt <= now || host.seenAt + STALE_MS <= now) known.delete(origin);
      else if (!host.stopped && host.retryAt <= now) origins.push(origin);
    }
    return origins;
  }

  async function get<T>(
    origin: string,
    path: string,
    signal: AbortSignal,
    check: (response: Response) => Promise<T>,
    headerBudget?: number,
  ) {
    let response: Response | undefined;
    try {
      const headers = new AbortController();
      const timer =
        headerBudget === undefined ? undefined : setTimeout(() => headers.abort(), headerBudget);
      try {
        response = await fetchHost(new URL(path, origin), {
          cache: "no-store",
          credentials: "omit",
          redirect: "manual",
          signal: timer === undefined ? signal : AbortSignal.any([signal, headers.signal]),
        });
      } finally {
        clearTimeout(timer);
      }
      const value = await check(response);
      signal.throwIfAborted();
      return value;
    } catch {
      return undefined;
    } finally {
      if (response?.bodyUsed === false) await response.body?.cancel().catch(() => {});
    }
  }

  async function probe(origin: string, shared: boolean, parent?: AbortSignal) {
    const revision = outageRevision;
    const timeout = AbortSignal.timeout(3_000);
    const signal = parent === undefined ? timeout : AbortSignal.any([parent, timeout]);
    return get(origin, PEERS_PATH, signal, async (response) => {
      const body = await readJSON(response, MAX_MESSAGE_BYTES, signal);
      const now = Date.now();
      const message = parseMessage(body, release.id, now);
      if (message === undefined || (!shared && origin !== message.from.origin)) return undefined;
      if (revision === outageRevision) remember(message, now);
      if (message.from.left || (message.from.endsAt ?? Infinity) <= now) return undefined;
      if (revision !== outageRevision) return message;
      liveRevision++;
      const current = known.get(message.from.origin);
      if (
        current?.run === BigInt(message.from.runNumber) &&
        current.sequence === message.from.seq
      ) {
        current.retryAt = 0;
        if (message.audience !== undefined)
          audience = { until: Math.min(now, message.from.reportedAt) + STALE_MS, message };
      }
      return message;
    });
  }

  function refresh(origins: string[], retain?: Retain) {
    const now = Date.now();
    if (retain === undefined || refreshing || now < refreshAt) return;
    const origin = origins[refreshCursor % origins.length];
    if (origin === undefined) return;
    refreshCursor++;
    refreshing = true;
    refreshAt = now + REFRESH_MS + Math.floor(Math.random() * 2_000);
    // only share the resulting data across requests, not a fetch owned by one request.
    retain(
      probe(origin, false)
        .then((message) => {
          if (message === undefined) coolDown(origin);
        })
        .finally(() => {
          refreshing = false;
        }),
    );
  }

  function coolDown(origin: string) {
    const host = known.get(origin);
    if (host !== undefined) host.retryAt = Date.now() + COOLDOWN_MS;
  }

  async function fromHost(
    request: Request,
    sharedHost: string,
    retain: Retain | undefined,
    read: (
      origin: string,
      signal: AbortSignal,
      alternate: boolean,
    ) => Promise<Response | undefined>,
    discover?: (message: GossipMessage) => Response,
  ): Promise<Response> {
    const deadline = AbortSignal.any([
      request.signal,
      AbortSignal.timeout(discover === undefined ? 20_000 : PEER_DISCOVERY_MS),
    ]);
    const revision = liveRevision;
    let discovered = false;
    const attempted = new Set<string>();
    refresh(candidates(Date.now()), retain);
    while (attempted.size < ATTEMPTS && !deadline.aborted) {
      let origins = candidates(Date.now()).filter((origin) => !attempted.has(origin));
      let origin = origins[cursor % origins.length];
      // after two cached aliases fail, use the remaining attempt on a host
      // answering the shared address. the roster may lag behind a turnover.
      if (!discovered && (origin === undefined || attempted.size === ATTEMPTS - 1)) {
        discovered = true;
        const message = await probe(sharedHost, true, deadline);
        if (message !== undefined && discover !== undefined) return discover(message);
        origins = candidates(Date.now()).filter((value) => !attempted.has(value));
        origin =
          attempted.size > 0 && message !== undefined && origins.includes(message.from.origin)
            ? message.from.origin
            : origins[cursor % origins.length];
      }
      if (origin === undefined || deadline.aborted) break;
      // pick the starting position synchronously so concurrent requests rotate too.
      if (attempted.size === 0) cursor++;
      attempted.add(origin);
      const response = await read(
        origin,
        deadline,
        attempted.size < ATTEMPTS && origins.length > 1,
      );
      if (response !== undefined) return response;
      if (!deadline.aborted) coolDown(origin);
    }
    // a newer successful probe wins over an overlapping failed search.
    const noHost =
      discover !== undefined && discovered && !deadline.aborted && revision === liveRevision;
    if (noHost) {
      audience = undefined;
      outageRevision++;
    }
    return unavailable(noHost);
  }

  return {
    audience(request: Request, retain: Retain) {
      if (request.method !== "GET" || new URL(request.url).search !== "")
        return new Response(null, { status: 404 });
      const now = Date.now();
      // share only a bounded observation. a crowd reading it must not send a
      // probe per tab, or keep reporting an old audience after the host stops.
      if (!refreshing && now >= refreshAt) refresh(candidates(now), retain);
      const message = audience?.message;
      const host = message && known.get(message.from.origin);
      if (
        !audience ||
        now >= audience.until ||
        !message?.audience ||
        !host ||
        host.stopped ||
        host.run !== BigInt(message.from.runNumber) ||
        host.endsAt <= now ||
        host.retryAt > now
      )
        return new Response(null, { status: 204, headers: siteHeaders("application/json") });
      return Response.json(
        {
          ...message.audience,
          releaseID: release.id,
          startedAt: message.startedAt,
          host: hostIdentity(message.from),
        },
        { headers: siteHeaders("application/json") },
      );
    },
    file(request: Request, sharedHost = SHARED_HOST, retain?: Retain) {
      const { pathname, search } = new URL(request.url);
      const asset = assets.get(pathname === "/" ? "/index.html" : pathname);
      if (
        request.method !== "GET" ||
        search !== "" ||
        asset === undefined ||
        pathname.startsWith("/hosting/")
      ) {
        return new Response(null, { status: 404 });
      }
      return fromHost(request, sharedHost, retain, (origin, deadline, alternate) => {
        const signal = AbortSignal.any([deadline, AbortSignal.timeout(6_000)]);
        const selected = known.get(origin);
        return get(
          origin,
          asset.path,
          signal,
          async (response) => {
            const bytes = await readAssetResponse(asset, response, signal);
            signal.throwIfAborted();
            if (selected !== undefined && known.get(origin) === selected)
              selected.seenAt = Date.now();
            return new Response(bytes, { headers: siteHeaders(contentType(asset.path)) });
          },
          alternate ? 1_000 : undefined,
        );
      });
    },
    peers(request: Request, sharedHost = SHARED_HOST, retain?: Retain) {
      if (request.method !== "GET" || new URL(request.url).search !== "") {
        return new Response(null, { status: 404 });
      }
      const respond = (message: GossipMessage) =>
        Response.json(message, { headers: siteHeaders("application/json") });
      return fromHost(
        request,
        sharedHost,
        retain,
        async (origin, deadline) => {
          const message = await probe(origin, false, deadline);
          return message === undefined ? undefined : respond(message);
        },
        respond,
      );
    },
  };
}
