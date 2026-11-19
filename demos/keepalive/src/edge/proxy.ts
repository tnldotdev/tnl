import {
  MAX_MESSAGE_BYTES,
  PEERS_PATH,
  SHARED_HOST,
  parseMessage,
  type GossipMessage,
} from "../peers/gossip.ts";
import { contentType, readAssetResponse, readJSON, type Release } from "../release.ts";

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

function unavailable() {
  // keep empty navigations from becoming downloads in Safari.
  return new Response(null, { status: 503, headers: siteHeaders("text/html; charset=utf-8") });
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
  ) {
    let response: Response | undefined;
    try {
      response = await fetchHost(new URL(path, origin), {
        cache: "no-store",
        credentials: "omit",
        redirect: "manual",
        signal,
      });
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
    const timeout = AbortSignal.timeout(3_000);
    const signal = parent === undefined ? timeout : AbortSignal.any([parent, timeout]);
    return get(origin, PEERS_PATH, signal, async (response) => {
      const body = await readJSON(response, MAX_MESSAGE_BYTES, signal);
      const now = Date.now();
      const message = parseMessage(body, release.id, now);
      if (message === undefined || (!shared && origin !== message.from.origin)) return undefined;
      remember(message, now);
      return message.from.left || (message.from.endsAt ?? Infinity) <= now ? undefined : message;
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
    read: (origin: string, signal: AbortSignal) => Promise<Response | undefined>,
    discover: (message: GossipMessage) => Response | undefined = () => undefined,
  ): Promise<Response> {
    const deadline = AbortSignal.any([request.signal, AbortSignal.timeout(20_000)]);
    let discovered = false;
    const attempted = new Set<string>();
    refresh(candidates(Date.now()), retain);
    while (attempted.size < ATTEMPTS && !deadline.aborted) {
      const origins = candidates(Date.now()).filter((origin) => !attempted.has(origin));
      const origin = origins[cursor % origins.length];
      if (origin === undefined) {
        if (discovered) break;
        discovered = true;
        const message = await probe(sharedHost, true, deadline);
        if (message === undefined) break;
        const response = discover(message);
        if (response !== undefined) return response;
        continue;
      }
      // pick the starting position synchronously so concurrent requests rotate too.
      if (attempted.size === 0) cursor++;
      attempted.add(origin);
      const response = await read(origin, deadline);
      if (response !== undefined) return response;
      if (!deadline.aborted) coolDown(origin);
    }
    return unavailable();
  }

  return {
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
      return fromHost(request, sharedHost, retain, (origin, deadline) => {
        const signal = AbortSignal.any([deadline, AbortSignal.timeout(6_000)]);
        const selected = known.get(origin);
        return get(origin, asset.path, signal, async (response) => {
          const bytes = await readAssetResponse(asset, response, signal);
          signal.throwIfAborted();
          if (selected !== undefined && known.get(origin) === selected)
            selected.seenAt = Date.now();
          return new Response(bytes, { headers: siteHeaders(contentType(asset.path)) });
        });
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
