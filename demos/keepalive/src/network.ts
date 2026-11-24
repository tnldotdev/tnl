export const PEER_DISCOVERY_MS = 14_000;
export const PEER_REQUEST_MS = PEER_DISCOVERY_MS + 2_000;
export const NO_HOST_HEADER = "X-Keepalive-No-Reachable-Host";

export function noReachableHost(response: Response) {
  return response.status === 503 && response.headers.get(NO_HOST_HEADER) === "1";
}

export class NoReachableHost extends Error {
  constructor() {
    super("No host is serving the site right now.");
  }
}

export class TransportFailure extends Error {
  constructor(cause: unknown) {
    super("The connection was interrupted.", { cause });
  }
}

export class HTTPFailure extends Error {
  readonly status: number;
  readonly retryAfter: string | undefined;

  constructor(status: number, retryAfter?: string) {
    super("The request could not be completed.");
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

export async function request(url: string | URL, init: RequestInit) {
  init.signal?.throwIfAborted();
  try {
    return await fetch(url, { cache: "no-store", redirect: "manual", ...init });
  } catch (error) {
    init.signal?.throwIfAborted();
    if (error instanceof TypeError) throw new TransportFailure(error);
    throw error;
  }
}

export async function requireStatus(response: Response, status = 200) {
  if (response.status === status) return response;
  await response.body?.cancel().catch(() => {});
  throw new HTTPFailure(response.status, response.headers.get("Retry-After") ?? undefined);
}

export function retryDelay(error: unknown) {
  if (
    error instanceof TransportFailure ||
    (error instanceof DOMException && error.name === "TimeoutError")
  )
    return 200 + Math.random() * 300;
  if (!(error instanceof HTTPFailure) || ![408, 429, 500, 502, 503, 504].includes(error.status))
    return;
  if (error.retryAfter === undefined)
    return error.status === 429 ? undefined : 200 + Math.random() * 300;
  const delay = /^\d+$/.test(error.retryAfter)
    ? Number(error.retryAfter) * 1_000
    : Date.parse(error.retryAfter) - Date.now();
  // leave longer server-directed waits to the user or the normal polling interval.
  return Number.isFinite(delay) && delay <= 1_000
    ? Math.max(200, delay) + Math.random() * 300
    : undefined;
}

export async function retryOnce<T>(signal: AbortSignal, run: () => Promise<T>) {
  signal.throwIfAborted();
  try {
    return await run();
  } catch (error) {
    signal.throwIfAborted();
    const delay = retryDelay(error);
    if (delay === undefined) throw error;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", stop);
        resolve();
      }, delay);
      function stop() {
        clearTimeout(timer);
        reject(signal.reason);
      }
      signal.addEventListener("abort", stop, { once: true });
    });
    signal.throwIfAborted();
    return run();
  }
}
