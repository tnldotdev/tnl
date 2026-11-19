import { MAX_MESSAGE_BYTES, PEERS_PATH, SHARED_HOST, parseMessage } from "./peers.ts";
import { contentType, readAssetResponse, readJSON, type Release } from "./release.ts";

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
  return new Response(null, { status: 503, headers: siteHeaders() });
}

export function createProxy(release: Release, fetchHost = fetch) {
  const assets = new Map(release.assets.map((asset) => [asset.path, asset]));

  async function fromHost(
    request: Request,
    upstream: URL,
    check: (response: Response, signal: AbortSignal) => Promise<Response | undefined>,
  ): Promise<Response> {
    const deadline = AbortSignal.any([request.signal, AbortSignal.timeout(20_000)]);
    for (let i = 0; i < 3 && !deadline.aborted; i++) {
      const signal = AbortSignal.any([deadline, AbortSignal.timeout(6_000)]);
      try {
        const response = await fetchHost(upstream, {
          cache: "no-store",
          credentials: "omit",
          redirect: "manual",
          signal,
        });
        const checked = await check(response, signal);
        if (checked !== undefined) return checked;
      } catch {
        // tnl may pick another host for a new connection.
      }
    }
    return unavailable();
  }

  return {
    file(request: Request, sharedHost = SHARED_HOST) {
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
      return fromHost(request, new URL(asset.path, sharedHost), async (response, signal) => {
        const bytes = await readAssetResponse(asset, response, signal);
        return new Response(bytes, { headers: siteHeaders(contentType(asset.path)) });
      });
    },
    peers(request: Request, sharedHost = SHARED_HOST) {
      if (request.method !== "GET" || new URL(request.url).search !== "") {
        return new Response(null, { status: 404 });
      }
      return fromHost(request, new URL(PEERS_PATH, sharedHost), async (response, signal) => {
        const message = parseMessage(
          await readJSON(response, MAX_MESSAGE_BYTES, signal),
          release.id,
          Date.now(),
        );
        if (message === undefined) return undefined;
        return Response.json(message, { headers: siteHeaders("application/json") });
      });
    },
  };
}
