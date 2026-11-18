import { MAX_MESSAGE_BYTES, PEERS_PATH, SHARED_HOST, parseMessage } from "./peers.ts";
import { RELEASE_PATH, contentType, readAssetResponse, readJSON, type Release } from "./release.ts";

export function siteHeaders(type = "application/octet-stream") {
  return {
    "Cache-Control": "no-store",
    "Content-Type": type,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy":
      "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src blob:; " +
      "style-src 'self'; font-src 'self'; connect-src https: wss: 'self'; " +
      "frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  };
}

function unavailable() {
  return new Response(
    "No host could serve the site. Start one at https://start.keepthisalive.com/.\n",
    {
      status: 503,
      headers: siteHeaders("text/plain; charset=utf-8"),
    },
  );
}

export function createProxy(release: Release, fetchHost = fetch, sharedHost = SHARED_HOST) {
  const assets = new Map(release.assets.map((asset) => [asset.path, asset]));
  return async (request: Request): Promise<Response> => {
    const { pathname, search } = new URL(request.url);
    if (request.method !== "GET" || search !== "") return new Response(null, { status: 404 });
    if (pathname === RELEASE_PATH) {
      return Response.json(release, { headers: siteHeaders("application/json") });
    }
    const asset = assets.get(pathname === "/" ? "/index.html" : pathname);
    if (pathname !== PEERS_PATH && (asset === undefined || pathname.startsWith("/hosting/"))) {
      return new Response(null, { status: 404 });
    }
    const deadline = AbortSignal.any([request.signal, AbortSignal.timeout(20_000)]);
    for (let i = 0; i < 3 && !deadline.aborted; i++) {
      const signal = AbortSignal.any([deadline, AbortSignal.timeout(6_000)]);
      try {
        const response = await fetchHost(new URL(asset?.path ?? PEERS_PATH, sharedHost), {
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
          signal,
        });
        if (asset !== undefined) {
          const bytes = await readAssetResponse(asset, response, signal);
          return new Response(bytes, { headers: siteHeaders(contentType(asset.path)) });
        }
        const message = parseMessage(
          await readJSON(response, MAX_MESSAGE_BYTES, signal),
          release.id,
          Date.now(),
        );
        if (message !== undefined) {
          return Response.json(message, { headers: siteHeaders("application/json") });
        }
      } catch {
        // tnl may pick another host for a new connection.
      }
    }
    return unavailable();
  };
}
