import { contentType, type Release } from "../release.ts";

// opt in only on an explicit gzip offer with a nonzero quality.
function acceptsGzip(request: Request) {
  return (request.headers.get("Accept-Encoding") ?? "").split(",").some((item) => {
    const offer = /^gzip(?:\s*;\s*q=(0(?:\.\d{0,3})?|1(?:\.0{0,3})?))?$/i.exec(item.trim());
    return offer !== null && Number(offer[1] ?? 1) > 0;
  });
}

export function serveRelease(release: Release, files: ReadonlyMap<string, ArrayBuffer>) {
  const assets = new Map(release.assets.map((asset) => [asset.path, asset]));
  const compressed = new Map<string, Promise<ArrayBuffer | undefined>>();
  return async (request: Request): Promise<Response> => {
    const { pathname, search } = new URL(request.url);
    const asset = assets.get(pathname === "/" ? "/index.html" : pathname);
    if (request.method !== "GET" || search !== "" || asset === undefined) {
      return new Response(null, { status: 404 });
    }
    const bytes = files.get(asset.path);
    if (bytes === undefined) return new Response(null, { status: 503 });
    const headers = new Headers({
      "Cache-Control": "no-store",
      "Content-Type": contentType(asset.path) ?? "application/octet-stream",
      Vary: "Accept-Encoding",
    });
    if (typeof CompressionStream !== "undefined" && acceptsGzip(request)) {
      // share one compressed copy of each pinned asset for this turn.
      let gzip = compressed.get(asset.path);
      if (gzip === undefined) {
        gzip = new Response(new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip")))
          .arrayBuffer()
          .then((encoded) => (encoded.byteLength < bytes.byteLength ? encoded : undefined))
          .catch(() => undefined);
        compressed.set(asset.path, gzip);
      }
      const encoded = await gzip;
      if (encoded !== undefined) {
        headers.set("Content-Encoding", "gzip");
        return new Response(encoded, { headers });
      }
    }
    return new Response(bytes, { headers });
  };
}
