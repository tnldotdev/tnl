import { contentType, type ReadAsset, type Release } from "./release.ts";

export function serveRelease(release: Release, read: ReadAsset) {
  const assets = new Map(release.assets.map((asset) => [asset.path, asset]));
  return async (request: Request): Promise<Response> => {
    const { pathname, search } = new URL(request.url);
    const asset = assets.get(pathname === "/" ? "/index.html" : pathname);
    if (request.method !== "GET" || search !== "" || asset === undefined) {
      return new Response(null, { status: 404 });
    }
    const bytes = await read(asset);
    if (bytes === undefined) return new Response(null, { status: 503 });
    return new Response(bytes, {
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": contentType(asset.path) ?? "application/octet-stream",
      },
    });
  };
}
