import { expect, it } from "vitest";
import { serveRelease } from "../src/hosting/serving.ts";
import { digest, readAssetResponse, WASM_PATH, WORKER_PATH } from "../src/release.ts";

it("serves independent compressed assets that decode to their own pinned bytes", async () => {
  const files = new Map(
    [WASM_PATH, WORKER_PATH, "/index.html", "/app.js", "/index.css", "/favicon.svg"].map(
      (path, index) => [path, new Uint8Array(128 * 1024).fill(index).buffer],
    ),
  );
  const assets = await Promise.all(
    [...files].map(async ([path, bytes]) => ({
      path,
      size: bytes.byteLength,
      sha256: await digest(bytes),
    })),
  );
  const serve = serveRelease({ id: "a".repeat(64), assets }, files);
  const fetch = (path: string, encoding?: string) =>
    serve(
      new Request(new URL(path, "https://host.test"), {
        headers: encoding === undefined ? {} : { "Accept-Encoding": encoding },
      }),
    );
  await Promise.all(
    assets.map(async (asset) => {
      for (const response of await Promise.all([
        fetch(asset.path, "br, gzip, deflate"),
        fetch(asset.path, "GZIP;q=0.5"),
      ])) {
        expect(response.headers.get("Content-Encoding")).toBe("gzip");
        expect(response.headers.get("Vary")).toBe("Accept-Encoding");
        const encoded = await response.blob();
        expect(encoded.size).toBeLessThan(asset.size);
        const decoded = new Response(encoded.stream().pipeThrough(new DecompressionStream("gzip")));
        await readAssetResponse(asset, decoded, new AbortController().signal);
      }
      for (const encoding of [undefined, "br", "gzip;q=0.000, identity", "xgzip"]) {
        const response = await fetch(asset.path, encoding);
        expect(response.headers.has("Content-Encoding")).toBe(false);
        await readAssetResponse(asset, response, new AbortController().signal);
      }
    }),
  );
});
