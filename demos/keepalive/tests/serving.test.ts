import { expect, it } from "vitest";
import { serveRelease } from "../src/hosting/serving.ts";
import { digest, readAssetResponse, WASM_PATH } from "../src/release.ts";

it("serves independent compressed WASM copies that decode to the pinned release", async () => {
  const bytes = new Uint8Array(128 * 1024);
  const asset = { path: WASM_PATH, size: bytes.length, sha256: await digest(bytes) };
  const serve = serveRelease(
    { id: "a".repeat(64), assets: [asset] },
    new Map([[WASM_PATH, bytes.buffer]]),
  );
  const fetch = (encoding?: string) =>
    serve(
      new Request(new URL(WASM_PATH, "https://host.test"), {
        headers: encoding === undefined ? {} : { "Accept-Encoding": encoding },
      }),
    );
  for (const response of await Promise.all([fetch("br, gzip, deflate"), fetch("GZIP;q=0.5")])) {
    expect(response.headers.get("Content-Encoding")).toBe("gzip");
    expect(response.headers.get("Vary")).toBe("Accept-Encoding");
    const encoded = await response.blob();
    expect(encoded.size).toBeLessThan(bytes.length);
    const decoded = new Response(encoded.stream().pipeThrough(new DecompressionStream("gzip")));
    await readAssetResponse(asset, decoded, new AbortController().signal);
  }
  for (const encoding of [undefined, "br", "gzip;q=0.000, identity", "xgzip"]) {
    const response = await fetch(encoding);
    expect(response.headers.has("Content-Encoding")).toBe(false);
    await readAssetResponse(asset, response, new AbortController().signal);
  }
});
